package cn.sky.skylicense.web.service;

import cn.sky.skylicense.web.entity.WebSession;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.security.WebSessionSecurity;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import com.j256.ormlite.dao.Dao;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Base64;

/** Persistent, bounded allow-list for browser sessions. */
@Service
public final class SessionService {
    static final int DEFAULT_MAX_SESSIONS = 100_000;
    static final int DEFAULT_MAX_SESSIONS_PER_USER = 20;
    static final long DEFAULT_EXPIRATION_SECONDS = 24L * 60 * 60;
    private static final int TOKEN_BYTES = 32;

    private final WebDataAccessor accessor;
    private final int maxSessions;
    private final int maxSessionsPerUser;
    private final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    public SessionService(WebDataAccessor accessor) {
        this(accessor, DEFAULT_MAX_SESSIONS, DEFAULT_MAX_SESSIONS_PER_USER);
    }

    SessionService(WebDataAccessor accessor, int maxSessions, int maxSessionsPerUser) {
        if (accessor == null || maxSessions <= 0 || maxSessionsPerUser <= 0
                || maxSessionsPerUser > maxSessions) {
            throw new IllegalArgumentException("valid session limits and accessor are required");
        }
        this.accessor = accessor;
        this.maxSessions = maxSessions;
        this.maxSessionsPerUser = maxSessionsPerUser;
    }

    public SessionToken createSession(long userId) {
        SessionToken session = new SessionToken(
                randomToken(),
                randomToken(),
                DEFAULT_EXPIRATION_SECONDS);
        persistSession(userId, session);
        return session;
    }

    @SneakyThrows
    synchronized void persistSession(long userId, SessionToken session) {
        if (userId <= 0 || session == null || session.token() == null
                || !WebSessionSecurity.isValidOpaqueToken(session.token())
                || !WebSessionSecurity.isValidOpaqueToken(session.csrfToken())
                || session.expiresInSeconds() <= 0) {
            throw new IllegalArgumentException("valid session data is required");
        }
        long now = System.currentTimeMillis();
        long expiresAt = Math.addExact(
                now,
                Math.multiplyExact(session.expiresInSeconds(), 1_000L));
        Dao<WebSession, String> dao = accessor.getSessionDao();
        purgeExpired(dao, now);
        if (dao.countOf() >= maxSessions) {
            throw new BizException(503, "会话容量已满，请稍后重试");
        }
        long createdAt = nextCreatedAt(dao, userId, now);

        long userSessions = dao.queryBuilder()
                .where().eq("user_id", userId)
                .countOf();
        if (userSessions >= maxSessionsPerUser) {
            List<WebSession> oldest = dao.queryBuilder()
                    .where().eq("user_id", userId)
                    .queryBuilder()
                    .orderBy("created_at", true)
                    .limit(userSessions - maxSessionsPerUser + 1)
                    .query();
            for (WebSession entry : oldest) {
                dao.deleteById(entry.getTokenDigest());
            }
        }
        dao.create(WebSession.builder()
                .tokenDigest(digest(session.token()))
                .userId(userId)
                .csrfToken(session.csrfToken())
                .expiresAt(expiresAt)
                .createdAt(createdAt)
                .build());
    }

    @SneakyThrows
    public boolean isActive(String token) {
        if (!WebSessionSecurity.isValidOpaqueToken(token)) {
            return false;
        }
        Dao<WebSession, String> dao = accessor.getSessionDao();
        String digest = digest(token);
        WebSession session = dao.queryForId(digest);
        if (session == null) {
            return false;
        }
        if (session.getExpiresAt() <= System.currentTimeMillis()) {
            dao.deleteById(digest);
            return false;
        }
        return true;
    }

    @SneakyThrows
    public UserContext resolveContext(String token) {
        if (!WebSessionSecurity.isValidOpaqueToken(token)) {
            return null;
        }
        Dao<WebSession, String> dao = accessor.getSessionDao();
        String tokenDigest = digest(token);
        WebSession session = dao.queryForId(tokenDigest);
        if (session == null) {
            return null;
        }
        if (session.getExpiresAt() <= System.currentTimeMillis()
                || !WebSessionSecurity.isValidOpaqueToken(session.getCsrfToken())) {
            dao.deleteById(tokenDigest);
            return null;
        }
        WebUser user = accessor.getUserDao().queryForId(session.getUserId());
        if (user == null || user.getStatus() != 1) {
            dao.deleteById(tokenDigest);
            return null;
        }
        return new UserContext(
                user.getId(),
                user.getUsername(),
                user.getRole(),
                session.getCsrfToken(),
                user.getMfaEnabled() == 1);
    }

    @SneakyThrows
    public synchronized void revoke(String token) {
        if (!WebSessionSecurity.isValidOpaqueToken(token)) {
            return;
        }
        accessor.getSessionDao().deleteById(digest(token));
    }

    @SneakyThrows
    public synchronized void revokeUser(long userId) {
        Dao<WebSession, String> dao = accessor.getSessionDao();
        List<WebSession> sessions = dao.queryBuilder()
                .where().eq("user_id", userId)
                .query();
        for (WebSession session : sessions) {
            dao.deleteById(session.getTokenDigest());
        }
        List<cn.sky.skylicense.web.entity.WebMfaChallenge> challenges =
                accessor.getMfaChallengeDao().queryBuilder()
                        .where().eq("user_id", userId)
                        .query();
        for (cn.sky.skylicense.web.entity.WebMfaChallenge challenge : challenges) {
            accessor.getMfaChallengeDao().deleteById(challenge.getTokenDigest());
        }
    }

    @SneakyThrows
    public synchronized long activeCount() {
        purgeExpired(accessor.getSessionDao(), System.currentTimeMillis());
        return accessor.getSessionDao().countOf();
    }

    private static void purgeExpired(Dao<WebSession, String> dao, long now)
            throws java.sql.SQLException {
        List<WebSession> expired = dao.queryBuilder()
                .where().le("expires_at", now)
                .query();
        for (WebSession session : expired) {
            dao.deleteById(session.getTokenDigest());
        }
    }

    private static long nextCreatedAt(
            Dao<WebSession, String> dao,
            long userId,
            long now
    ) throws java.sql.SQLException {
        List<WebSession> newest = dao.queryBuilder()
                .where().eq("user_id", userId)
                .queryBuilder()
                .orderBy("created_at", false)
                .limit(1L)
                .query();
        if (newest.isEmpty() || newest.get(0).getCreatedAt() < now) {
            return now;
        }
        return Math.addExact(newest.get(0).getCreatedAt(), 1L);
    }

    private static String digest(String token) {
        byte[] encoded = token.getBytes(StandardCharsets.UTF_8);
        byte[] hash = null;
        try {
            hash = MessageDigest.getInstance("SHA-256").digest(encoded);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        } finally {
            Arrays.fill(encoded, (byte) 0);
            if (hash != null) {
                Arrays.fill(hash, (byte) 0);
            }
        }
    }

    private String randomToken() {
        byte[] value = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(value);
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
        } finally {
            Arrays.fill(value, (byte) 0);
        }
    }

    public record SessionToken(String token, String csrfToken, long expiresInSeconds) {
    }
}

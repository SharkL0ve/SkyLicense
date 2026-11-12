package cn.sky.skylicense.web.service;

import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.WebSession;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.security.WebSessionSecurity;
import com.j256.ormlite.misc.TransactionManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionServiceTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void generatedSessionUsesIndependentOpaqueCredentialsAndResolvesUser() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("generated.db").toString());
            WebUser user = WebUser.builder()
                    .username("admin")
                    .password("stored-password")
                    .role("ADMIN")
                    .maxPrograms(10)
                    .status(1)
                    .mfaEnabled(1)
                    .createTime("2026-01-01-00:00")
                    .build();
            accessor.getUserDao().create(user);

            SessionService service = new SessionService(accessor);
            SessionService.SessionToken session = service.createSession(user.getId());

            assertTrue(WebSessionSecurity.isValidOpaqueToken(session.token()));
            assertTrue(WebSessionSecurity.isValidOpaqueToken(session.csrfToken()));
            assertNotEquals(session.token(), session.csrfToken());
            assertFalse(session.token().contains("."));
            WebSession row = accessor.getSessionDao().queryForId(
                    digest(session.token()));
            assertNotNull(row);
            assertNotEquals(session.token(), row.getTokenDigest());

            UserContext context = service.resolveContext(session.token());
            assertNotNull(context);
            assertEquals(user.getId(), context.getUserId());
            assertEquals("admin", context.getUsername());
            assertEquals("ADMIN", context.getRole());
            assertEquals(session.csrfToken(), context.getCsrfToken());
            assertTrue(context.isMfaEnabled());
        } finally {
            accessor.close();
        }
    }

    @Test
    void sessionAllowListSurvivesDatabaseReconnectAndLogoutRemovesIt() throws Exception {
        Path database = temporaryDirectory.resolve("sessions.db");
        SessionService.SessionToken session = session(1, 3_600);

        WebDataAccessor firstAccessor = new WebDataAccessor();
        firstAccessor.connect(database.toString());
        SessionService first = new SessionService(firstAccessor);
        WebUser user = WebUser.builder()
                .username("persistent-user")
                .password("stored-password")
                .role("USER")
                .maxPrograms(5)
                .status(1)
                .createTime("2026-01-01-00:00")
                .build();
        firstAccessor.getUserDao().create(user);
        first.persistSession(user.getId(), session);
        assertTrue(first.isActive(session.token()));
        firstAccessor.close();

        WebDataAccessor secondAccessor = new WebDataAccessor();
        try {
            secondAccessor.connect(database.toString());
            SessionService second = new SessionService(secondAccessor);
            assertTrue(second.isActive(session.token()));
            assertEquals(
                    session.csrfToken(),
                    second.resolveContext(session.token()).getCsrfToken());
            second.revoke(session.token());
            assertFalse(second.isActive(session.token()));
        } finally {
            secondAccessor.close();
        }

        WebDataAccessor thirdAccessor = new WebDataAccessor();
        try {
            thirdAccessor.connect(database.toString());
            SessionService third = new SessionService(thirdAccessor);
            assertFalse(third.isActive(session.token()));
            assertEquals(0, third.activeCount());
        } finally {
            thirdAccessor.close();
        }
    }

    @Test
    void perUserCapacityEvictsOnlyTheOldestSession() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("capacity.db").toString());
            WebUser user = createUser(accessor, "capacity-user");
            SessionService service = new SessionService(accessor);
            SessionService.SessionToken first = session(0, 3_600);
            service.persistSession(user.getId(), first);
            for (int index = 1; index <= 20; index++) {
                service.persistSession(user.getId(), session(index, 3_600));
            }

            assertFalse(service.isActive(first.token()));
            assertTrue(service.isActive(session(20, 3_600).token()));
            assertEquals(20, service.activeCount());
        } finally {
            accessor.close();
        }
    }

    @Test
    void expiredAndInvalidSessionsAreRejectedAndExpiredRowsAreCleaned() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("expiry.db").toString());
            WebUser user = createUser(accessor, "expiry-user");
            SessionService service = new SessionService(accessor);
            SessionService.SessionToken expired = session(100, -1);
            accessor.getSessionDao().create(WebSession.builder()
                    .tokenDigest("X".repeat(43))
                    .userId(user.getId())
                    .csrfToken("C".repeat(43))
                    .expiresAt(System.currentTimeMillis() - 1)
                    .createdAt(System.currentTimeMillis() - 10)
                    .build());

            assertThrows(
                    IllegalArgumentException.class,
                    () -> service.persistSession(user.getId(), expired));
            assertEquals(1, accessor.getSessionDao().countOf());
            assertEquals(0, service.activeCount());
            assertFalse(service.isActive(null));
            assertFalse(service.isActive("legacy.jwt"));
        } finally {
            accessor.close();
        }
    }

    @Test
    void sessionCreationParticipatesInOuterTransaction() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("transaction.db").toString());
            WebUser user = createUser(accessor, "transaction-user");
            SessionService service = new SessionService(accessor, 10, 2);
            SessionService.SessionToken session = session(200, 3_600);

            SQLException failure = assertThrows(
                    SQLException.class,
                    () -> TransactionManager.callInTransaction(
                            accessor.getConnectionSource(),
                            () -> {
                                service.persistSession(user.getId(), session);
                                throw new IllegalStateException("rollback");
                            }));
            assertTrue(failure.getCause() instanceof IllegalStateException);

            assertFalse(service.isActive(session.token()));
            assertEquals(0, service.activeCount());
        } finally {
            accessor.close();
        }
    }

    @Test
    void globalCapacityFailsClosedWithoutEvictingExistingSessions() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("global-capacity.db").toString());
            WebUser firstUser = createUser(accessor, "global-first");
            WebUser secondUser = createUser(accessor, "global-second");
            SessionService service = new SessionService(accessor, 2, 2);
            SessionService.SessionToken first = session(300, 3_600);
            SessionService.SessionToken second = session(301, 3_600);
            service.persistSession(firstUser.getId(), first);
            service.persistSession(secondUser.getId(), second);

            assertThrows(
                    cn.sky.skylicense.web.exception.BizException.class,
                    () -> service.persistSession(firstUser.getId(), session(302, 3_600)));
            assertTrue(service.isActive(first.token()));
            assertTrue(service.isActive(second.token()));
            assertEquals(2, service.activeCount());
        } finally {
            accessor.close();
        }
    }

    private static SessionService.SessionToken session(long seed, long expiresInSeconds) {
        return new SessionService.SessionToken(
                String.format(java.util.Locale.ROOT, "%043d", seed),
                "C".repeat(43),
                expiresInSeconds);
    }

    private static WebUser createUser(WebDataAccessor accessor, String username)
            throws SQLException {
        WebUser user = WebUser.builder()
                .username(username)
                .password("stored-password")
                .role("USER")
                .maxPrograms(1)
                .status(1)
                .createTime("2026-01-01-00:00")
                .build();
        accessor.getUserDao().create(user);
        return user;
    }

    private static String digest(String token) throws Exception {
        byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                .digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}

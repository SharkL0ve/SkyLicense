package cn.sky.skylicense.web.service;

import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.WebLoginAttempt;
import com.j256.ormlite.dao.Dao;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;

/** Restart-persistent, bounded login throttling with no plaintext identity keys. */
public final class PersistentLoginRateLimiter implements LoginRateLimiter {
    private static final int MAXIMUM_ENTRIES = 50_000;
    private static final long CLEANUP_AGE_MILLIS = Duration.ofMinutes(10).toMillis();
    private static final String REFERENCE_DOMAIN = "login-rate-limit-reference-v1";

    private final WebDataAccessor accessor;
    private final OperationLogSanitizer sanitizer;

    public PersistentLoginRateLimiter(
            WebDataAccessor accessor,
            OperationLogSanitizer sanitizer
    ) {
        if (accessor == null || sanitizer == null) {
            throw new IllegalArgumentException("database and audit key owner are required");
        }
        this.accessor = accessor;
        this.sanitizer = sanitizer;
    }

    @Override
    public String reference(Scope scope, String key) {
        if (scope == null) {
            throw new IllegalArgumentException("login rate-limit scope is required");
        }
        byte[] scopeBytes = scope.name().getBytes(StandardCharsets.US_ASCII);
        byte[] keyBytes = normalize(key).getBytes(StandardCharsets.UTF_8);
        ByteBuffer payload = ByteBuffer.allocate(8 + scopeBytes.length + keyBytes.length);
        try {
            payload.putInt(scopeBytes.length).put(scopeBytes);
            payload.putInt(keyBytes.length).put(keyBytes);
            return sanitizer.auditMac(REFERENCE_DOMAIN, payload.array());
        } finally {
            java.util.Arrays.fill(scopeBytes, (byte) 0);
            java.util.Arrays.fill(keyBytes, (byte) 0);
            java.util.Arrays.fill(payload.array(), (byte) 0);
        }
    }

    @Override
    public synchronized long retryAfterSeconds(
            Scope scope,
            String reference,
            Policy policy
    ) {
        validateReference(scope, reference, policy);
        try {
            Dao<WebLoginAttempt, String> dao = accessor.getLoginAttemptDao();
            WebLoginAttempt attempt = dao.queryForId(reference);
            if (attempt == null) {
                return 0;
            }
            requireScope(scope, attempt);
            long now = System.currentTimeMillis();
            if (isStale(attempt, now, policy)) {
                dao.deleteById(reference);
                return 0;
            }
            return secondsRoundedUp(attempt.getLockedUntil() - now);
        } catch (SQLException error) {
            throw new IllegalStateException("unable to read persistent login throttling state", error);
        }
    }

    @Override
    public synchronized boolean recordFailure(
            Scope scope,
            String reference,
            Policy policy
    ) {
        validateReference(scope, reference, policy);
        try {
            return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                Dao<WebLoginAttempt, String> dao = accessor.getLoginAttemptDao();
                long now = System.currentTimeMillis();
                WebLoginAttempt attempt = dao.queryForId(reference);
                if (attempt == null) {
                    cleanupStale(dao, now);
                    if (dao.countOf() >= MAXIMUM_ENTRIES) {
                        return false;
                    }
                    attempt = WebLoginAttempt.builder()
                            .attemptKey(reference)
                            .scope(scope.name())
                            .failureCount(1)
                            .windowStartedAt(now)
                            .lockedUntil(0L)
                            .updatedAt(now)
                            .build();
                    dao.create(attempt);
                    return true;
                }
                requireScope(scope, attempt);
                if (isStale(attempt, now, policy)) {
                    attempt.setFailureCount(1);
                    attempt.setWindowStartedAt(now);
                    attempt.setLockedUntil(0L);
                } else if (attempt.getFailureCount() < Integer.MAX_VALUE) {
                    attempt.setFailureCount(attempt.getFailureCount() + 1);
                }
                if (attempt.getFailureCount() >= policy.maximumAttempts()) {
                    attempt.setLockedUntil(Math.addExact(now, policy.windowMillis()));
                }
                attempt.setUpdatedAt(now);
                dao.update(attempt);
                return true;
            });
        } catch (SQLException error) {
            throw new IllegalStateException("unable to persist login throttling state", error);
        }
    }

    @Override
    public synchronized void clear(Scope scope, String reference) {
        validateReference(scope, reference, policyFor(scope));
        try {
            Dao<WebLoginAttempt, String> dao = accessor.getLoginAttemptDao();
            WebLoginAttempt attempt = dao.queryForId(reference);
            if (attempt != null) {
                requireScope(scope, attempt);
                dao.deleteById(reference);
            }
        } catch (SQLException error) {
            throw new IllegalStateException("unable to clear login throttling state", error);
        }
    }

    private static void cleanupStale(Dao<WebLoginAttempt, String> dao, long now)
            throws SQLException {
        List<WebLoginAttempt> stale = dao.queryBuilder()
                .where().le("updated_at", now - CLEANUP_AGE_MILLIS)
                .queryBuilder().limit(1_000L).query();
        for (WebLoginAttempt attempt : stale) {
            dao.deleteById(attempt.getAttemptKey());
        }
    }

    private static boolean isStale(WebLoginAttempt attempt, long now, Policy policy) {
        return attempt.getLockedUntil() <= now
                && now - attempt.getWindowStartedAt() >= policy.windowMillis();
    }

    private static long secondsRoundedUp(long millis) {
        return millis <= 0 ? 0 : 1 + (millis - 1) / 1_000L;
    }

    private static void validateReference(Scope scope, String reference, Policy policy) {
        if (scope == null || policy == null || reference == null || reference.length() != 64
                || !reference.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
            throw new IllegalArgumentException("valid login rate-limit reference is required");
        }
    }

    private static void requireScope(Scope scope, WebLoginAttempt attempt) {
        if (!scope.name().equals(attempt.getScope())) {
            throw new IllegalStateException("login rate-limit reference scope mismatch");
        }
    }

    private static Policy policyFor(Scope scope) {
        return switch (scope) {
            case ACCOUNT -> ACCOUNT_POLICY;
            case ADDRESS -> ADDRESS_POLICY;
            case MFA_CHALLENGE -> MFA_CHALLENGE_POLICY;
            case MFA_MANAGEMENT -> MFA_MANAGEMENT_POLICY;
        };
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "<missing>" : value;
    }
}

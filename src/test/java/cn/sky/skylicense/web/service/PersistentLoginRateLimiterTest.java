package cn.sky.skylicense.web.service;

import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PersistentLoginRateLimiterTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void lockoutSurvivesReconnectAndDatabaseNeverStoresTheRawKey() throws Exception {
        Path database = temporaryDirectory.resolve("persistent-rate-limit.db");
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x41);
        String reference;

        WebDataAccessor firstAccessor = new WebDataAccessor();
        firstAccessor.connect(database.toString());
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            PersistentLoginRateLimiter limiter =
                    new PersistentLoginRateLimiter(firstAccessor, sanitizer);
            reference = limiter.reference(LoginRateLimiter.Scope.ACCOUNT, "SensitiveUser");
            assertEquals(64, reference.length());
            assertFalse(reference.contains("SensitiveUser"));
            for (int attempt = 0; attempt < 5; attempt++) {
                assertTrue(limiter.recordFailure(
                        LoginRateLimiter.Scope.ACCOUNT,
                        reference,
                        LoginRateLimiter.ACCOUNT_POLICY));
            }
            assertTrue(limiter.retryAfterSeconds(
                    LoginRateLimiter.Scope.ACCOUNT,
                    reference,
                    LoginRateLimiter.ACCOUNT_POLICY) > 0);
            assertEquals(reference, firstAccessor.getLoginAttemptDao().queryForAll()
                    .get(0).getAttemptKey());
        } finally {
            firstAccessor.close();
        }

        WebDataAccessor secondAccessor = new WebDataAccessor();
        secondAccessor.connect(database.toString());
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            PersistentLoginRateLimiter limiter =
                    new PersistentLoginRateLimiter(secondAccessor, sanitizer);
            assertEquals(
                    reference,
                    limiter.reference(LoginRateLimiter.Scope.ACCOUNT, "SensitiveUser"));
            assertTrue(limiter.retryAfterSeconds(
                    LoginRateLimiter.Scope.ACCOUNT,
                    reference,
                    LoginRateLimiter.ACCOUNT_POLICY) > 0);
            limiter.clear(LoginRateLimiter.Scope.ACCOUNT, reference);
            assertEquals(0, limiter.retryAfterSeconds(
                    LoginRateLimiter.Scope.ACCOUNT,
                    reference,
                    LoginRateLimiter.ACCOUNT_POLICY));
        } finally {
            secondAccessor.close();
            Arrays.fill(key, (byte) 0);
        }
    }
}

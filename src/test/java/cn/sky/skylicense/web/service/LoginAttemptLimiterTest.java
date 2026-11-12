package cn.sky.skylicense.web.service;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginAttemptLimiterTest {
    @Test
    void locksAtTheConfiguredThresholdUsingMonotonicTime() {
        LoginAttemptLimiter limiter =
                new LoginAttemptLimiter(10, 2, Duration.ofMinutes(5));
        long start = 1_000L;

        assertTrue(limiter.recordFailureAt("account", start));
        assertEquals(0, limiter.retryAfterSecondsAt("account", start));
        assertTrue(limiter.recordFailureAt("account", start + 1));
        assertEquals(300, limiter.retryAfterSecondsAt("account", start + 1));
        assertEquals(0, limiter.retryAfterSecondsAt(
                "account", start + 1 + Duration.ofMinutes(5).toNanos()));
    }

    @Test
    void hardCapacityFailsClosedUntilAnEntryBecomesStale() {
        LoginAttemptLimiter limiter =
                new LoginAttemptLimiter(2, 5, Duration.ofSeconds(10));
        long start = 5_000L;

        assertTrue(limiter.recordFailureAt("one", start));
        assertTrue(limiter.recordFailureAt("two", start));
        assertFalse(limiter.recordFailureAt("three", start));
        assertEquals(2, limiter.size());
        assertTrue(limiter.recordFailureAt(
                "three", start + Duration.ofSeconds(10).toNanos()));
        assertEquals(1, limiter.size());
    }
}

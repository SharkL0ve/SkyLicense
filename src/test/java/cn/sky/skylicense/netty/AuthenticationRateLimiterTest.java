package cn.sky.skylicense.netty;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationRateLimiterTest {
    @Test
    void burstIsBoundedAndTokensRefillFromMonotonicTime() {
        AuthenticationRateLimiter limiter =
                new AuthenticationRateLimiter(10, 2, 1.0, Duration.ofMinutes(1));
        long start = 1_000L;

        assertTrue(limiter.tryAcquireAt("127.0.0.1", start));
        assertTrue(limiter.tryAcquireAt("127.0.0.1", start));
        assertFalse(limiter.tryAcquireAt("127.0.0.1", start));
        assertFalse(limiter.tryAcquireAt("127.0.0.1", start + 999_999_999L));
        assertTrue(limiter.tryAcquireAt("127.0.0.1", start + 1_000_000_000L));
        AuthenticationRateLimiter.Snapshot snapshot = limiter.snapshot();
        assertEquals(1, snapshot.trackedAddresses());
        assertEquals(2, snapshot.throttledRejections());
        assertEquals(0, snapshot.capacityRejections());
    }

    @Test
    void hardCapacityRejectsNewAddressesUntilAStaleBucketIsRemoved() {
        AuthenticationRateLimiter limiter =
                new AuthenticationRateLimiter(2, 1, 1.0, Duration.ofSeconds(10));
        long start = 5_000L;

        assertTrue(limiter.tryAcquireAt("192.0.2.1", start));
        assertTrue(limiter.tryAcquireAt("192.0.2.2", start));
        assertFalse(limiter.tryAcquireAt("192.0.2.3", start));
        assertEquals(2, limiter.size());
        assertEquals(1, limiter.snapshot().capacityRejections());

        assertTrue(limiter.tryAcquireAt("192.0.2.3", start + Duration.ofSeconds(10).toNanos()));
        assertEquals(1, limiter.size());
    }

    @Test
    void clearDropsAllAddressState() {
        AuthenticationRateLimiter limiter =
                new AuthenticationRateLimiter(2, 1, 1.0, Duration.ofMinutes(1));
        assertTrue(limiter.tryAcquireAt("198.51.100.1", 1));
        limiter.clear();
        assertEquals(0, limiter.size());
        assertEquals(0, limiter.snapshot().throttledRejections());
        assertEquals(0, limiter.snapshot().capacityRejections());
    }
}

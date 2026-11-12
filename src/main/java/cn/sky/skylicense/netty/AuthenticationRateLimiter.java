package cn.sky.skylicense.netty;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

/**
 * Bounded per-address token buckets for initial authentication messages.
 * Heartbeats and challenge responses are dispatched before this limiter.
 */
final class AuthenticationRateLimiter {
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final Object insertionLock = new Object();
    private final int maximumBuckets;
    private final double burstTokens;
    private final double tokensPerNanosecond;
    private final long staleAfterNanos;
    private final LongAdder throttledRejections = new LongAdder();
    private final LongAdder capacityRejections = new LongAdder();
    private final LongAdder invalidAddressRejections = new LongAdder();

    AuthenticationRateLimiter(
            int maximumBuckets,
            int burstTokens,
            double tokensPerSecond,
            Duration staleAfter
    ) {
        if (maximumBuckets <= 0 || burstTokens <= 0 || tokensPerSecond <= 0.0
                || staleAfter.isZero() || staleAfter.isNegative()) {
            throw new IllegalArgumentException("rate-limiter settings must be positive");
        }
        this.maximumBuckets = maximumBuckets;
        this.burstTokens = burstTokens;
        this.tokensPerNanosecond = tokensPerSecond / 1_000_000_000.0;
        this.staleAfterNanos = staleAfter.toNanos();
    }

    boolean tryAcquire(String address) {
        return tryAcquireAt(address, System.nanoTime());
    }

    boolean tryAcquireAt(String address, long nowNanos) {
        if (address == null || address.isEmpty()) {
            invalidAddressRejections.increment();
            return false;
        }

        Bucket bucket = buckets.get(address);
        if (bucket == null) {
            synchronized (insertionLock) {
                bucket = buckets.get(address);
                if (bucket == null) {
                    if (buckets.size() >= maximumBuckets) {
                        cleanupStaleAt(nowNanos);
                    }
                    if (buckets.size() >= maximumBuckets) {
                        capacityRejections.increment();
                        return false;
                    }
                    bucket = new Bucket(burstTokens, nowNanos);
                    buckets.put(address, bucket);
                }
            }
        }
        boolean acquired = bucket.tryAcquire(nowNanos, burstTokens, tokensPerNanosecond);
        if (!acquired) {
            throttledRejections.increment();
        }
        return acquired;
    }

    void cleanupStale() {
        cleanupStaleAt(System.nanoTime());
    }

    void clear() {
        buckets.clear();
        throttledRejections.reset();
        capacityRejections.reset();
        invalidAddressRejections.reset();
    }

    int size() {
        return buckets.size();
    }

    Snapshot snapshot() {
        return new Snapshot(
                buckets.size(),
                throttledRejections.sum(),
                capacityRejections.sum(),
                invalidAddressRejections.sum());
    }

    record Snapshot(
            int trackedAddresses,
            long throttledRejections,
            long capacityRejections,
            long invalidAddressRejections
    ) {
    }

    private void cleanupStaleAt(long nowNanos) {
        for (Map.Entry<String, Bucket> entry : buckets.entrySet()) {
            if (entry.getValue().isStale(nowNanos, staleAfterNanos)) {
                buckets.remove(entry.getKey(), entry.getValue());
            }
        }
    }

    private static final class Bucket {
        private double tokens;
        private long lastRefillNanos;
        private volatile long lastSeenNanos;

        private Bucket(double tokens, long nowNanos) {
            this.tokens = tokens;
            this.lastRefillNanos = nowNanos;
            this.lastSeenNanos = nowNanos;
        }

        private synchronized boolean tryAcquire(
                long nowNanos,
                double maximumTokens,
                double tokensPerNanosecond
        ) {
            long elapsed = nowNanos - lastRefillNanos;
            if (elapsed > 0) {
                tokens = Math.min(maximumTokens, tokens + elapsed * tokensPerNanosecond);
                lastRefillNanos = nowNanos;
            }
            lastSeenNanos = nowNanos;
            if (tokens < 1.0) {
                return false;
            }
            tokens -= 1.0;
            return true;
        }

        private boolean isStale(long nowNanos, long staleAfterNanos) {
            return nowNanos - lastSeenNanos >= staleAfterNanos;
        }
    }
}

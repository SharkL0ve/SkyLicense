package cn.sky.skylicense.web.service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Bounded monotonic login-failure tracker for an account or network address. */
final class LoginAttemptLimiter {
    private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();
    private final Object insertionLock = new Object();
    private final int maximumEntries;
    private final int maximumAttempts;
    private final long lockNanos;

    LoginAttemptLimiter(int maximumEntries, int maximumAttempts, Duration lockDuration) {
        if (maximumEntries <= 0 || maximumAttempts <= 0
                || lockDuration == null || lockDuration.isZero() || lockDuration.isNegative()) {
            throw new IllegalArgumentException("login limiter settings must be positive");
        }
        this.maximumEntries = maximumEntries;
        this.maximumAttempts = maximumAttempts;
        this.lockNanos = lockDuration.toNanos();
    }

    long retryAfterSeconds(String key) {
        return retryAfterSecondsAt(key, System.nanoTime());
    }

    long retryAfterSecondsAt(String key, long nowNanos) {
        if (key == null || key.isEmpty()) {
            return secondsRoundedUp(lockNanos);
        }
        Attempt attempt = attempts.get(key);
        if (attempt == null) {
            return 0;
        }
        long retryNanos = attempt.retryAfterNanos(nowNanos, maximumAttempts, lockNanos);
        if (retryNanos <= 0 && attempt.isStale(nowNanos, lockNanos)) {
            attempts.remove(key, attempt);
        }
        return secondsRoundedUp(retryNanos);
    }

    boolean recordFailure(String key) {
        return recordFailureAt(key, System.nanoTime());
    }

    boolean recordFailureAt(String key, long nowNanos) {
        if (key == null || key.isEmpty()) {
            return false;
        }
        Attempt attempt = attempts.get(key);
        if (attempt == null) {
            synchronized (insertionLock) {
                attempt = attempts.get(key);
                if (attempt == null) {
                    if (attempts.size() >= maximumEntries) {
                        cleanupStaleAt(nowNanos);
                    }
                    if (attempts.size() >= maximumEntries) {
                        return false;
                    }
                    attempt = new Attempt(nowNanos);
                    attempts.put(key, attempt);
                    return true;
                }
            }
        }
        attempt.record(nowNanos, lockNanos);
        return true;
    }

    void clear(String key) {
        if (key != null) {
            attempts.remove(key);
        }
    }

    int size() {
        return attempts.size();
    }

    private void cleanupStaleAt(long nowNanos) {
        for (Map.Entry<String, Attempt> entry : attempts.entrySet()) {
            if (entry.getValue().isStale(nowNanos, lockNanos)) {
                attempts.remove(entry.getKey(), entry.getValue());
            }
        }
    }

    private static long secondsRoundedUp(long nanos) {
        if (nanos <= 0) {
            return 0;
        }
        long oneSecond = Duration.ofSeconds(1).toNanos();
        return 1 + (nanos - 1) / oneSecond;
    }

    private static final class Attempt {
        private int count = 1;
        private volatile long lastFailureNanos;

        private Attempt(long nowNanos) {
            lastFailureNanos = nowNanos;
        }

        private synchronized void record(long nowNanos, long staleAfterNanos) {
            if (nowNanos - lastFailureNanos >= staleAfterNanos) {
                count = 1;
            } else if (count < Integer.MAX_VALUE) {
                count++;
            }
            lastFailureNanos = nowNanos;
        }

        private synchronized long retryAfterNanos(
                long nowNanos,
                int maximumAttempts,
                long lockDurationNanos
        ) {
            if (count < maximumAttempts) {
                return 0;
            }
            long elapsed = nowNanos - lastFailureNanos;
            return elapsed >= lockDurationNanos ? 0 : lockDurationNanos - elapsed;
        }

        private boolean isStale(long nowNanos, long staleAfterNanos) {
            return nowNanos - lastFailureNanos >= staleAfterNanos;
        }
    }
}

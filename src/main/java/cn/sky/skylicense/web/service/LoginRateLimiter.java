package cn.sky.skylicense.web.service;

import java.time.Duration;

/** Shared account/address login throttling contract. */
public interface LoginRateLimiter {
    Policy ACCOUNT_POLICY = new Policy(5, Duration.ofMinutes(5));
    Policy ADDRESS_POLICY = new Policy(50, Duration.ofMinutes(5));
    Policy MFA_CHALLENGE_POLICY = new Policy(5, Duration.ofMinutes(5));
    Policy MFA_MANAGEMENT_POLICY = new Policy(5, Duration.ofMinutes(5));

    enum Scope {
        ACCOUNT,
        ADDRESS,
        MFA_CHALLENGE,
        MFA_MANAGEMENT
    }

    String reference(Scope scope, String key);

    long retryAfterSeconds(Scope scope, String reference, Policy policy);

    boolean recordFailure(Scope scope, String reference, Policy policy);

    void clear(Scope scope, String reference);

    record Policy(int maximumAttempts, Duration window) {
        public Policy {
            if (maximumAttempts <= 0 || window == null || window.isZero() || window.isNegative()) {
                throw new IllegalArgumentException("login rate-limit policy must be positive");
            }
        }

        long windowMillis() {
            return window.toMillis();
        }
    }
}

package cn.sky.skylicense.web.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;

/** Test-only fallback; production uses the persistent SQLite implementation. */
final class InMemoryLoginRateLimiter implements LoginRateLimiter {
    private static final int MAXIMUM_KEYS = 50_000;
    private final Map<Scope, LoginAttemptLimiter> delegates = new EnumMap<>(Scope.class);

    InMemoryLoginRateLimiter() {
        delegates.put(Scope.ACCOUNT, new LoginAttemptLimiter(
                MAXIMUM_KEYS, ACCOUNT_POLICY.maximumAttempts(), ACCOUNT_POLICY.window()));
        delegates.put(Scope.ADDRESS, new LoginAttemptLimiter(
                MAXIMUM_KEYS, ADDRESS_POLICY.maximumAttempts(), ADDRESS_POLICY.window()));
        delegates.put(Scope.MFA_CHALLENGE, new LoginAttemptLimiter(
                MAXIMUM_KEYS,
                MFA_CHALLENGE_POLICY.maximumAttempts(),
                MFA_CHALLENGE_POLICY.window()));
        delegates.put(Scope.MFA_MANAGEMENT, new LoginAttemptLimiter(
                MAXIMUM_KEYS,
                MFA_MANAGEMENT_POLICY.maximumAttempts(),
                MFA_MANAGEMENT_POLICY.window()));
    }

    @Override
    public String reference(Scope scope, String key) {
        if (scope == null) {
            throw new IllegalArgumentException("login rate-limit scope is required");
        }
        byte[] value = (scope.name() + "\0" + normalize(key)).getBytes(StandardCharsets.UTF_8);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            try {
                return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            } finally {
                java.util.Arrays.fill(digest, (byte) 0);
            }
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        } finally {
            java.util.Arrays.fill(value, (byte) 0);
        }
    }

    @Override
    public long retryAfterSeconds(Scope scope, String reference, Policy policy) {
        return delegate(scope, policy).retryAfterSeconds(reference);
    }

    @Override
    public boolean recordFailure(Scope scope, String reference, Policy policy) {
        return delegate(scope, policy).recordFailure(reference);
    }

    @Override
    public void clear(Scope scope, String reference) {
        delegate(scope, policyFor(scope)).clear(reference);
    }

    private LoginAttemptLimiter delegate(Scope scope, Policy policy) {
        if (!policyFor(scope).equals(policy)) {
            throw new IllegalArgumentException("unexpected login rate-limit policy");
        }
        return delegates.get(scope);
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

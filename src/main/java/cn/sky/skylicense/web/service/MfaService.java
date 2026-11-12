package cn.sky.skylicense.web.service;

import cn.sky.skylicense.security.MfaSecretProtector;
import cn.sky.skylicense.utils.PasswordUtil;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.response.MfaEnrollmentResponse;
import cn.sky.skylicense.web.dto.response.MfaRecoveryCodesResponse;
import cn.sky.skylicense.web.dto.response.MfaStatusResponse;
import cn.sky.skylicense.web.entity.WebMfaChallenge;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.security.WebSessionSecurity;
import cn.sky.skylicense.web.security.UsernamePolicy;
import com.j256.ormlite.dao.Dao;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/** Handles TOTP enrollment, one-time recovery codes, and password-login challenges. */
@Service
public final class MfaService {
    static final long ENROLLMENT_TTL_MILLIS = 10 * 60 * 1_000L;
    static final long CHALLENGE_TTL_MILLIS = 5 * 60 * 1_000L;
    static final int CHALLENGE_ATTEMPTS = 5;
    private static final int MAX_CHALLENGES = 100_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final WebDataAccessor accessor;
    private final SessionService sessionService;
    private final MfaSecretProtector secretProtector;
    private final LoginRateLimiter rateLimiter;

    public MfaService(
            WebDataAccessor accessor,
            SessionService sessionService,
            MfaSecretProtector secretProtector,
            LoginRateLimiter rateLimiter
    ) {
        this.accessor = accessor;
        this.sessionService = sessionService;
        this.secretProtector = secretProtector;
        this.rateLimiter = rateLimiter;
    }

    @SneakyThrows
    public MfaStatusResponse status() {
        WebUser user = currentUser();
        return new MfaStatusResponse(
                user.getMfaEnabled() == 1,
                MfaRecoveryCodes.count(user.getMfaRecoveryHashes()));
    }

    @SneakyThrows
    public MfaEnrollmentResponse startEnrollment(String password) {
        WebUser user = currentUser();
        if (user.getMfaEnabled() == 1) {
            throw new BizException("MFA 已启用，请先完成验证后再禁用");
        }
        String managementReference = managementReference(user);
        checkManagementRateLimit(managementReference);
        if (!PasswordUtil.verifyPassword(password, user.getPassword())) {
            recordManagementFailure(managementReference);
            throw new BizException(401, "当前密码错误");
        }
        byte[] secret = TotpUtil.generateSecret();
        try {
            String manualSecret = TotpUtil.encodeBase32(secret);
            String encrypted = secretProtector.encrypt(secret);
            String uri = TotpUtil.enrollmentUri("SkyLicense", user.getUsername(), manualSecret);
            long now = System.currentTimeMillis();
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                WebUser current = requireUser(user.getId());
                if (!java.util.Objects.equals(current.getPassword(), user.getPassword())
                        || !sameMfaState(current, user)) {
                    throw new BizException(409, "账户安全状态已变化，请重试");
                }
                current.setMfaPendingSecret(encrypted);
                current.setMfaPendingCreatedAt(now);
                current.setMfaUpdatedAt(now);
                accessor.getUserDao().update(current);
                return null;
            });
            rateLimiter.clear(
                    LoginRateLimiter.Scope.MFA_MANAGEMENT, managementReference);
            return new MfaEnrollmentResponse(
                    manualSecret,
                    uri,
                    ENROLLMENT_TTL_MILLIS / 1_000L);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    @SneakyThrows
    public MfaRecoveryCodesResponse confirmEnrollment(String factor) {
        WebUser user = currentUser();
        long now = System.currentTimeMillis();
        if (user.getMfaEnabled() == 1
                || user.getMfaPendingSecret() == null
                || user.getMfaPendingCreatedAt() == null
                || now - user.getMfaPendingCreatedAt() > ENROLLMENT_TTL_MILLIS) {
            throw new BizException("MFA enrollment is not pending or has expired");
        }
        String managementReference = managementReference(user);
        checkManagementRateLimit(managementReference);
        byte[] secret = secretProtector.decrypt(user.getMfaPendingSecret());
        String pendingCiphertext = user.getMfaPendingSecret();
        try {
            long step = TotpUtil.verify(
                    secret,
                    normalizeTotpFactor(factor),
                    now / 1_000L,
                    user.getMfaLastTimeStep());
            if (step < 0) {
                recordManagementFailure(managementReference);
                throw new BizException(401, "MFA 验证码错误或已过期");
            }
            MfaRecoveryCodes.Generated generated = MfaRecoveryCodes.generate();
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                WebUser current = requireUser(user.getId());
                if (current.getMfaEnabled() == 1
                        || current.getMfaPendingSecret() == null
                        || !pendingCiphertext.equals(current.getMfaPendingSecret())
                        || current.getMfaPendingCreatedAt() == null
                        || now - current.getMfaPendingCreatedAt() > ENROLLMENT_TTL_MILLIS
                        || step <= current.getMfaLastTimeStep()) {
                    throw new BizException("MFA enrollment is no longer pending");
                }
                current.setMfaEnabled(1);
                current.setMfaSecret(current.getMfaPendingSecret());
                current.setMfaPendingSecret(null);
                current.setMfaPendingCreatedAt(null);
                current.setMfaRecoveryHashes(generated.encodedHashes());
                current.setMfaLastTimeStep(step);
                current.setMfaUpdatedAt(now);
                accessor.getUserDao().update(current);
                sessionService.revokeUser(current.getId());
                return null;
            });
            rateLimiter.clear(
                    LoginRateLimiter.Scope.MFA_MANAGEMENT, managementReference);
            return new MfaRecoveryCodesResponse(generated.displayCodes());
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    @SneakyThrows
    public MfaRecoveryCodesResponse regenerateRecoveryCodes(String password, String factor) {
        WebUser user = currentUser();
        MfaRecoveryCodes.Generated generated = MfaRecoveryCodes.generate();
        verifyAndConsumeManagementFactor(user, password, factor, generated.encodedHashes(), true);
        return new MfaRecoveryCodesResponse(generated.displayCodes());
    }

    @SneakyThrows
    public void disable(String password, String factor) {
        WebUser user = currentUser();
        if ("ADMIN".equals(user.getRole())) {
            throw BizException.forbidden(
                    "管理员不能自行禁用 MFA，请由另一名管理员执行重置");
        }
        verifyAndConsumeManagementFactor(user, password, factor, null, false);
    }

    /** Break-glass recovery performed by a separately authenticated administrator. */
    @SneakyThrows
    public void resetByAdministrator(long targetUserId, String password, String factor) {
        UserContext context = UserContext.get();
        if (context == null || !context.isAdmin()) {
            throw BizException.forbidden("需要管理员权限");
        }
        if (targetUserId <= 0) {
            throw new BizException("用户 ID 无效");
        }
        if (targetUserId == context.getUserId()) {
            throw BizException.forbidden("管理员不能通过重置接口修改自己的 MFA");
        }
        WebUser actor = requireUser(context.getUserId());
        String managementReference = managementReference(actor);
        checkManagementRateLimit(managementReference);
        if (!PasswordUtil.verifyPassword(password, actor.getPassword())) {
            recordManagementFailure(managementReference);
            throw new BizException(401, "当前密码或MFA验证码错误");
        }

        long now = System.currentTimeMillis();
        long acceptedStep = -1L;
        MfaRecoveryCodes.Match recovery = MfaRecoveryCodes.Match.notFound(
                actor.getMfaRecoveryHashes());
        if (actor.getMfaEnabled() == 1) {
            byte[] secret = secretProtector.decrypt(actor.getMfaSecret());
            try {
                acceptedStep = TotpUtil.verify(
                        secret,
                        normalizeTotpFactor(factor),
                        now / 1_000L,
                        actor.getMfaLastTimeStep());
                if (acceptedStep < 0) {
                    recovery = MfaRecoveryCodes.findMatch(
                            actor.getMfaRecoveryHashes(), factor);
                }
                if (acceptedStep < 0 && !recovery.matched()) {
                    recordManagementFailure(managementReference);
                    throw new BizException(401, "当前密码或MFA验证码错误");
                }
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
        }

        long verifiedStep = acceptedStep;
        MfaRecoveryCodes.Match verifiedRecovery = recovery;
        DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
            WebUser currentActor = requireUser(actor.getId());
            if (!"ADMIN".equals(currentActor.getRole())
                    || !java.util.Objects.equals(currentActor.getPassword(), actor.getPassword())
                    || !sameMfaState(currentActor, actor)) {
                throw BizException.forbidden("管理员身份已变化，请重新登录");
            }
            if (currentActor.getMfaEnabled() == 1) {
                if (verifiedStep >= 0) {
                    if (verifiedStep <= currentActor.getMfaLastTimeStep()) {
                        throw new BizException(401, "当前密码或MFA验证码错误");
                    }
                    currentActor.setMfaLastTimeStep(verifiedStep);
                } else {
                    if (!java.util.Objects.equals(
                            currentActor.getMfaRecoveryHashes(), actor.getMfaRecoveryHashes())) {
                        throw new BizException(401, "当前密码或MFA验证码错误");
                    }
                    currentActor.setMfaRecoveryHashes(verifiedRecovery.remainingHashes());
                }
                currentActor.setMfaUpdatedAt(now);
                accessor.getUserDao().update(currentActor);
            }

            WebUser target = accessor.getUserDao().queryForId(targetUserId);
            if (target == null) {
                throw BizException.notFound("用户不存在");
            }
            if (target.getMfaEnabled() != 1) {
                throw new BizException("目标用户未启用 MFA");
            }
            clearMfaState(target, now);
            accessor.getUserDao().update(target);
            sessionService.revokeUser(target.getId());
            return null;
        });
        rateLimiter.clear(LoginRateLimiter.Scope.MFA_MANAGEMENT, managementReference);
    }

    /** Creates a digest-only challenge after a correct password. */
    @SneakyThrows
    public LoginChallenge createChallenge(WebUser user, String clientAddress) {
        if (user == null || user.getId() <= 0 || user.getMfaEnabled() != 1
                || user.getMfaSecret() == null || user.getMfaSecret().isBlank()) {
            throw new IllegalArgumentException("an enabled MFA user is required");
        }
        String token = randomToken();
        String tokenDigest = digest(token);
        String accountReference = rateLimiter.reference(
                LoginRateLimiter.Scope.ACCOUNT, accountKey(user));
        String addressReference = rateLimiter.reference(
                LoginRateLimiter.Scope.ADDRESS, normalizeAddress(clientAddress));
        long now = System.currentTimeMillis();
        DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
            Dao<WebMfaChallenge, String> dao = accessor.getMfaChallengeDao();
            purgeExpiredChallenges(dao, now);
            List<WebMfaChallenge> existing = dao.queryBuilder()
                    .where().eq("user_id", user.getId()).query();
            for (WebMfaChallenge challenge : existing) {
                dao.deleteById(challenge.getTokenDigest());
            }
            if (dao.countOf() >= MAX_CHALLENGES) {
                throw new BizException(503, "MFA challenge capacity reached; retry later");
            }
            dao.create(WebMfaChallenge.builder()
                    .tokenDigest(tokenDigest)
                    .userId(user.getId())
                    .accountReference(accountReference)
                    .addressReference(addressReference)
                    .expiresAt(Math.addExact(now, CHALLENGE_TTL_MILLIS))
                    .remainingAttempts(CHALLENGE_ATTEMPTS)
                    .createdAt(now)
                    .build());
            return null;
        });
        return new LoginChallenge(token, CHALLENGE_TTL_MILLIS / 1_000L);
    }

    /** Verifies a challenge and creates the full browser session atomically. */
    @SneakyThrows
    public SessionService.SessionToken verifyChallenge(
            String token,
            String factor,
            String clientAddress
    ) {
        if (!WebSessionSecurity.isValidOpaqueToken(token)) {
            throw invalidChallenge();
        }
        String tokenDigest = digest(token);
        String addressReference = rateLimiter.reference(
                LoginRateLimiter.Scope.ADDRESS, normalizeAddress(clientAddress));
        WebMfaChallenge challenge = accessor.getMfaChallengeDao().queryForId(tokenDigest);
        long now = System.currentTimeMillis();
        if (challenge == null || challenge.getExpiresAt() <= now
                || challenge.getRemainingAttempts() <= 0
                || !matches(challenge.getAddressReference(), addressReference)) {
            recordChallengeFailure(challenge, tokenDigest, clientAddress);
            throw invalidChallenge();
        }
        WebUser user = accessor.getUserDao().queryForId(challenge.getUserId());
        if (user == null || user.getStatus() != 1 || user.getMfaEnabled() != 1) {
            recordChallengeFailure(challenge, tokenDigest, clientAddress);
            throw invalidChallenge();
        }
        String expectedAccountReference = rateLimiter.reference(
                LoginRateLimiter.Scope.ACCOUNT, accountKey(user));
        if (!matches(challenge.getAccountReference(), expectedAccountReference)) {
            recordChallengeFailure(challenge, tokenDigest, clientAddress);
            throw invalidChallenge();
        }
        String accountReference = challenge.getAccountReference();
        String challengeReference = rateLimiter.reference(
                LoginRateLimiter.Scope.MFA_CHALLENGE, tokenDigest);
        long retryAfter = Math.max(
                rateLimiter.retryAfterSeconds(
                        LoginRateLimiter.Scope.ACCOUNT,
                        accountReference,
                        LoginRateLimiter.ACCOUNT_POLICY),
                Math.max(
                        rateLimiter.retryAfterSeconds(
                                LoginRateLimiter.Scope.ADDRESS,
                                addressReference,
                                LoginRateLimiter.ADDRESS_POLICY),
                        rateLimiter.retryAfterSeconds(
                                LoginRateLimiter.Scope.MFA_CHALLENGE,
                                challengeReference,
                                LoginRateLimiter.MFA_CHALLENGE_POLICY)));
        if (retryAfter > 0) {
            throw new BizException(429, "Too many MFA failures; retry after " + retryAfter + " seconds");
        }

        byte[] secret = secretProtector.decrypt(user.getMfaSecret());
        try {
            String normalizedTotp = normalizeTotpFactor(factor);
            long acceptedStep = TotpUtil.verify(
                    secret,
                    normalizedTotp,
                    now / 1_000L,
                    user.getMfaLastTimeStep());
            MfaRecoveryCodes.Match recovery = acceptedStep < 0
                    ? MfaRecoveryCodes.findMatch(user.getMfaRecoveryHashes(), factor)
                    : MfaRecoveryCodes.Match.notFound(user.getMfaRecoveryHashes());
            if (acceptedStep < 0 && !recovery.matched()) {
                recordFailure(
                        accountReference,
                        addressReference,
                        challengeReference,
                        challenge,
                        tokenDigest);
                throw invalidChallenge();
            }

            SessionService.SessionToken session = DatabaseTransactions.call(
                    accessor.getConnectionSource(), () -> {
                        WebUser current = requireUser(user.getId());
                        WebMfaChallenge currentChallenge = accessor.getMfaChallengeDao()
                                .queryForId(tokenDigest);
                        if (current.getStatus() != 1 || current.getMfaEnabled() != 1
                                || currentChallenge == null
                                || currentChallenge.getExpiresAt() <= System.currentTimeMillis()
                                || currentChallenge.getRemainingAttempts() <= 0
                                || !matches(
                                currentChallenge.getAddressReference(), addressReference)
                                || !matches(
                                currentChallenge.getAccountReference(), accountReference)) {
                            throw invalidChallenge();
                        }
                        if (acceptedStep >= 0) {
                            if (acceptedStep <= current.getMfaLastTimeStep()) {
                                throw invalidChallenge();
                            }
                            current.setMfaLastTimeStep(acceptedStep);
                        } else {
                            if (!java.util.Objects.equals(
                                    current.getMfaRecoveryHashes(), user.getMfaRecoveryHashes())) {
                                throw invalidChallenge();
                            }
                            current.setMfaRecoveryHashes(recovery.remainingHashes());
                        }
                        current.setLastLoginTime(TimeUtil.getCurtTime());
                        accessor.getUserDao().update(current);
                        accessor.getMfaChallengeDao().deleteById(tokenDigest);
                        return sessionService.createSession(current.getId());
                    });
            rateLimiter.clear(LoginRateLimiter.Scope.ACCOUNT, accountReference);
            rateLimiter.clear(LoginRateLimiter.Scope.ADDRESS, addressReference);
            rateLimiter.clear(LoginRateLimiter.Scope.MFA_CHALLENGE, challengeReference);
            return session;
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    private void verifyAndConsumeManagementFactor(
            WebUser user,
            String password,
            String factor,
            String replacementRecoveryHashes,
            boolean regenerate
    ) throws java.sql.SQLException {
        if (user.getMfaEnabled() != 1 || user.getMfaSecret() == null) {
            throw new BizException("MFA 已经禁用");
        }
        String managementReference = managementReference(user);
        checkManagementRateLimit(managementReference);
        if (!PasswordUtil.verifyPassword(password, user.getPassword())) {
            recordManagementFailure(managementReference);
            throw new BizException(401, "当前密码或MFA验证码错误");
        }
        byte[] secret = secretProtector.decrypt(user.getMfaSecret());
        try {
            long now = System.currentTimeMillis();
            long acceptedStep = TotpUtil.verify(
                    secret,
                    normalizeTotpFactor(factor),
                    now / 1_000L,
                    user.getMfaLastTimeStep());
            MfaRecoveryCodes.Match recovery = acceptedStep < 0
                    ? MfaRecoveryCodes.findMatch(user.getMfaRecoveryHashes(), factor)
                    : MfaRecoveryCodes.Match.notFound(user.getMfaRecoveryHashes());
            if (acceptedStep < 0 && !recovery.matched()) {
                recordManagementFailure(managementReference);
                throw new BizException(401, "当前密码或MFA验证码错误");
            }
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                WebUser current = requireUser(user.getId());
                if (!java.util.Objects.equals(current.getPassword(), user.getPassword())
                        || !sameMfaState(current, user)) {
                    throw new BizException(409, "账户安全状态已变化，请重试");
                }
                if (acceptedStep >= 0) {
                    if (acceptedStep <= current.getMfaLastTimeStep()) {
                        throw new BizException(401, "当前密码或MFA验证码错误");
                    }
                    current.setMfaLastTimeStep(acceptedStep);
                } else {
                    if (!java.util.Objects.equals(
                            current.getMfaRecoveryHashes(), user.getMfaRecoveryHashes())) {
                        throw new BizException(401, "当前密码或MFA验证码错误");
                    }
                    current.setMfaRecoveryHashes(recovery.remainingHashes());
                }
                if (regenerate) {
                    current.setMfaRecoveryHashes(replacementRecoveryHashes);
                } else {
                    clearMfaState(current, now);
                }
                current.setMfaUpdatedAt(now);
                accessor.getUserDao().update(current);
                sessionService.revokeUser(current.getId());
                return null;
            });
            rateLimiter.clear(
                    LoginRateLimiter.Scope.MFA_MANAGEMENT, managementReference);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    @SneakyThrows
    private void recordChallengeFailure(
            WebMfaChallenge challenge,
            String tokenDigest,
            String clientAddress
    ) {
        String addressReference = rateLimiter.reference(
                LoginRateLimiter.Scope.ADDRESS, normalizeAddress(clientAddress));
        String challengeReference = rateLimiter.reference(
                LoginRateLimiter.Scope.MFA_CHALLENGE, tokenDigest);
        if (challenge != null) {
            WebUser user = accessor.getUserDao().queryForId(challenge.getUserId());
            String accountReference = user == null
                    ? rateLimiter.reference(LoginRateLimiter.Scope.ACCOUNT, "unknown")
                    : rateLimiter.reference(LoginRateLimiter.Scope.ACCOUNT, accountKey(user));
            recordFailure(accountReference, addressReference, challengeReference, challenge, tokenDigest);
        } else {
            rateLimiter.recordFailure(
                    LoginRateLimiter.Scope.ADDRESS,
                    addressReference,
                    LoginRateLimiter.ADDRESS_POLICY);
            rateLimiter.recordFailure(
                    LoginRateLimiter.Scope.MFA_CHALLENGE,
                    challengeReference,
                    LoginRateLimiter.MFA_CHALLENGE_POLICY);
        }
    }

    private void recordFailure(
            String accountReference,
            String addressReference,
            String challengeReference,
            WebMfaChallenge challenge,
            String tokenDigest
    ) {
        boolean account = rateLimiter.recordFailure(
                LoginRateLimiter.Scope.ACCOUNT,
                accountReference,
                LoginRateLimiter.ACCOUNT_POLICY);
        boolean address = rateLimiter.recordFailure(
                LoginRateLimiter.Scope.ADDRESS,
                addressReference,
                LoginRateLimiter.ADDRESS_POLICY);
        boolean challengeRate = rateLimiter.recordFailure(
                LoginRateLimiter.Scope.MFA_CHALLENGE,
                challengeReference,
                LoginRateLimiter.MFA_CHALLENGE_POLICY);
        if (!account || !address || !challengeRate) {
            throw new BizException(429, "Login limiter capacity reached; retry later");
        }
        try {
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                WebMfaChallenge current = accessor.getMfaChallengeDao().queryForId(tokenDigest);
                if (current == null) {
                    return null;
                }
                int remaining = Math.max(0, current.getRemainingAttempts() - 1);
                if (remaining == 0 || current.getExpiresAt() <= System.currentTimeMillis()) {
                    accessor.getMfaChallengeDao().deleteById(tokenDigest);
                } else {
                    current.setRemainingAttempts(remaining);
                    accessor.getMfaChallengeDao().update(current);
                }
                return null;
            });
        } catch (java.sql.SQLException error) {
            throw new IllegalStateException("unable to persist MFA challenge failure", error);
        }
    }

    private static void purgeExpiredChallenges(Dao<WebMfaChallenge, String> dao, long now)
            throws java.sql.SQLException {
        List<WebMfaChallenge> expired = dao.queryBuilder()
                .where().le("expires_at", now)
                .queryBuilder().limit(1_000L).query();
        for (WebMfaChallenge challenge : expired) {
            dao.deleteById(challenge.getTokenDigest());
        }
    }

    private WebUser currentUser() throws java.sql.SQLException {
        UserContext context = UserContext.get();
        if (context == null) {
            throw BizException.unauthorized("未登录");
        }
        return requireUser(context.getUserId());
    }

    private WebUser requireUser(long userId) throws java.sql.SQLException {
        WebUser user = accessor.getUserDao().queryForId(userId);
        if (user == null || user.getStatus() != 1) {
            throw BizException.unauthorized("用户不存在或已禁用");
        }
        return user;
    }

    private String managementReference(WebUser user) {
        return rateLimiter.reference(
                LoginRateLimiter.Scope.MFA_MANAGEMENT, accountKey(user));
    }

    private void checkManagementRateLimit(String reference) {
        long retryAfter = rateLimiter.retryAfterSeconds(
                LoginRateLimiter.Scope.MFA_MANAGEMENT,
                reference,
                LoginRateLimiter.MFA_MANAGEMENT_POLICY);
        if (retryAfter > 0) {
            throw new BizException(
                    429,
                    "Too many MFA management failures; retry after "
                            + retryAfter + " seconds");
        }
    }

    private void recordManagementFailure(String reference) {
        if (!rateLimiter.recordFailure(
                LoginRateLimiter.Scope.MFA_MANAGEMENT,
                reference,
                LoginRateLimiter.MFA_MANAGEMENT_POLICY)) {
            throw new BizException(
                    429, "MFA management limiter capacity reached; retry later");
        }
    }

    private static boolean sameMfaState(WebUser current, WebUser snapshot) {
        return current.getMfaEnabled() == snapshot.getMfaEnabled()
                && current.getMfaLastTimeStep() == snapshot.getMfaLastTimeStep()
                && java.util.Objects.equals(
                        current.getMfaSecret(), snapshot.getMfaSecret())
                && java.util.Objects.equals(
                        current.getMfaPendingSecret(), snapshot.getMfaPendingSecret())
                && java.util.Objects.equals(
                        current.getMfaPendingCreatedAt(), snapshot.getMfaPendingCreatedAt())
                && java.util.Objects.equals(
                        current.getMfaRecoveryHashes(), snapshot.getMfaRecoveryHashes())
                && java.util.Objects.equals(
                        current.getMfaUpdatedAt(), snapshot.getMfaUpdatedAt());
    }

    private static String normalizeTotpFactor(String factor) {
        if (factor == null) {
            return null;
        }
        return factor.replace(" ", "").replace("-", "");
    }

    private static BizException invalidChallenge() {
        return new BizException(401, "MFA 验证失败或挑战已过期");
    }

    private static boolean matches(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                actual.getBytes(StandardCharsets.US_ASCII));
    }

    private static String randomToken() {
        byte[] value = new byte[32];
        RANDOM.nextBytes(value);
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
        } finally {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static String digest(String token) {
        byte[] input = token.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(input);
            try {
                return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            } finally {
                Arrays.fill(hash, (byte) 0);
            }
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        } finally {
            Arrays.fill(input, (byte) 0);
        }
    }

    private static String normalizeAddress(String address) {
        if (address == null || address.isBlank() || address.length() > 256) {
            return "unknown";
        }
        return address;
    }

    private static String accountKey(WebUser user) {
        return UsernamePolicy.accountKey(
                UsernamePolicy.normalizeForLogin(user == null ? null : user.getUsername()));
    }

    private static void clearMfaState(WebUser user, long now) {
        user.setMfaEnabled(0);
        user.setMfaSecret(null);
        user.setMfaPendingSecret(null);
        user.setMfaPendingCreatedAt(null);
        user.setMfaRecoveryHashes(null);
        user.setMfaLastTimeStep(0L);
        user.setMfaUpdatedAt(now);
    }

    public record LoginChallenge(String token, long expiresInSeconds) {
    }
}

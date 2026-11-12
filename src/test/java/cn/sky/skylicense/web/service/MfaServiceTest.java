package cn.sky.skylicense.web.service;

import cn.sky.skylicense.security.MfaSecretProtector;
import cn.sky.skylicense.utils.PasswordUtil;
import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.response.MfaEnrollmentResponse;
import cn.sky.skylicense.web.dto.response.MfaRecoveryCodesResponse;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MfaServiceTest {
    private static final String PASSWORD = "Strong#Password123";

    @TempDir
    Path temporaryDirectory;

    @AfterEach
    void clearContext() {
        UserContext.clear();
    }

    @Test
    void enrollmentRevokesSessionsAndRecoveryCodeCompletesPasswordLoginOnce() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        byte[] protectorKey = new byte[32];
        byte[] auditKey = new byte[32];
        Arrays.fill(protectorKey, (byte) 0x27);
        Arrays.fill(auditKey, (byte) 0x38);
        try (MfaSecretProtector protector = MfaSecretProtector.forKey(protectorKey);
             OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(auditKey)) {
            accessor.connect(temporaryDirectory.resolve("mfa.db").toString());
            WebUser user = WebUser.builder()
                    .username("admin")
                    .password(PasswordUtil.hashPassword(PASSWORD))
                    .role("ADMIN")
                    .maxPrograms(10)
                    .status(1)
                    .createTime("2026-01-01-00:00")
                    .build();
            accessor.getUserDao().create(user);

            SessionService sessions = new SessionService(accessor);
            SessionService.SessionToken oldSession = sessions.createSession(user.getId());
            UserContext.set(new UserContext(user.getId(), user.getUsername(), user.getRole(),
                    oldSession.csrfToken()));
            LoginRateLimiter limiter = new PersistentLoginRateLimiter(accessor, sanitizer);
            MfaService mfa = new MfaService(accessor, sessions, protector, limiter);

            MfaEnrollmentResponse enrollment = mfa.startEnrollment(PASSWORD);
            assertNotNull(enrollment.manualSecret());
            assertTrue(enrollment.otpauthUri().startsWith("otpauth://totp/"));
            byte[] secret = TotpUtil.decodeBase32(enrollment.manualSecret());
            MfaRecoveryCodesResponse recovery;
            try {
                long now = System.currentTimeMillis() / 1_000L;
                recovery = mfa.confirmEnrollment(
                        TotpUtil.codeAt(secret, now / TotpUtil.PERIOD_SECONDS));
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
            assertEquals(MfaRecoveryCodes.CODE_COUNT, recovery.recoveryCodes().size());
            assertFalse(sessions.isActive(oldSession.token()));
            assertEquals(1, accessor.getUserDao().queryForId(user.getId()).getMfaEnabled());

            UserContext.clear();
            AuthService auth = new AuthService(accessor, sessions, mfa, limiter);
            LoginRequestFactory requestFactory = new LoginRequestFactory();
            AuthService.LoginOutcome outcome = auth.authenticate(
                    requestFactory.request(), "127.0.0.1");
            assertTrue(outcome.mfaRequired());
            assertNotNull(outcome.challenge());

            SessionService.SessionToken authenticated = auth.verifyMfa(
                    outcome.challenge().token(), recovery.recoveryCodes().get(0), "127.0.0.1");
            assertTrue(sessions.isActive(authenticated.token()));
            assertEquals(9, MfaRecoveryCodes.count(
                    accessor.getUserDao().queryForId(user.getId()).getMfaRecoveryHashes()));
            assertThrows(
                    BizException.class,
                    () -> auth.verifyMfa(
                            outcome.challenge().token(),
                            recovery.recoveryCodes().get(0),
                            "127.0.0.1"));
        } finally {
            accessor.close();
            Arrays.fill(protectorKey, (byte) 0);
            Arrays.fill(auditKey, (byte) 0);
        }
    }

    @Test
    void invalidMfaFactorConsumesChallengeAttemptsAndDoesNotCreateASession() throws Exception {
        // This test exercises the bounded challenge state without spending the costly
        // recovery-code PBKDF2 path.
        WebDataAccessor accessor = new WebDataAccessor();
        byte[] protectorKey = new byte[32];
        byte[] auditKey = new byte[32];
        Arrays.fill(protectorKey, (byte) 0x17);
        Arrays.fill(auditKey, (byte) 0x18);
        try (MfaSecretProtector protector = MfaSecretProtector.forKey(protectorKey);
             OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(auditKey)) {
            accessor.connect(temporaryDirectory.resolve("mfa-invalid.db").toString());
            WebUser user = WebUser.builder()
                    .username("invalid-user")
                    .password(PasswordUtil.hashPassword(PASSWORD))
                    .role("USER")
                    .maxPrograms(1)
                    .status(1)
                    .mfaEnabled(1)
                    .mfaSecret(protector.encrypt(new byte[]{1, 2, 3, 4, 5}))
                    .mfaRecoveryHashes(PasswordUtil.hashPassword("ABCDEFGHJKLMNPQ2"))
                    .build();
            accessor.getUserDao().create(user);
            SessionService sessions = new SessionService(accessor);
            LoginRateLimiter limiter = new PersistentLoginRateLimiter(accessor, sanitizer);
            MfaService mfa = new MfaService(accessor, sessions, protector, limiter);
            AuthService auth = new AuthService(accessor, sessions, mfa, limiter);
            LoginRequestFactory requestFactory = new LoginRequestFactory("invalid-user");
            AuthService.LoginOutcome outcome = auth.authenticate(
                    requestFactory.request(), "127.0.0.1");
            for (int attempt = 0; attempt < MfaService.CHALLENGE_ATTEMPTS; attempt++) {
                assertThrows(
                        BizException.class,
                        () -> auth.verifyMfa(
                                outcome.challenge().token(), "000000", "127.0.0.1"));
            }
            assertEquals(0, accessor.getMfaChallengeDao().countOf());
            assertEquals(0, sessions.activeCount());
        } finally {
            accessor.close();
            Arrays.fill(protectorKey, (byte) 0);
            Arrays.fill(auditKey, (byte) 0);
        }
    }

    private static final class LoginRequestFactory {
        private final String username;

        private LoginRequestFactory() {
            this("admin");
        }

        private LoginRequestFactory(String username) {
            this.username = username;
        }

        private cn.sky.skylicense.web.dto.request.LoginRequest request() {
            cn.sky.skylicense.web.dto.request.LoginRequest request =
                    new cn.sky.skylicense.web.dto.request.LoginRequest();
            request.setUsername(username);
            request.setPassword(PASSWORD);
            return request;
        }
    }
}

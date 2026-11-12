package cn.sky.skylicense.web.service;

import cn.sky.skylicense.security.MfaSecretProtector;
import cn.sky.skylicense.utils.PasswordUtil;
import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.WebDataAccessor;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MfaAdministratorResetTest {
    private static final String PASSWORD = "Strong#Password123";
    private static final String RECOVERY_CODE = "ABCD-EFGH-JKLM-NPQ2";

    @TempDir
    Path temporaryDirectory;

    @AfterEach
    void clearContext() {
        UserContext.clear();
    }

    @Test
    void totpResetRequiresStepUpAndRevokesOnlyTheTarget() throws Exception {
        try (Fixture fixture = new Fixture(temporaryDirectory.resolve("admin-reset.db"))) {
            byte[] actorSecret = secret((byte) 0x31);
            byte[] targetSecret = secret((byte) 0x42);
            try {
                WebUser actor = fixture.createEnabledUser(
                        "actor-admin", "ADMIN", actorSecret, RECOVERY_CODE);
                WebUser target = fixture.createEnabledUser(
                        "target-user", "USER", targetSecret, RECOVERY_CODE);
                SessionService.SessionToken actorSession =
                        fixture.sessions.createSession(actor.getId());
                SessionService.SessionToken targetSession =
                        fixture.sessions.createSession(target.getId());
                fixture.mfa.createChallenge(target, "127.0.0.2");
                UserContext.set(new UserContext(
                        actor.getId(), actor.getUsername(), actor.getRole(),
                        actorSession.csrfToken()));

                assertThrows(
                        BizException.class,
                        () -> fixture.mfa.resetByAdministrator(
                                actor.getId(), PASSWORD, "000000"));
                assertThrows(
                        BizException.class,
                        () -> fixture.mfa.resetByAdministrator(
                                target.getId(), "Wrong#Password123", "000000"));
                assertThrows(
                        BizException.class,
                        () -> fixture.mfa.resetByAdministrator(
                                target.getId(), PASSWORD, "000000"));
                assertTrue(fixture.sessions.isActive(targetSession.token()));
                assertEquals(1, fixture.accessor.getMfaChallengeDao().countOf());

                long step = System.currentTimeMillis() / 1_000L / TotpUtil.PERIOD_SECONDS;
                fixture.mfa.resetByAdministrator(
                        target.getId(), PASSWORD, TotpUtil.codeAt(actorSecret, step));

                WebUser resetTarget = fixture.accessor.getUserDao().queryForId(target.getId());
                assertEquals(0, resetTarget.getMfaEnabled());
                assertNull(resetTarget.getMfaSecret());
                assertNull(resetTarget.getMfaRecoveryHashes());
                assertEquals(0L, resetTarget.getMfaLastTimeStep());
                assertFalse(fixture.sessions.isActive(targetSession.token()));
                assertEquals(0, fixture.accessor.getMfaChallengeDao().countOf());
                assertEquals(0, fixture.accessor.getLoginAttemptDao().countOf());
                assertTrue(fixture.sessions.isActive(actorSession.token()));

                WebUser currentActor = fixture.accessor.getUserDao().queryForId(actor.getId());
                assertEquals(1, currentActor.getMfaEnabled());
                assertTrue(currentActor.getMfaLastTimeStep() >= step - 1);
            } finally {
                Arrays.fill(actorSecret, (byte) 0);
                Arrays.fill(targetSecret, (byte) 0);
            }
        }
    }

    @Test
    void repeatedManagementFailuresLockTheAdministratorAccount() throws Exception {
        try (Fixture fixture = new Fixture(temporaryDirectory.resolve("admin-reset-limit.db"))) {
            byte[] actorSecret = secret((byte) 0x35);
            byte[] targetSecret = secret((byte) 0x46);
            try {
                WebUser actor = fixture.createEnabledUser(
                        "limited-admin", "ADMIN", actorSecret, RECOVERY_CODE);
                WebUser target = fixture.createEnabledUser(
                        "limited-target", "USER", targetSecret, RECOVERY_CODE);
                UserContext.set(new UserContext(
                        actor.getId(), actor.getUsername(), actor.getRole(), "csrf"));

                for (int attempt = 0;
                     attempt < LoginRateLimiter.MFA_MANAGEMENT_POLICY.maximumAttempts();
                     attempt++) {
                    BizException error = assertThrows(
                            BizException.class,
                            () -> fixture.mfa.resetByAdministrator(
                                    target.getId(), PASSWORD, "invalid"));
                    assertEquals(401, error.getCode());
                }

                long step = System.currentTimeMillis() / 1_000L / TotpUtil.PERIOD_SECONDS;
                BizException locked = assertThrows(
                        BizException.class,
                        () -> fixture.mfa.resetByAdministrator(
                                target.getId(), PASSWORD, TotpUtil.codeAt(actorSecret, step)));
                assertEquals(429, locked.getCode());
                assertEquals(
                        1,
                        fixture.accessor.getUserDao().queryForId(target.getId()).getMfaEnabled());
                assertEquals("MFA_MANAGEMENT", fixture.accessor.getLoginAttemptDao()
                        .queryForAll().get(0).getScope());
            } finally {
                Arrays.fill(actorSecret, (byte) 0);
                Arrays.fill(targetSecret, (byte) 0);
            }
        }
    }

    @Test
    void failedTargetLookupRollsBackRecoveryCodeConsumption() throws Exception {
        try (Fixture fixture = new Fixture(temporaryDirectory.resolve("admin-reset-rollback.db"))) {
            byte[] actorSecret = secret((byte) 0x51);
            byte[] targetSecret = secret((byte) 0x62);
            try {
                WebUser actor = fixture.createEnabledUser(
                        "recovery-admin", "ADMIN", actorSecret, RECOVERY_CODE);
                WebUser target = fixture.createEnabledUser(
                        "recovery-target", "USER", targetSecret, RECOVERY_CODE);
                UserContext.set(new UserContext(
                        actor.getId(), actor.getUsername(), actor.getRole(), "csrf"));

                assertThrows(
                        BizException.class,
                        () -> fixture.mfa.resetByAdministrator(
                                Long.MAX_VALUE, PASSWORD, RECOVERY_CODE));
                assertEquals(
                        1,
                        MfaRecoveryCodes.count(fixture.accessor.getUserDao()
                                .queryForId(actor.getId()).getMfaRecoveryHashes()));

                fixture.mfa.resetByAdministrator(target.getId(), PASSWORD, RECOVERY_CODE);
                assertEquals(
                        0,
                        MfaRecoveryCodes.count(fixture.accessor.getUserDao()
                                .queryForId(actor.getId()).getMfaRecoveryHashes()));
                assertEquals(
                        0,
                        fixture.accessor.getUserDao().queryForId(target.getId()).getMfaEnabled());
            } finally {
                Arrays.fill(actorSecret, (byte) 0);
                Arrays.fill(targetSecret, (byte) 0);
            }
        }
    }

    @Test
    void activeAdministratorWithoutMfaCanResetAnotherUserWithPassword() throws Exception {
        try (Fixture fixture = new Fixture(temporaryDirectory.resolve("admin-reset-password.db"))) {
            WebUser actor = fixture.createUser("bootstrap-admin", "ADMIN");
            byte[] targetSecret = secret((byte) 0x73);
            try {
                WebUser target = fixture.createEnabledUser(
                        "locked-user", "USER", targetSecret, RECOVERY_CODE);
                UserContext.set(new UserContext(
                        actor.getId(), actor.getUsername(), actor.getRole(), "csrf"));

                fixture.mfa.resetByAdministrator(target.getId(), PASSWORD, null);

                assertEquals(
                        0,
                        fixture.accessor.getUserDao().queryForId(target.getId()).getMfaEnabled());
            } finally {
                Arrays.fill(targetSecret, (byte) 0);
            }
        }
    }

    @Test
    void enrollmentAndSelfManagementUseTheSamePersistentThrottle() throws Exception {
        try (Fixture fixture = new Fixture(temporaryDirectory.resolve("mfa-management-limit.db"))) {
            WebUser enrollmentUser = fixture.createUser("enrollment-user", "USER");
            UserContext.set(new UserContext(
                    enrollmentUser.getId(), enrollmentUser.getUsername(),
                    enrollmentUser.getRole(), "csrf"));
            for (int attempt = 0;
                 attempt < LoginRateLimiter.MFA_MANAGEMENT_POLICY.maximumAttempts();
                 attempt++) {
                BizException error = assertThrows(
                        BizException.class,
                        () -> fixture.mfa.startEnrollment("Wrong#Password123"));
                assertEquals(401, error.getCode());
            }
            BizException enrollmentLocked = assertThrows(
                    BizException.class,
                    () -> fixture.mfa.startEnrollment(PASSWORD));
            assertEquals(429, enrollmentLocked.getCode());
            assertNull(fixture.accessor.getUserDao()
                    .queryForId(enrollmentUser.getId()).getMfaPendingSecret());

            WebUser confirmationUser = fixture.createUser("confirmation-user", "USER");
            UserContext.set(new UserContext(
                    confirmationUser.getId(), confirmationUser.getUsername(),
                    confirmationUser.getRole(), "csrf"));
            cn.sky.skylicense.web.dto.response.MfaEnrollmentResponse enrollment =
                    fixture.mfa.startEnrollment(PASSWORD);
            byte[] confirmationSecret = TotpUtil.decodeBase32(enrollment.manualSecret());
            try {
                for (int attempt = 0;
                     attempt < LoginRateLimiter.MFA_MANAGEMENT_POLICY.maximumAttempts();
                     attempt++) {
                    BizException error = assertThrows(
                            BizException.class,
                            () -> fixture.mfa.confirmEnrollment("invalid"));
                    assertEquals(401, error.getCode());
                }
                long step = System.currentTimeMillis() / 1_000L / TotpUtil.PERIOD_SECONDS;
                BizException confirmationLocked = assertThrows(
                        BizException.class,
                        () -> fixture.mfa.confirmEnrollment(
                                TotpUtil.codeAt(confirmationSecret, step)));
                assertEquals(429, confirmationLocked.getCode());
                assertEquals(
                        0,
                        fixture.accessor.getUserDao()
                                .queryForId(confirmationUser.getId()).getMfaEnabled());
            } finally {
                Arrays.fill(confirmationSecret, (byte) 0);
            }

            byte[] enabledSecret = secret((byte) 0x74);
            try {
                WebUser enabledUser = fixture.createEnabledUser(
                        "management-user", "USER", enabledSecret, RECOVERY_CODE);
                UserContext.set(new UserContext(
                        enabledUser.getId(), enabledUser.getUsername(),
                        enabledUser.getRole(), "csrf"));
                for (int attempt = 0;
                     attempt < LoginRateLimiter.MFA_MANAGEMENT_POLICY.maximumAttempts();
                     attempt++) {
                    BizException error = assertThrows(
                            BizException.class,
                            () -> fixture.mfa.disable(PASSWORD, "invalid"));
                    assertEquals(401, error.getCode());
                }
                long step = System.currentTimeMillis() / 1_000L / TotpUtil.PERIOD_SECONDS;
                BizException managementLocked = assertThrows(
                        BizException.class,
                        () -> fixture.mfa.disable(
                                PASSWORD, TotpUtil.codeAt(enabledSecret, step)));
                assertEquals(429, managementLocked.getCode());
                assertEquals(
                        1,
                        fixture.accessor.getUserDao()
                                .queryForId(enabledUser.getId()).getMfaEnabled());
            } finally {
                Arrays.fill(enabledSecret, (byte) 0);
            }
        }
    }

    @Test
    void administratorCannotDisableOwnMfaThroughSelfService() throws Exception {
        try (Fixture fixture = new Fixture(temporaryDirectory.resolve("admin-disable.db"))) {
            byte[] actorSecret = secret((byte) 0x5a);
            try {
                WebUser actor = fixture.createEnabledUser(
                        "self-disable-admin", "ADMIN", actorSecret, RECOVERY_CODE);
                UserContext.set(new UserContext(
                        actor.getId(), actor.getUsername(), actor.getRole(), "csrf", true));

                BizException error = assertThrows(
                        BizException.class,
                        () -> fixture.mfa.disable(PASSWORD, "000000"));

                assertEquals(403, error.getCode());
                WebUser unchanged = fixture.accessor.getUserDao().queryForId(actor.getId());
                assertEquals(1, unchanged.getMfaEnabled());
                assertTrue(unchanged.getMfaSecret() != null);
                assertEquals(0, fixture.accessor.getLoginAttemptDao().countOf());
            } finally {
                Arrays.fill(actorSecret, (byte) 0);
            }
        }
    }

    private static byte[] secret(byte value) {
        byte[] secret = new byte[TotpUtil.SECRET_BYTES];
        Arrays.fill(secret, value);
        return secret;
    }

    private static final class Fixture implements AutoCloseable {
        private final WebDataAccessor accessor = new WebDataAccessor();
        private final byte[] protectorKey = key((byte) 0x15);
        private final byte[] auditKey = key((byte) 0x26);
        private final MfaSecretProtector protector;
        private final OperationLogSanitizer sanitizer;
        private final SessionService sessions;
        private final LoginRateLimiter limiter;
        private final MfaService mfa;

        private Fixture(Path database) throws Exception {
            protector = MfaSecretProtector.forKey(protectorKey);
            sanitizer = OperationLogSanitizer.forKey(auditKey);
            accessor.connect(database.toString());
            sessions = new SessionService(accessor);
            limiter = new PersistentLoginRateLimiter(accessor, sanitizer);
            mfa = new MfaService(accessor, sessions, protector, limiter);
        }

        private WebUser createUser(String username, String role) throws Exception {
            WebUser user = WebUser.builder()
                    .username(username)
                    .password(PasswordUtil.hashPassword(PASSWORD))
                    .role(role)
                    .maxPrograms(10)
                    .status(1)
                    .createTime("2026-01-01-00:00")
                    .build();
            accessor.getUserDao().create(user);
            return user;
        }

        private WebUser createEnabledUser(
                String username,
                String role,
                byte[] secret,
                String recoveryCode
        ) throws Exception {
            WebUser user = WebUser.builder()
                    .username(username)
                    .password(PasswordUtil.hashPassword(PASSWORD))
                    .role(role)
                    .maxPrograms(10)
                    .status(1)
                    .createTime("2026-01-01-00:00")
                    .mfaEnabled(1)
                    .mfaSecret(protector.encrypt(secret))
                    .mfaRecoveryHashes(PasswordUtil.hashPassword(
                            recoveryCode.replace("-", "")))
                    .mfaLastTimeStep(0L)
                    .mfaUpdatedAt(1L)
                    .build();
            accessor.getUserDao().create(user);
            return user;
        }

        @Override
        public void close() {
            accessor.close();
            sanitizer.close();
            protector.close();
            Arrays.fill(protectorKey, (byte) 0);
            Arrays.fill(auditKey, (byte) 0);
        }

        private static byte[] key(byte value) {
            byte[] key = new byte[32];
            Arrays.fill(key, value);
            return key;
        }
    }
}

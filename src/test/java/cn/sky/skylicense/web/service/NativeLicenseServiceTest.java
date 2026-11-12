package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.request.UnbindRequest;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.BanRecord;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.security.UserContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeLicenseServiceTest {
    private static final String CODE = "TEST-LICENSE";
    private static final String PROGRAM_NAME = "TestProgram";
    private static final String FIRST_IP = "203.0.113.10";
    private static final String FIRST_HWID = "hwid-one";

    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private NativeLicenseService service;
    private LicenseService licenseService;
    private WebUser owner;
    private Program program;
    private License license;

    @BeforeEach
    void setUp() throws Exception {
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("license.db").toString());
        licenseService = new LicenseService(accessor);
        BanService banService = new BanService(accessor, licenseService);
        service = new NativeLicenseService(accessor, banService);

        owner = WebUser.builder()
                .username("owner")
                .password("not-used-by-this-test")
                .role("USER")
                .maxPrograms(5)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getUserDao().create(owner);

        program = Program.builder()
                .userId(owner.getId())
                .name(PROGRAM_NAME)
                .description("test")
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getProgramDao().create(program);

        license = License.builder()
                .code(CODE)
                .programId(program.getId())
                .userId(owner.getId())
                .qq("10001")
                .bindableIps(1)
                .bindableHwids(1)
                .status(1)
                .ips("")
                .hwids("")
                .createTime(TimeUtil.getCurtTime())
                .lastModifiedTime(TimeUtil.getCurtTime())
                .build();
        accessor.getLicenseDao().create(license);
    }

    @AfterEach
    void tearDown() {
        UserContext.clear();
        if (accessor != null) {
            accessor.close();
        }
    }

    @Test
    void resourceReleaseCommitsBindingsAndAcknowledgementConfirmsIt() throws Exception {
        NativeLicenseService.Decision preview = service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);

        assertTrue(preview.allowed());
        License unchanged = accessor.getLicenseDao().queryForId(license.getId());
        assertTrue(unchanged.parseIps().isEmpty());
        assertTrue(unchanged.parseHwids().isEmpty());
        assertTrue(accessor.getAuthLogDao().queryForAll().isEmpty());

        NativeLicenseService.Decision completed = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);

        assertTrue(completed.allowed());
        License pending = accessor.getLicenseDao().queryForId(license.getId());
        assertTrue(pending.parseIps().isEmpty());
        assertTrue(pending.parseHwids().isEmpty());
        assertTrue(pending.getLastAuthTime() == null || pending.getLastAuthTime().isBlank());
        assertEquals("PENDING", accessor.getAuthLogDao().queryForAll().get(0).getResult());
        assertFalse(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME, completed.authLogId()));

        service.commitResourceRelease(completed.authLogId());

        License bound = accessor.getLicenseDao().queryForId(license.getId());
        assertEquals(List.of(FIRST_IP), bound.parseIps());
        assertEquals(List.of(FIRST_HWID), bound.parseHwids());
        assertFalse(bound.getLastAuthTime().isBlank());
        assertEquals("RELEASED", accessor.getAuthLogDao()
                .queryForId(completed.authLogId()).getResult());
        assertTrue(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME, completed.authLogId()));

        service.recordDeliverySuccess(completed.authLogId());

        List<AuthLog> logs = accessor.getAuthLogDao().queryForAll();
        assertEquals(1, logs.size());
        assertEquals("OK", logs.get(0).getResult());
        assertEquals(program.getId(), logs.get(0).getProgramId());
        assertEquals(owner.getId(), logs.get(0).getUserId());
    }

    @Test
    void bindingLimitsRejectAdditionalAddressesAndMachines() {
        assertTrue(service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME).allowed());

        NativeLicenseService.Decision ipLimit = service.preAuthorize(
                CODE, "203.0.113.11", FIRST_HWID, PROGRAM_NAME);
        NativeLicenseService.Decision hwidLimit = service.preAuthorize(
                CODE, FIRST_IP, "hwid-two", PROGRAM_NAME);

        assertFalse(ipLimit.allowed());
        assertEquals("IP_LIMIT", ipLimit.result());
        assertFalse(hwidLimit.allowed());
        assertEquals("HWID_LIMIT", hwidLimit.result());
    }

    @Test
    void failedPendingReservationDoesNotConsumeBindingSlots() throws Exception {
        NativeLicenseService.Decision pending = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);

        License beforeFailure = accessor.getLicenseDao().queryForId(license.getId());
        assertTrue(beforeFailure.parseIps().isEmpty());
        assertTrue(beforeFailure.parseHwids().isEmpty());
        assertDecision("IP_LIMIT", service.preAuthorize(
                CODE, "203.0.113.11", FIRST_HWID, PROGRAM_NAME));
        assertDecision("HWID_LIMIT", service.preAuthorize(
                CODE, FIRST_IP, "hwid-two", PROGRAM_NAME));

        service.recordDeliveryFailure(pending.authLogId());

        License afterFailure = accessor.getLicenseDao().queryForId(license.getId());
        assertTrue(afterFailure.parseIps().isEmpty());
        assertTrue(afterFailure.parseHwids().isEmpty());
        assertTrue(service.preAuthorize(
                CODE, "203.0.113.11", "hwid-two", PROGRAM_NAME).allowed());
    }

    @Test
    void confirmationWriteFailureCannotRewriteACommittedAuthorization() throws Exception {
        NativeLicenseService.Decision authorization = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);
        service.commitResourceRelease(authorization.authLogId());
        service.recordDeliverySuccess(authorization.authLogId());

        // The transport confirmation may fail after this point. The signed ACK
        // already committed the binding and the daily-auth attempt, but the
        // audit must show that the client never received final confirmation.
        service.recordDeliveryFailure(authorization.authLogId());

        License stored = accessor.getLicenseDao().queryForId(license.getId());
        assertEquals(List.of(FIRST_IP), stored.parseIps());
        assertEquals(List.of(FIRST_HWID), stored.parseHwids());
        assertEquals("DELIVERY_UNCONFIRMED", accessor.getAuthLogDao()
                .queryForId(authorization.authLogId()).getResult());
        assertFalse(service.preAuthorize(
                CODE, "203.0.113.11", FIRST_HWID, PROGRAM_NAME).allowed());
    }

    @Test
    void unbindInvalidatesMatchingPendingAuthorizationAtomically() throws Exception {
        NativeLicenseService.Decision pending = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);
        UserContext.set(new UserContext(
                owner.getId(), owner.getUsername(), owner.getRole(), "A".repeat(43)));
        UnbindRequest request = new UnbindRequest();
        request.setAll(true);

        licenseService.unbind(CODE, request);

        assertEquals("DELIVERY_FAILED", accessor.getAuthLogDao()
                .queryForId(pending.authLogId()).getResult());
        assertThrows(
                IllegalStateException.class,
                () -> service.recordDeliverySuccess(pending.authLogId()));
        License stored = accessor.getLicenseDao().queryForId(license.getId());
        assertTrue(stored.parseIps().isEmpty());
        assertTrue(stored.parseHwids().isEmpty());
    }

    @Test
    void unbindRevokesReleasedAuthorizationWithoutRefundingItsQuota() throws Exception {
        license.setMaxDailyAuth(1);
        accessor.getLicenseDao().update(license);
        NativeLicenseService.Decision released = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);
        service.commitResourceRelease(released.authLogId());
        UserContext.set(new UserContext(
                owner.getId(), owner.getUsername(), owner.getRole(), "A".repeat(43)));
        UnbindRequest request = new UnbindRequest();
        request.setAll(true);

        licenseService.unbind(CODE, request);

        assertEquals("DELIVERY_UNCONFIRMED", accessor.getAuthLogDao()
                .queryForId(released.authLogId()).getResult());
        assertThrows(
                IllegalStateException.class,
                () -> service.recordDeliverySuccess(released.authLogId()));
        assertFalse(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME, released.authLogId()));
        assertDecision("DAILY_AUTH_LIMIT", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
    }

    @Test
    void heartbeatCannotBorrowAnotherSessionsPendingReservation() throws Exception {
        license.setBindableIps(2);
        license.setBindableHwids(2);
        accessor.getLicenseDao().update(license);
        NativeLicenseService.Decision first = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);
        NativeLicenseService.Decision second = service.completeAuthorization(
                CODE, "203.0.113.11", "hwid-two", PROGRAM_NAME);
        service.commitResourceRelease(first.authLogId());
        service.commitResourceRelease(second.authLogId());

        assertTrue(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME, first.authLogId()));
        assertTrue(service.isSessionAuthorized(
                CODE, "203.0.113.11", "hwid-two", PROGRAM_NAME, second.authLogId()));
        assertFalse(service.isSessionAuthorized(
                CODE, "203.0.113.11", "hwid-two", PROGRAM_NAME, first.authLogId()));
    }

    @Test
    void identityAndStatusFailuresAreRejectedWithAuditableReasons() throws Exception {
        assertDecision("PROGRAM_MISMATCH", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, "OtherProgram"));

        program.setStatus(0);
        accessor.getProgramDao().update(program);
        assertDecision("PROGRAM_DISABLED", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
        program.setStatus(1);
        accessor.getProgramDao().update(program);

        owner.setStatus(0);
        accessor.getUserDao().update(owner);
        assertDecision("USER_DISABLED", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
        owner.setStatus(1);
        accessor.getUserDao().update(owner);

        license.setStatus(0);
        license.setBanReason("revoked");
        accessor.getLicenseDao().update(license);
        assertDecision("BANNED", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));

        List<String> results = accessor.getAuthLogDao().queryForAll().stream()
                .map(AuthLog::getResult)
                .toList();
        assertEquals(List.of(
                "PROGRAM_MISMATCH", "PROGRAM_DISABLED", "USER_DISABLED", "BANNED"), results);
    }

    @Test
    void invalidOwnerMutationAndGlobalBanAreRejected() throws Exception {
        WebUser otherOwner = WebUser.builder()
                .username("other")
                .password("not-used-by-this-test")
                .role("USER")
                .maxPrograms(1)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getUserDao().create(otherOwner);
        license.setUserId(otherOwner.getId());
        assertThrows(SQLException.class, () -> accessor.getLicenseDao().update(license));

        license.setUserId(owner.getId());
        accessor.getBanRecordDao().create(BanRecord.builder()
                .type("HWID")
                .value(FIRST_HWID)
                .reason("compromised")
                .operatorId(owner.getId())
                .programId(program.getId())
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build());
        assertDecision("BANNED_BY_HWID", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
    }

    @Test
    void programScopedAndExpiredRulesDoNotLeakIntoOtherAuthorizations() throws Exception {
        WebUser otherOwner = WebUser.builder()
                .username("other-program-owner")
                .password("not-used-by-this-test")
                .role("USER")
                .maxPrograms(1)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getUserDao().create(otherOwner);
        Program otherProgram = Program.builder()
                .userId(otherOwner.getId())
                .name("OtherProgram")
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getProgramDao().create(otherProgram);

        accessor.getBanRecordDao().create(BanRecord.builder()
                .type("IP")
                .value(FIRST_IP)
                .programId(otherProgram.getId())
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build());
        assertTrue(service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME).allowed());

        accessor.getBanRecordDao().create(BanRecord.builder()
                .type("HWID")
                .value(FIRST_HWID)
                .programId(0)
                .status(1)
                .expirationDate("2000-01-01 00:00:00")
                .createTime(TimeUtil.getCurtTime())
                .build());
        assertTrue(service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME).allowed());

        accessor.getBanRecordDao().create(BanRecord.builder()
                .type("IP")
                .value(FIRST_IP)
                .programId(program.getId())
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build());
        assertDecision("BANNED_BY_IP", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
    }

    @Test
    void removingAnActiveBindingRevokesTheHeartbeatSessionButAllowsRebinding() throws Exception {
        NativeLicenseService.Decision authorization = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);
        assertTrue(authorization.allowed());
        service.commitResourceRelease(authorization.authLogId());
        service.recordDeliverySuccess(authorization.authLogId());
        assertTrue(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME, authorization.authLogId()));

        License stored = accessor.getLicenseDao().queryForId(license.getId());
        stored.setHwids("");
        accessor.getLicenseDao().update(stored);

        assertFalse(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME, authorization.authLogId()));
        assertTrue(service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME).allowed());
    }

    @Test
    void releasedResourceConsumesDailyQuotaEvenWhenAcknowledgementIsMissing()
            throws Exception {
        license.setMaxDailyAuth(1);
        accessor.getLicenseDao().update(license);

        NativeLicenseService.Decision firstAuthorization = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);
        assertTrue(firstAuthorization.allowed());
        assertDecision("DAILY_AUTH_LIMIT", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
        assertFalse(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME,
                firstAuthorization.authLogId()));

        service.commitResourceRelease(firstAuthorization.authLogId());
        assertTrue(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME,
                firstAuthorization.authLogId()));
        service.recordDeliveryFailure(firstAuthorization.authLogId());
        assertDecision("DAILY_AUTH_LIMIT", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
        assertFalse(service.isSessionAuthorized(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME,
                firstAuthorization.authLogId()));

        List<String> results = accessor.getAuthLogDao().queryForAll().stream()
                .map(AuthLog::getResult)
                .toList();
        assertEquals(List.of(
                "DELIVERY_UNCONFIRMED", "DAILY_AUTH_LIMIT", "DAILY_AUTH_LIMIT"),
                results);
    }

    @Test
    void unfinishedDeliveryIsRecoveredAndDoesNotConsumeDailyQuota() throws Exception {
        license.setMaxDailyAuth(1);
        accessor.getLicenseDao().update(license);

        NativeLicenseService.Decision pending = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);
        assertEquals("PENDING", accessor.getAuthLogDao().queryForId(pending.authLogId()).getResult());
        assertEquals(1, service.recoverPendingDeliveries());
        assertEquals("DELIVERY_FAILED",
                accessor.getAuthLogDao().queryForId(pending.authLogId()).getResult());
        License recovered = accessor.getLicenseDao().queryForId(license.getId());
        assertTrue(recovered.parseIps().isEmpty());
        assertTrue(recovered.parseHwids().isEmpty());
        assertTrue(recovered.getLastAuthTime() == null || recovered.getLastAuthTime().isBlank());
        assertTrue(service.preAuthorize(CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME).allowed());
        assertEquals(0, service.recoverPendingDeliveries());
    }

    @Test
    void releasedDeliveryRecoveryRetainsBindingsAndDailyQuota() throws Exception {
        license.setMaxDailyAuth(1);
        accessor.getLicenseDao().update(license);
        NativeLicenseService.Decision released = service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME);
        service.commitResourceRelease(released.authLogId());

        assertEquals(1, service.recoverPendingDeliveries());

        assertEquals("DELIVERY_UNCONFIRMED", accessor.getAuthLogDao()
                .queryForId(released.authLogId()).getResult());
        License recovered = accessor.getLicenseDao().queryForId(license.getId());
        assertEquals(List.of(FIRST_IP), recovered.parseIps());
        assertEquals(List.of(FIRST_HWID), recovered.parseHwids());
        assertFalse(recovered.getLastAuthTime().isBlank());
        assertDecision("DAILY_AUTH_LIMIT", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
        assertEquals(0, service.recoverPendingDeliveries());
    }

    @Test
    void authorizationBindingRollsBackWhenSuccessAuditCannotBeWritten() throws Exception {
        try (Connection connection = accessor.getDataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE TRIGGER fail_auth_log_insert "
                    + "BEFORE INSERT ON auth_log BEGIN "
                    + "SELECT RAISE(ABORT, 'forced audit failure'); END");
        }

        assertThrows(IllegalStateException.class, () -> service.completeAuthorization(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));

        License rolledBack = accessor.getLicenseDao().queryForId(license.getId());
        assertTrue(rolledBack.parseIps().isEmpty());
        assertTrue(rolledBack.parseHwids().isEmpty());
        assertTrue(rolledBack.getLastAuthTime() == null || rolledBack.getLastAuthTime().isBlank());
        assertTrue(accessor.getAuthLogDao().queryForAll().isEmpty());
    }

    @Test
    void expiredLicenseIsRejected() throws Exception {
        license.setExpirationDate("2000-01-01-00:00");
        accessor.getLicenseDao().update(license);

        assertDecision("EXPIRED", service.preAuthorize(
                CODE, FIRST_IP, FIRST_HWID, PROGRAM_NAME));
    }

    private static void assertDecision(
            String expectedResult,
            NativeLicenseService.Decision decision
    ) {
        assertFalse(decision.allowed());
        assertEquals(expectedResult, decision.result());
    }
}

package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.request.AdminCreateLicenseRequest;
import cn.sky.skylicense.web.dto.request.BatchLicenseRequest;
import cn.sky.skylicense.web.dto.request.CreateLicenseRequest;
import cn.sky.skylicense.web.dto.request.UnbindRequest;
import cn.sky.skylicense.web.dto.request.UpdateLicenseRequest;
import cn.sky.skylicense.web.dto.query.AuthLogQuery;
import cn.sky.skylicense.web.dto.query.LicenseQuery;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LicenseServiceTest {
    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private LicenseService service;
    private WebUser owner;
    private Program program;

    @BeforeEach
    void setUp() throws Exception {
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("licenses.db").toString());
        service = new LicenseService(accessor);
        owner = createUser("owner", "USER");
        program = createProgram(owner, "OwnedProgram");
    }

    @AfterEach
    void tearDown() {
        UserContext.clear();
        if (accessor != null) {
            accessor.close();
        }
    }

    @Test
    void administratorAllProgramsCreationUsesProgramOwnerAndPolicyFields() throws Exception {
        WebUser admin = createUser("admin", "ADMIN");
        UserContext.set(context(admin));
        AdminCreateLicenseRequest request = new AdminCreateLicenseRequest();
        request.setAllPrograms(true);
        request.setProgramIds(List.of());
        request.setQq("10001");
        request.setBindableIps(2);
        request.setBindableHwids(1);
        request.setExpirationDate("2099-12-31-23:59");
        request.setMaxDailyAuth(5);

        List<License> created = service.adminCreateLicense(request);

        assertEquals(1, created.size());
        License license = created.get(0);
        assertEquals(owner.getId(), license.getUserId());
        assertEquals(program.getId(), license.getProgramId());
        assertEquals("2099-12-31-23:59", license.getExpirationDate());
        assertEquals(5, license.getMaxDailyAuth());
    }

    @Test
    void creationNormalizesValidCodesAndRejectsUnsafeCodes() throws Exception {
        UserContext.set(context(owner));
        CreateLicenseRequest valid = new CreateLicenseRequest();
        valid.setCode("  SAFE-CODE_1  ");

        License created = service.createLicense(program.getId(), valid);

        assertEquals("SAFE-CODE_1", created.getCode());

        CreateLicenseRequest invalid = new CreateLicenseRequest();
        invalid.setCode("unsafe code");
        assertThrows(BizException.class, () -> service.createLicense(program.getId(), invalid));
        assertEquals(1, accessor.getLicenseDao().countOf());
    }

    @Test
    void multiProgramCreationRejectsCodeThatExceedsLimitAfterSuffixing() throws Exception {
        Program second = createProgram(owner, "SecondProgram");
        UserContext.set(context(owner));
        CreateLicenseRequest request = new CreateLicenseRequest();
        request.setCode("A".repeat(256));
        request.setProgramIds(List.of(program.getId(), second.getId()));

        assertThrows(BizException.class, () -> service.createLicenseMulti(request));
        assertEquals(0, accessor.getLicenseDao().countOf());
    }

    @Test
    void unbindCanonicalizesIpv6AndInvalidatesMatchingPendingDelivery() throws Exception {
        UserContext.set(context(owner));
        License license = service.createLicense(program.getId(), new CreateLicenseRequest());
        license.setIps("2001:db8::1,198.51.100.10");
        accessor.getLicenseDao().update(license);
        AuthLog pending = authLog(license, "2001:db8::1", null, NativeLicenseService.PENDING);
        accessor.getAuthLogDao().create(pending);

        UnbindRequest request = new UnbindRequest();
        request.setIp(" 2001:0db8:0:0:0:0:0:1 ");
        License changed = service.unbind(license.getCode(), request);

        assertEquals(List.of("198.51.100.10"), changed.parseIps());
        assertEquals(
                NativeLicenseService.DELIVERY_FAILED,
                accessor.getAuthLogDao().queryForId(pending.getId()).getResult());
    }

    @Test
    void unbindRejectsInvalidIpWithoutChangingStoredBindings() throws Exception {
        UserContext.set(context(owner));
        License license = service.createLicense(program.getId(), new CreateLicenseRequest());
        license.setIps("198.51.100.10");
        accessor.getLicenseDao().update(license);

        UnbindRequest request = new UnbindRequest();
        request.setIp("not-an-ip");

        assertThrows(BizException.class, () -> service.unbind(license.getCode(), request));
        assertEquals(
                List.of("198.51.100.10"),
                accessor.getLicenseDao().queryForId(license.getId()).parseIps());
    }

    @Test
    void unbindTrimsLegacyHwidAndInvalidatesReleasedDelivery() throws Exception {
        UserContext.set(context(owner));
        License license = service.createLicense(program.getId(), new CreateLicenseRequest());
        String legacyHwid = "legacy-hwid:device-01";
        license.setHwids(legacyHwid);
        accessor.getLicenseDao().update(license);
        AuthLog released = authLog(
                license, null, legacyHwid, NativeLicenseService.RELEASED);
        accessor.getAuthLogDao().create(released);

        UnbindRequest request = new UnbindRequest();
        request.setHwid("  " + legacyHwid + "  ");
        License changed = service.unbind(license.getCode(), request);

        assertEquals(List.of(), changed.parseHwids());
        assertEquals(
                NativeLicenseService.DELIVERY_UNCONFIRMED,
                accessor.getAuthLogDao().queryForId(released.getId()).getResult());
    }

    @Test
    void unbindAllIgnoresIndividualValues() throws Exception {
        UserContext.set(context(owner));
        License license = service.createLicense(program.getId(), new CreateLicenseRequest());
        license.setIps("198.51.100.10");
        license.setHwids("legacy-hwid");
        accessor.getLicenseDao().update(license);

        UnbindRequest request = new UnbindRequest();
        request.setAll(true);
        request.setIp("not-an-ip");
        request.setHwid("X".repeat(257));

        License changed = service.unbind(license.getCode(), request);

        assertEquals(List.of(), changed.parseIps());
        assertEquals(List.of(), changed.parseHwids());
    }

    @Test
    void updateCanClearOptionalTextAndExpirationWithoutResettingOmittedFields()
            throws Exception {
        UserContext.set(context(owner));
        CreateLicenseRequest create = new CreateLicenseRequest();
        create.setQq("10001");
        create.setBindableIps(3);
        create.setBindableHwids(2);
        create.setNotes("initial");
        create.setExpirationDate("2099-12-31-23:59");
        create.setMaxDailyAuth(4);
        License license = service.createLicense(program.getId(), create);

        UpdateLicenseRequest update = new UpdateLicenseRequest();
        update.setQq("");
        update.setNotes("");
        update.setExpirationDate("");
        update.setMaxDailyAuth(0);
        License changed = service.updateLicense(license.getCode(), update);

        assertNull(changed.getQq());
        assertNull(changed.getNotes());
        assertNull(changed.getExpirationDate());
        assertEquals(0, changed.getMaxDailyAuth());
        assertEquals(3, changed.getBindableIps());
        assertEquals(2, changed.getBindableHwids());
    }

    @Test
    void updateRejectsBindingLimitBelowExistingBindings() throws Exception {
        UserContext.set(context(owner));
        CreateLicenseRequest create = new CreateLicenseRequest();
        create.setBindableIps(3);
        create.setBindableHwids(3);
        License license = service.createLicense(program.getId(), create);
        license.setIps("198.51.100.10,198.51.100.11");
        license.setHwids("hwid-a,hwid-b");
        accessor.getLicenseDao().update(license);

        UpdateLicenseRequest updateIps = new UpdateLicenseRequest();
        updateIps.setBindableIps(1);
        assertThrows(
                BizException.class,
                () -> service.updateLicense(license.getCode(), updateIps));

        UpdateLicenseRequest updateHwids = new UpdateLicenseRequest();
        updateHwids.setBindableHwids(1);
        assertThrows(
                BizException.class,
                () -> service.updateLicense(license.getCode(), updateHwids));

        License unchanged = accessor.getLicenseDao().queryForId(license.getId());
        assertEquals(3, unchanged.getBindableIps());
        assertEquals(3, unchanged.getBindableHwids());
    }

    @Test
    void multiProgramCreationRollsBackWhenALaterCodeConflicts() throws Exception {
        Program second = createProgram(owner, "SecondProgram");
        UserContext.set(context(owner));

        CreateLicenseRequest existingRequest = new CreateLicenseRequest();
        existingRequest.setCode("BATCH-" + second.getId());
        service.createLicense(second.getId(), existingRequest);

        CreateLicenseRequest batch = new CreateLicenseRequest();
        batch.setCode("BATCH");
        batch.setProgramIds(List.of(program.getId(), second.getId()));

        assertThrows(BizException.class, () -> service.createLicenseMulti(batch));
        assertEquals(1, accessor.getLicenseDao().countOf());
        assertNull(accessor.getLicenseDao().queryBuilder()
                .where().eq("code", "BATCH-" + program.getId()).queryForFirst());
    }

    @Test
    void administratorMultiProgramCreationIsAtomicOnConflict() throws Exception {
        Program second = createProgram(owner, "SecondProgram");
        UserContext.set(context(owner));
        CreateLicenseRequest existingRequest = new CreateLicenseRequest();
        existingRequest.setCode("ADMIN-BATCH-" + second.getId());
        service.createLicense(second.getId(), existingRequest);

        WebUser admin = createUser("admin", "ADMIN");
        UserContext.set(context(admin));
        AdminCreateLicenseRequest request = new AdminCreateLicenseRequest();
        request.setProgramIds(List.of(program.getId(), second.getId()));
        request.setCode("ADMIN-BATCH");

        assertThrows(BizException.class, () -> service.adminCreateLicense(request));
        assertEquals(1, accessor.getLicenseDao().countOf());
        assertNull(accessor.getLicenseDao().queryBuilder()
                .where().eq("code", "ADMIN-BATCH-" + program.getId()).queryForFirst());
    }

    @Test
    void batchDeleteChecksAllOwnershipBeforeDeletingAnything() throws Exception {
        UserContext.set(context(owner));
        CreateLicenseRequest ownedRequest = new CreateLicenseRequest();
        ownedRequest.setCode("OWNED");
        service.createLicense(program.getId(), ownedRequest);

        WebUser other = createUser("other", "USER");
        Program otherProgram = createProgram(other, "OtherProgram");
        UserContext.set(context(other));
        CreateLicenseRequest foreignRequest = new CreateLicenseRequest();
        foreignRequest.setCode("FOREIGN");
        service.createLicense(otherProgram.getId(), foreignRequest);

        UserContext.set(context(owner));
        BatchLicenseRequest batch = new BatchLicenseRequest();
        batch.setCodes(List.of("OWNED", "FOREIGN"));

        assertThrows(BizException.class, () -> service.batchDelete(batch));
        assertEquals(2, accessor.getLicenseDao().countOf());
    }

    @Test
    void licenseHistoryCannotCrossContaminateWhenACodeIsReused() throws Exception {
        UserContext.set(context(owner));
        CreateLicenseRequest request = new CreateLicenseRequest();
        request.setCode("REUSED-CODE");
        License oldLicense = service.createLicense(program.getId(), request);
        accessor.getAuthLogDao().create(AuthLog.builder()
                .licenseId(oldLicense.getId())
                .code(oldLicense.getCode())
                .programId(program.getId())
                .userId(owner.getId())
                .ip("198.51.100.10")
                .hwid("old-hwid")
                .result("OK")
                .timestamp(TimeUtil.getCurtTime())
                .build());

        service.deleteLicense(oldLicense.getCode());
        License newLicense = service.createLicense(program.getId(), request);
        AuthLog newLog = AuthLog.builder()
                .licenseId(newLicense.getId())
                .code(newLicense.getCode())
                .programId(program.getId())
                .userId(owner.getId())
                .ip("198.51.100.11")
                .hwid("new-hwid")
                .result("OK")
                .timestamp(TimeUtil.getCurtTime())
                .build();
        accessor.getAuthLogDao().create(newLog);

        var history = service.getAuthLogs(newLicense.getCode(), 1, 20);
        assertEquals(1, history.getTotal());
        assertEquals(newLog.getId(), history.getRecords().get(0).getId());
    }

    @Test
    void listFiltersEscapeSqlWildcardsAndRejectInvalidRanges() throws Exception {
        UserContext.set(context(owner));
        CreateLicenseRequest literalPercent = new CreateLicenseRequest();
        literalPercent.setCode("PERCENT-CODE");
        literalPercent.setNotes("contains%marker");
        service.createLicense(program.getId(), literalPercent);

        CreateLicenseRequest ordinary = new CreateLicenseRequest();
        ordinary.setCode("ORDINARY-CODE");
        ordinary.setNotes("ordinary marker");
        service.createLicense(program.getId(), ordinary);

        LicenseQuery query = new LicenseQuery();
        query.setKeyword("%");
        var result = service.listByProgram(program.getId(), 1, 20, query);
        assertEquals(1, result.getTotal());
        assertEquals("PERCENT-CODE", result.getRecords().get(0).getCode());

        LicenseQuery invalidSort = new LicenseQuery();
        invalidSort.setSortBy("random()");
        assertThrows(
                BizException.class,
                () -> service.listByProgram(program.getId(), 1, 20, invalidSort));

        AuthLogQuery inverted = new AuthLogQuery();
        inverted.setStartTime("2026-02-01-00:00");
        inverted.setEndTime("2026-01-01-00:00");
        assertThrows(
                BizException.class,
                () -> service.getAuthLogsByUser(inverted, 1, 20));
    }

    private WebUser createUser(String username, String role) throws Exception {
        WebUser user = WebUser.builder()
                .username(username)
                .password("not-used")
                .role(role)
                .maxPrograms(10)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getUserDao().create(user);
        return user;
    }

    private Program createProgram(WebUser user, String name) throws Exception {
        Program created = Program.builder()
                .userId(user.getId())
                .name(name)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getProgramDao().create(created);
        return created;
    }

    private static AuthLog authLog(
            License license,
            String ip,
            String hwid,
            String result
    ) {
        return AuthLog.builder()
                .licenseId(license.getId())
                .code(license.getCode())
                .programId(license.getProgramId())
                .userId(license.getUserId())
                .ip(ip)
                .hwid(hwid)
                .result(result)
                .timestamp(TimeUtil.getCurtTime())
                .build();
    }

    private static UserContext context(WebUser user) {
        return new UserContext(
                user.getId(), user.getUsername(), user.getRole(), "A".repeat(43));
    }
}

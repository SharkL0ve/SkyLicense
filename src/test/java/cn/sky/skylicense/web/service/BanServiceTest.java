package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.request.BanRequest;
import cn.sky.skylicense.web.entity.BanRecord;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BanServiceTest {
    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private BanService service;
    private WebUser owner;
    private Program firstProgram;
    private Program secondProgram;
    private License firstLicense;
    private License secondLicense;

    @BeforeEach
    void setUp() throws Exception {
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("ban.db").toString());
        LicenseService licenseService = new LicenseService(accessor);
        service = new BanService(accessor, licenseService);

        owner = createUser("owner", "USER");
        firstProgram = createProgram(owner, "FirstProgram");
        secondProgram = createProgram(owner, "SecondProgram");
        firstLicense = createLicense("FIRST-CODE", firstProgram);
        secondLicense = createLicense("SECOND-CODE", secondProgram);
        UserContext.set(context(owner));
    }

    @AfterEach
    void tearDown() {
        UserContext.clear();
        if (accessor != null) {
            accessor.close();
        }
    }

    @Test
    void programScopedRulesDoNotChangeMatchingLicensesInAnotherProgram() throws Exception {
        BanRecord firstRule = service.createBan(request("IP", "203.0.113.8", firstProgram.getId()));

        assertEquals(firstProgram.getId(), firstRule.getProgramId());
        assertEquals(0, accessor.getLicenseDao().queryForId(firstLicense.getId()).getStatus());
        assertEquals(1, accessor.getLicenseDao().queryForId(secondLicense.getId()).getStatus());
        assertNotNull(service.checkBanned(firstLicense, "203.0.113.8", "shared-hwid"));
        assertNull(service.checkBanned(secondLicense, "203.0.113.8", "shared-hwid"));

        BanRecord secondRule = service.createBan(request(
                "IP", "203.0.113.8", secondProgram.getId()));
        assertEquals(secondProgram.getId(), secondRule.getProgramId());
        assertEquals(0, accessor.getLicenseDao().queryForId(secondLicense.getId()).getStatus());
    }

    @Test
    void ordinaryUsersCannotCreateGlobalOrForeignProgramRules() throws Exception {
        assertThrows(BizException.class, () -> service.createBan(request("QQ", "10001", null)));

        WebUser foreignOwner = createUser("foreign", "USER");
        Program foreignProgram = createProgram(foreignOwner, "ForeignProgram");
        assertThrows(BizException.class, () -> service.createBan(request(
                "HWID", "shared-hwid", foreignProgram.getId())));
    }

    @Test
    void administratorGlobalRuleAffectsAllPrograms() throws Exception {
        WebUser admin = createUser("admin", "ADMIN");
        UserContext.set(context(admin));

        service.createBan(request("QQ", "10001", null));

        assertEquals(0, accessor.getLicenseDao().queryForId(firstLicense.getId()).getStatus());
        assertEquals(0, accessor.getLicenseDao().queryForId(secondLicense.getId()).getStatus());
    }

    @Test
    void deletingRuleRollsBackWhenAffectedLicenseCannotBeRestored() throws Exception {
        BanRecord rule = service.createBan(request("IP", "203.0.113.8", firstProgram.getId()));
        try (Connection connection = accessor.getDataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE TRIGGER fail_license_restore "
                    + "BEFORE UPDATE ON license WHEN NEW.status = 1 BEGIN "
                    + "SELECT RAISE(ABORT, 'forced restore failure'); END");
        }

        assertThrows(Exception.class, () -> service.deleteBan(rule.getId()));
        assertNotNull(accessor.getBanRecordDao().queryForId(rule.getId()));
        assertEquals(0, accessor.getLicenseDao().queryForId(firstLicense.getId()).getStatus());
    }

    @Test
    void rejectsMalformedTypedValuesAndCanonicalizesIpv6() throws Exception {
        assertThrows(BizException.class, () -> service.createBan(request(
                "IP", "license.example.com", firstProgram.getId())));
        assertThrows(BizException.class, () -> service.createBan(request(
                "HWID", "not-base64", firstProgram.getId())));
        assertThrows(BizException.class, () -> service.createBan(request(
                "QQ", "account@example.com", firstProgram.getId())));
        assertThrows(BizException.class, () -> service.createBan(request(
                "CODE", "bad@code", firstProgram.getId())));

        BanRecord record = service.createBan(request(
                "IP", " 2001:0db8:0:0::1 ", firstProgram.getId()));
        assertEquals("2001:db8::1", record.getValue());
    }

    @Test
    void overlappingRuleRemovalRestoresOnlyAfterTheLastRuleIsGone() throws Exception {
        BanRecord ipRule = service.createBan(request(
                "IP", "203.0.113.8", firstProgram.getId()));
        BanRecord qqRule = service.createBan(request(
                "QQ", "10001", firstProgram.getId()));

        assertEquals(0, accessor.getLicenseDao().queryForId(firstLicense.getId()).getStatus());

        service.deleteBan(ipRule.getId());
        assertEquals(0, accessor.getLicenseDao().queryForId(firstLicense.getId()).getStatus());

        service.deleteBan(qqRule.getId());
        assertEquals(1, accessor.getLicenseDao().queryForId(firstLicense.getId()).getStatus());
        assertNull(accessor.getLicenseDao().queryForId(firstLicense.getId()).getBanReason());
    }

    @Test
    void expiredRuleIsDeactivatedAndItsExistingLicenseIsRestored() throws Exception {
        BanRequest request = request("IP", "203.0.113.8", firstProgram.getId());
        request.setExpirationDate("2099-12-31-23:59");
        BanRecord rule = service.createBan(request);
        rule.setExpirationDate("2000-01-01-00:00");
        accessor.getBanRecordDao().update(rule);

        assertEquals(0, accessor.getLicenseDao().queryForId(firstLicense.getId()).getStatus());
        assertEquals(1, service.expireDueBans());
        assertEquals(0, accessor.getBanRecordDao().queryForId(rule.getId()).getStatus());
        assertEquals(1, accessor.getLicenseDao().queryForId(firstLicense.getId()).getStatus());
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
        Program program = Program.builder()
                .userId(user.getId())
                .name(name)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getProgramDao().create(program);
        return program;
    }

    private License createLicense(String code, Program program) throws Exception {
        License license = License.builder()
                .code(code)
                .programId(program.getId())
                .userId(program.getUserId())
                .qq("10001")
                .bindableIps(1)
                .bindableHwids(1)
                .status(1)
                .ips("203.0.113.8")
                .hwids("shared-hwid")
                .createTime(TimeUtil.getCurtTime())
                .lastModifiedTime(TimeUtil.getCurtTime())
                .build();
        accessor.getLicenseDao().create(license);
        return license;
    }

    private static BanRequest request(String type, String value, Long programId) {
        BanRequest request = new BanRequest();
        request.setType(type);
        request.setValue(value);
        request.setProgramId(programId);
        request.setReason("test");
        return request;
    }

    private static UserContext context(WebUser user) {
        return new UserContext(
                user.getId(), user.getUsername(), user.getRole(), "A".repeat(43));
    }
}

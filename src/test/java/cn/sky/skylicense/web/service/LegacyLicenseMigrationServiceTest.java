package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.WebUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LegacyLicenseMigrationServiceTest {
    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private Path legacyDatabase;

    @BeforeEach
    void setUp() throws Exception {
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("web.db").toString());
        WebUser owner = WebUser.builder()
                .username("owner")
                .password("not-used-by-this-test")
                .role("USER")
                .maxPrograms(10)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getUserDao().create(owner);
        createProgram(owner, "Product");
        createProgram(owner, "Other");

        legacyDatabase = temporaryDirectory.resolve("magiclicense.db");
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + legacyDatabase);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE license_user_data ("
                    + "code TEXT PRIMARY KEY, pluginName TEXT, qq TEXT, bindable INTEGER, "
                    + "status INTEGER, ips TEXT, createTime TEXT, lastLoginTime TEXT, "
                    + "unbindNumber INTEGER, lastUnbindTime TEXT, notes TEXT)");
        }
        insertLegacy("ONE", "Product", "123", 2, 1, "198.51.100.1", "first");
        insertLegacy("ALL", "all", "456", 1, 0, "", "banned");
    }

    @AfterEach
    void tearDown() {
        if (accessor != null) {
            accessor.close();
        }
    }

    @Test
    void migrationCreatesOwnerBoundWebLicensesAndAStableBackup() throws Exception {
        LegacyLicenseMigrationService service = new LegacyLicenseMigrationService(
                accessor, legacyDatabase);

        LegacyLicenseMigrationService.MigrationReport report = service.migrateIfNeeded();

        assertTrue(report.completed());
        assertEquals(2, report.sourceCount());
        assertEquals(3, report.createdCount());
        assertEquals(3, accessor.getLicenseDao().countOf());
        assertTrue(Files.isRegularFile(
                legacyDatabase.resolveSibling("magiclicense.db.pre-web-migration-v1.bak")));

        License specific = accessor.getLicenseDao().queryBuilder()
                .where().eq("code", "ONE").queryForFirst();
        assertEquals(2, specific.getBindableIps());
        assertEquals("198.51.100.1", specific.getIps());
        assertEquals(0, specific.getBindableHwids());

        Program other = accessor.getProgramDao().queryBuilder()
                .where().eq("name", "Other").queryForFirst();
        License allForOther = accessor.getLicenseDao().queryBuilder()
                .where().eq("code", "ALL-p" + other.getId()).queryForFirst();
        assertEquals(other.getId(), allForOther.getProgramId());
        assertEquals(0, allForOther.getStatus());
        assertFalse(allForOther.getNotes().isBlank());

        LegacyLicenseMigrationService.MigrationReport second = service.migrateIfNeeded();
        assertTrue(second.completed());
        assertEquals(0, second.sourceCount());
        assertEquals(3, accessor.getLicenseDao().countOf());
    }

    @Test
    void unresolvedProgramKeepsMigrationPendingAndCanBeRetried() throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + legacyDatabase);
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO license_user_data "
                             + "(code, pluginName, qq, bindable, status, ips, createTime, "
                             + "lastLoginTime, unbindNumber, lastUnbindTime, notes) "
                             + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, "MISSING");
            statement.setString(2, "NotCreatedYet");
            statement.setString(3, "");
            statement.setInt(4, 1);
            statement.setInt(5, 1);
            statement.setString(6, "");
            statement.setString(7, "now");
            statement.setString(8, "none");
            statement.setInt(9, 0);
            statement.setString(10, "null");
            statement.setString(11, "pending");
            statement.executeUpdate();
        }

        LegacyLicenseMigrationService service = new LegacyLicenseMigrationService(
                accessor, legacyDatabase);
        LegacyLicenseMigrationService.MigrationReport report = service.migrateIfNeeded();

        assertFalse(report.completed());
        assertEquals(1, report.unresolvedCount());
        assertEquals(3, accessor.getLicenseDao().countOf());
    }

    private Program createProgram(WebUser owner, String name) throws Exception {
        Program program = Program.builder()
                .userId(owner.getId())
                .name(name)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getProgramDao().create(program);
        return program;
    }

    private void insertLegacy(
            String code,
            String program,
            String qq,
            int bindable,
            int status,
            String ips,
            String notes
    ) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + legacyDatabase);
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO license_user_data "
                             + "(code, pluginName, qq, bindable, status, ips, createTime, "
                             + "lastLoginTime, unbindNumber, lastUnbindTime, notes) "
                             + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, code);
            statement.setString(2, program);
            statement.setString(3, qq);
            statement.setInt(4, bindable);
            statement.setInt(5, status);
            statement.setString(6, ips);
            statement.setString(7, "2026-07-18 00:00:00");
            statement.setString(8, "2026-07-18 00:00:01");
            statement.setInt(9, 2);
            statement.setString(10, "2026-07-18 00:00:02");
            statement.setString(11, notes);
            statement.executeUpdate();
        }
    }
}

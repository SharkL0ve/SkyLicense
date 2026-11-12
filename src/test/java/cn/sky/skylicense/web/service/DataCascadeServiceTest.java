package cn.sky.skylicense.web.service;

import cn.sky.skylicense.security.SecureFiles;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.BanRecord;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.ProgramVersion;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.entity.WebSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataCascadeServiceTest {
    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private DataCascadeService service;
    private WebUser owner;
    private Program program;
    private Path resourceFile;

    @BeforeEach
    void setUp() throws Exception {
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("cascade.db").toString());
        Path resourceBase = SecureFiles.preparePrivateDirectory(
                temporaryDirectory.resolve("resources"));
        resourceFile = resourceBase.resolve("resource.jar");
        Files.writeString(resourceFile, "test", StandardCharsets.UTF_8);
        service = new DataCascadeService(accessor, resourceBase);

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
                .name("Product")
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getProgramDao().create(program);
        accessor.getProgramVersionDao().create(ProgramVersion.builder()
                .programId(program.getId())
                .version("1.0.0")
                .fileName(resourceFile.getFileName().toString())
                .filePath(resourceFile.toString())
                .entryClass("test/Entry")
                .entryPoint("run")
                .uploadTime(TimeUtil.getCurtTime())
                .build());
        License license = License.builder()
                .code("CODE")
                .programId(program.getId())
                .userId(owner.getId())
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getLicenseDao().create(license);
        accessor.getAuthLogDao().create(AuthLog.builder()
                .licenseId(license.getId())
                .code(license.getCode())
                .programId(program.getId())
                .userId(owner.getId())
                .result("OK")
                .timestamp(TimeUtil.getCurtTime())
                .build());
        accessor.getBanRecordDao().create(BanRecord.builder()
                .type("CODE")
                .value(license.getCode())
                .operatorId(owner.getId())
                .programId(program.getId())
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build());
        accessor.getSessionDao().create(WebSession.builder()
                .tokenDigest("S".repeat(43))
                .userId(owner.getId())
                .csrfToken("C".repeat(43))
                .expiresAt(System.currentTimeMillis() + 60_000)
                .createdAt(System.currentTimeMillis())
                .build());
    }

    @AfterEach
    void tearDown() {
        if (accessor != null) {
            accessor.close();
        }
    }

    @Test
    void programDeletionCascadesDatabaseRowsAndProtectedFile() throws Exception {
        service.deleteProgram(program);

        assertNull(accessor.getProgramDao().queryForId(program.getId()));
        assertEquals(0, accessor.getProgramVersionDao().countOf());
        assertEquals(0, accessor.getLicenseDao().countOf());
        assertEquals(0, accessor.getAuthLogDao().countOf());
        assertEquals(0, accessor.getBanRecordDao().countOf());
        assertEquals(1, accessor.getSessionDao().countOf());
        assertFalse(Files.exists(resourceFile));
    }

    @Test
    void userDeletionIncludesAllOwnedProgramData() throws Exception {
        service.deleteUser(owner);

        assertNull(accessor.getUserDao().queryForId(owner.getId()));
        assertEquals(0, accessor.getProgramDao().countOf());
        assertEquals(0, accessor.getProgramVersionDao().countOf());
        assertEquals(0, accessor.getLicenseDao().countOf());
        assertEquals(0, accessor.getAuthLogDao().countOf());
        assertEquals(0, accessor.getBanRecordDao().countOf());
        assertEquals(0, accessor.getSessionDao().countOf());
        assertFalse(Files.exists(resourceFile));
    }

    @Test
    void databaseFailureRestoresQuarantinedArtifactAndRows() throws Exception {
        try (java.sql.Connection connection = accessor.getDataSource().getConnection();
             java.sql.Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TRIGGER reject_program_delete
                    BEFORE DELETE ON program
                    BEGIN
                      SELECT RAISE(ABORT, 'injected delete failure');
                    END
                    """);
        }

        assertThrows(Exception.class, () -> service.deleteProgram(program));

        assertTrue(Files.isRegularFile(resourceFile));
        assertNotNull(accessor.getProgramDao().queryForId(program.getId()));
        assertEquals(1, accessor.getProgramVersionDao().countOf());
        assertEquals(1, accessor.getLicenseDao().countOf());
        assertEquals(1, accessor.getAuthLogDao().countOf());
        assertEquals(1, accessor.getBanRecordDao().countOf());
    }
}

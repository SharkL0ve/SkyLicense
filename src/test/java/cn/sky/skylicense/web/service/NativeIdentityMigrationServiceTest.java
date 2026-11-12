package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.BanRecord;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.WebUser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeIdentityMigrationServiceTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void normalizesLegacyIpsAndPreservesUnconvertibleHwids() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("identities.db").toString());
            String validHwid = validHwid();
            WebUser owner = WebUser.builder()
                    .username("legacy-owner")
                    .password("stored-password")
                    .role("USER")
                    .maxPrograms(1)
                    .status(1)
                    .createTime(TimeUtil.getCurtTime())
                    .build();
            accessor.getUserDao().create(owner);
            Program program = Program.builder()
                    .userId(owner.getId())
                    .name("LegacyProgram")
                    .status(1)
                    .createTime(TimeUtil.getCurtTime())
                    .build();
            accessor.getProgramDao().create(program);
            License license = License.builder()
                    .code("LEGACY")
                    .programId(program.getId())
                    .userId(owner.getId())
                    .bindableIps(4)
                    .bindableHwids(4)
                    .status(0)
                    .ips("2001:0db8:0:0:0:0:0:1,2001:db8::1,legacy-ip")
                    .hwids(" legacy-hwid ,legacy-hwid," + validHwid)
                    .banReason("[license-ban-rule:IP=2001:0db8:0:0:0:0:0:1] legacy")
                    .createTime(TimeUtil.getCurtTime())
                    .build();
            accessor.getLicenseDao().create(license);
            BanRecord ban = BanRecord.builder()
                    .type("IP")
                    .value("2001:0db8:0:0:0:0:0:1")
                    .operatorId(owner.getId())
                    .programId(program.getId())
                    .status(1)
                    .createTime(TimeUtil.getCurtTime())
                    .build();
            accessor.getBanRecordDao().create(ban);
            AuthLog pending = AuthLog.builder()
                    .licenseId(license.getId())
                    .code(license.getCode())
                    .ip("2001:0db8:0:0:0:0:0:1")
                    .hwid(" " + validHwid + " ")
                    .result(NativeLicenseService.PENDING)
                    .timestamp(TimeUtil.getCurtTime())
                    .programId(program.getId())
                    .userId(owner.getId())
                    .build();
            accessor.getAuthLogDao().create(pending);

            NativeIdentityMigrationService service =
                    new NativeIdentityMigrationService(accessor);
            NativeIdentityMigrationService.MigrationReport report = service.migrateIfNeeded();

            License migrated = accessor.getLicenseDao().queryForId(license.getId());
            assertEquals("2001:db8::1,legacy-ip", migrated.getIps());
            assertEquals("legacy-hwid," + validHwid, migrated.getHwids());
            assertTrue(migrated.getBanReason().startsWith(
                    "[license-ban-rule:IP=2001:db8::1]"));
            assertEquals("2001:db8::1", accessor.getBanRecordDao()
                    .queryForId(ban.getId()).getValue());
            AuthLog migratedPending = accessor.getAuthLogDao().queryForId(pending.getId());
            assertEquals("2001:db8::1", migratedPending.getIp());
            assertEquals(validHwid, migratedPending.getHwid());
            assertEquals(1, report.invalidLegacyIps());
            assertEquals(1, report.invalidLegacyHwids());
            assertTrue(service.migrateIfNeeded().skipped());
        } finally {
            accessor.close();
        }
    }

    private static String validHwid() {
        byte[] value = new byte[32];
        Arrays.fill(value, (byte) 1);
        return Base64.getEncoder().encodeToString(value);
    }
}

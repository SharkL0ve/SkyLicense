package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.SystemMetadata;
import com.j256.ormlite.misc.TransactionManager;
import lombok.SneakyThrows;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** One-shot, idempotent migration from the obsolete license_user_data table. */
@Service
public class LegacyLicenseMigrationService {
    private static final Logger LOG = LogManager.getLogger(LegacyLicenseMigrationService.class);
    private static final String MIGRATION_KEY = "legacy-license-migration-v1";
    private static final String REPORT_KEY = MIGRATION_KEY + ".report";
    private static final String SOURCE_DATABASE = "magiclicense.db";

    private final WebDataAccessor accessor;
    private final Path sourceDatabase;

    @Autowired
    public LegacyLicenseMigrationService(WebDataAccessor accessor) {
        this(accessor, Path.of(SOURCE_DATABASE));
    }

    LegacyLicenseMigrationService(WebDataAccessor accessor, Path sourceDatabase) {
        this.accessor = accessor;
        this.sourceDatabase = sourceDatabase.toAbsolutePath().normalize();
    }

    @SneakyThrows
    public MigrationReport migrateIfNeeded() {
        SystemMetadata completed = accessor.getSystemMetadataDao().queryForId(MIGRATION_KEY);
        if (completed != null) {
            return new MigrationReport(0, 0, 0, 0, List.of(), List.of(), true);
        }
        if (!Files.isRegularFile(sourceDatabase)) {
            LOG.info("No legacy license database found at {}; migration skipped", sourceDatabase);
            return new MigrationReport(0, 0, 0, 0, List.of(), List.of(), false);
        }

        Path backup = backupSource();
        List<LegacyLicense> legacyLicenses = readLegacyLicenses();
        MigrationPlan plan = buildPlan(legacyLicenses);
        boolean complete = plan.unmapped().isEmpty() && plan.conflicts().isEmpty();
        TransactionManager.callInTransaction(accessor.getConnectionSource(), () -> {
            for (PlannedLicense planned : plan.licenses()) {
                if (accessor.getLicenseDao().queryBuilder()
                        .where().eq("code", planned.license().getCode()).queryForFirst() == null) {
                    accessor.getLicenseDao().create(planned.license());
                }
            }
            String report = plan.report(backup);
            accessor.getSystemMetadataDao().createOrUpdate(SystemMetadata.builder()
                    .key(REPORT_KEY)
                    .value(report)
                    .build());
            if (complete) {
                accessor.getSystemMetadataDao().createOrUpdate(SystemMetadata.builder()
                        .key(MIGRATION_KEY)
                        .value(report)
                        .build());
            }
            return null;
        });

        if (!complete) {
            LOG.warn("Legacy license migration remains pending: {}", plan.report(backup));
        } else {
            LOG.info("Legacy license migration completed: {}", plan.report(backup));
        }
        return new MigrationReport(
                legacyLicenses.size(),
                plan.licenses().size(),
                plan.existingCount(),
                plan.unmapped().size() + plan.conflicts().size(),
                plan.unmapped(),
                plan.conflicts(),
                complete);
    }

    private Path backupSource() throws IOException {
        Path backup = sourceDatabase.resolveSibling(
                sourceDatabase.getFileName() + ".pre-web-migration-v1.bak");
        if (!Files.exists(backup)) {
            Files.copy(sourceDatabase, backup, StandardCopyOption.COPY_ATTRIBUTES);
            if (Files.size(backup) != Files.size(sourceDatabase)) {
                throw new IOException("legacy database backup size verification failed");
            }
            LOG.info("Legacy license database backed up to {}", backup);
        }
        return backup;
    }

    private List<LegacyLicense> readLegacyLicenses() throws SQLException {
        List<LegacyLicense> records = new ArrayList<>();
        String url = "jdbc:sqlite:" + sourceDatabase;
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            try (ResultSet table = statement.executeQuery(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                            + "AND name='license_user_data'")) {
                if (!table.next()) {
                    return records;
                }
            }
            try (ResultSet result = statement.executeQuery(
                    "SELECT code, pluginName, qq, bindable, status, ips, createTime, "
                            + "lastLoginTime, unbindNumber, lastUnbindTime, notes "
                            + "FROM license_user_data")) {
                while (result.next()) {
                    records.add(new LegacyLicense(
                            result.getString("code"),
                            result.getString("pluginName"),
                            result.getString("qq"),
                            result.getInt("bindable"),
                            result.getInt("status"),
                            result.getString("ips"),
                            result.getString("createTime"),
                            result.getString("lastLoginTime"),
                            result.getInt("unbindNumber"),
                            result.getString("lastUnbindTime"),
                            result.getString("notes")));
                }
            }
        }
        return records;
    }

    private MigrationPlan buildPlan(List<LegacyLicense> legacyLicenses) throws SQLException {
        Map<String, List<Program>> programsByName = new HashMap<>();
        for (Program program : accessor.getProgramDao().queryForAll()) {
            programsByName.computeIfAbsent(
                    program.getName().toLowerCase(Locale.ROOT), ignored -> new ArrayList<>())
                    .add(program);
        }

        List<PlannedLicense> planned = new ArrayList<>();
        List<String> unmapped = new ArrayList<>();
        List<String> conflicts = new ArrayList<>();
        Set<String> plannedCodes = new HashSet<>();
        int existingCount = 0;
        for (LegacyLicense legacy : legacyLicenses) {
            if (legacy.code() == null || legacy.code().isBlank()) {
                unmapped.add("<blank-code>");
                continue;
            }
            List<Program> targets = resolvePrograms(legacy, programsByName);
            if (targets.isEmpty()) {
                unmapped.add(legacy.code() + " [program=" + legacy.pluginName() + "]");
                continue;
            }
            if (!"all".equalsIgnoreCase(legacy.pluginName()) && targets.size() != 1) {
                conflicts.add(legacy.code() + " [ambiguous program="
                        + legacy.pluginName() + "]");
                continue;
            }
            for (Program target : targets) {
                String code = legacy.pluginName() != null
                        && "all".equalsIgnoreCase(legacy.pluginName())
                        ? legacy.code() + "-p" + target.getId()
                        : legacy.code();
                if (!plannedCodes.add(code)) {
                    conflicts.add(code + " [duplicate migration target]");
                    continue;
                }
                License existing = accessor.getLicenseDao().queryBuilder()
                        .where().eq("code", code).queryForFirst();
                if (existing != null) {
                    if (existing.getProgramId() == target.getId()
                            && existing.getUserId() == target.getUserId()) {
                        existingCount++;
                    } else {
                        conflicts.add(code + " [already owned by program "
                                + existing.getProgramId() + "]");
                    }
                    continue;
                }
                planned.add(new PlannedLicense(toLicense(legacy, target, code)));
            }
        }
        return new MigrationPlan(planned, existingCount, unmapped, conflicts);
    }

    private static List<Program> resolvePrograms(
            LegacyLicense legacy,
            Map<String, List<Program>> programsByName
    ) {
        if (legacy.pluginName() == null || legacy.pluginName().isBlank()) {
            return List.of();
        }
        if ("all".equalsIgnoreCase(legacy.pluginName())) {
            return programsByName.values().stream().flatMap(List::stream).toList();
        }
        List<Program> matches = programsByName.get(
                legacy.pluginName().toLowerCase(Locale.ROOT));
        return matches == null ? List.of() : matches;
    }

    private static License toLicense(LegacyLicense legacy, Program program, String code) {
        int bindableIps = Math.max(0, legacy.bindable());
        int status = legacy.status() == 0 ? 0 : 1;
        String notes = legacy.notes();
        String migrationNotes = "Migrated from legacy license_user_data"
                + "; unbindNumber=" + legacy.unbindNumber()
                + "; lastUnbindTime=" + legacy.lastUnbindTime();
        notes = notes == null || notes.isBlank()
                ? migrationNotes
                : notes + "\n" + migrationNotes;
        return License.builder()
                .code(code)
                .programId(program.getId())
                .userId(program.getUserId())
                .qq(normalizeNullable(legacy.qq()))
                .bindableIps(bindableIps)
                .bindableHwids(0)
                .status(status)
                .ips(normalizeList(legacy.ips()))
                .hwids("")
                .createTime(normalizeNullable(legacy.createTime()))
                .lastAuthTime(normalizeNullable(legacy.lastLoginTime()))
                .banReason(status == 0 ? normalizeNullable(legacy.notes()) : null)
                .notes(notes)
                .lastModifiedTime(TimeUtil.getCurtTime())
                .maxDailyAuth(0)
                .build();
    }

    private static String normalizeNullable(String value) {
        return value == null || value.isBlank() || "null".equalsIgnoreCase(value)
                ? null : value;
    }

    private static String normalizeList(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        Set<String> values = new java.util.LinkedHashSet<>();
        for (String item : value.split(",")) {
            if (!item.isBlank()) {
                values.add(item.trim());
            }
        }
        return String.join(",", values);
    }

    public record MigrationReport(
            int sourceCount,
            int createdCount,
            int existingCount,
            int unresolvedCount,
            List<String> unmapped,
            List<String> conflicts,
            boolean completed
    ) {
    }

    private record LegacyLicense(
            String code,
            String pluginName,
            String qq,
            int bindable,
            int status,
            String ips,
            String createTime,
            String lastLoginTime,
            int unbindNumber,
            String lastUnbindTime,
            String notes
    ) {
    }

    private record PlannedLicense(License license) {
    }

    private record MigrationPlan(
            List<PlannedLicense> licenses,
            int existingCount,
            List<String> unmapped,
            List<String> conflicts
    ) {
        private String report(Path backup) {
            String value = "backup=" + backup
                    + ";created=" + licenses.size()
                    + ";existing=" + existingCount
                    + ";unmapped=" + unmapped.size()
                    + ";conflicts=" + conflicts.size()
                    + ";unmappedRecords=" + unmapped
                    + ";conflictRecords=" + conflicts;
            return value.length() <= 8192 ? value : value.substring(0, 8192);
        }
    }
}

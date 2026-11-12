package cn.sky.skylicense.web.service;

import cn.sky.skylicense.security.NativeIdentifierValidator;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.BanRecord;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.SystemMetadata;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.stmt.Where;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/** One-shot normalization for identities written before the protocol-v4 canonical boundary. */
public final class NativeIdentityMigrationService {
    private static final Logger LOG = LogManager.getLogger(NativeIdentityMigrationService.class);
    private static final String MIGRATION_KEY = "native-identity-normalization-v1";
    private static final int BATCH_SIZE = 500;

    private final WebDataAccessor accessor;

    public NativeIdentityMigrationService(WebDataAccessor accessor) {
        this.accessor = accessor;
    }

    public MigrationReport migrateIfNeeded() {
        try {
            MigrationReport result = DatabaseTransactions.call(
                    accessor.getConnectionSource(), () -> {
                        if (accessor.getSystemMetadataDao().queryForId(MIGRATION_KEY) != null) {
                            return MigrationReport.skippedReport();
                        }

                        MutableReport report = new MutableReport();
                        Map<String, String> banMarkerReplacements = new LinkedHashMap<>();
                        migrateBanRecords(report, banMarkerReplacements);
                        migrateLicenses(report, banMarkerReplacements);
                        migratePendingAuthLogs(report);

                        MigrationReport migrated = report.result(false);
                        accessor.getSystemMetadataDao().createOrUpdate(SystemMetadata.builder()
                                .key(MIGRATION_KEY)
                                .value(migrated.summary())
                                .build());
                        return migrated;
                    });
            if (result.skipped()) {
                return result;
            }
            if (result.invalidLegacyIps() > 0 || result.invalidLegacyHwids() > 0) {
                LOG.warn("Native identity normalization completed with retained legacy values: {}",
                        result.summary());
            } else {
                LOG.info("Native identity normalization completed: {}", result.summary());
            }
            return result;
        } catch (SQLException error) {
            throw new IllegalStateException("Unable to normalize legacy native identities", error);
        }
    }

    private void migrateBanRecords(
            MutableReport report,
            Map<String, String> markerReplacements
    ) throws SQLException {
        Dao<BanRecord, Long> dao = accessor.getBanRecordDao();
        long afterId = 0;
        while (true) {
            QueryBuilder<BanRecord, Long> query = dao.queryBuilder();
            query.where().gt("id", afterId);
            List<BanRecord> records = query.orderBy("id", true).limit((long) BATCH_SIZE).query();
            if (records.isEmpty()) {
                return;
            }
            for (BanRecord record : records) {
                afterId = record.getId();
                String value = record.getValue();
                String normalized = value == null ? null : value.trim();
                if ("IP".equals(record.getType())) {
                    try {
                        normalized = NativeIdentifierValidator.normalizeIpLiteral(normalized);
                    } catch (IllegalArgumentException error) {
                        report.invalidLegacyIps++;
                        continue;
                    }
                } else if ("HWID".equals(record.getType())) {
                    if (!NativeIdentifierValidator.isValidHwid(normalized)) {
                        report.invalidLegacyHwids++;
                    }
                } else {
                    continue;
                }
                if (normalized != null && !normalized.equals(value)) {
                    markerReplacements.put(
                            ruleMarker(record.getType(), value),
                            ruleMarker(record.getType(), normalized));
                    record.setValue(normalized);
                    dao.update(record);
                    report.normalizedBanRecords++;
                }
            }
        }
    }

    private void migrateLicenses(
            MutableReport report,
            Map<String, String> markerReplacements
    ) throws SQLException {
        Dao<License, Long> dao = accessor.getLicenseDao();
        long afterId = 0;
        while (true) {
            QueryBuilder<License, Long> query = dao.queryBuilder();
            query.where().gt("id", afterId);
            List<License> licenses = query.orderBy("id", true).limit((long) BATCH_SIZE).query();
            if (licenses.isEmpty()) {
                return;
            }
            for (License license : licenses) {
                afterId = license.getId();
                ListNormalization ips = normalizeIpList(license.parseIps());
                ListNormalization hwids = normalizeHwidList(license.parseHwids());
                report.invalidLegacyIps += ips.invalidValues();
                report.invalidLegacyHwids += hwids.invalidValues();

                String normalizedIps = License.joinList(ips.values());
                String normalizedHwids = License.joinList(hwids.values());
                boolean changed = !normalizedIps.equals(nullToEmpty(license.getIps()))
                        || !normalizedHwids.equals(nullToEmpty(license.getHwids()));
                if (!normalizedIps.equals(nullToEmpty(license.getIps()))) {
                    license.setIps(normalizedIps);
                    report.normalizedLicenseIpRows++;
                }
                if (!normalizedHwids.equals(nullToEmpty(license.getHwids()))) {
                    license.setHwids(normalizedHwids);
                    report.normalizedLicenseHwidRows++;
                }
                String updatedReason = replaceMarker(license.getBanReason(), markerReplacements);
                if (!java.util.Objects.equals(updatedReason, license.getBanReason())) {
                    license.setBanReason(updatedReason);
                    changed = true;
                    report.normalizedBanMarkers++;
                }
                if (changed) {
                    dao.update(license);
                }
            }
        }
    }

    private void migratePendingAuthLogs(MutableReport report) throws SQLException {
        Dao<AuthLog, Long> dao = accessor.getAuthLogDao();
        long afterId = 0;
        while (true) {
            QueryBuilder<AuthLog, Long> query = dao.queryBuilder();
            Where<AuthLog, Long> where = query.where();
            where.gt("id", afterId).and().in(
                    "result", List.of(NativeLicenseService.PENDING, NativeLicenseService.RELEASED));
            List<AuthLog> logs = query.orderBy("id", true).limit((long) BATCH_SIZE).query();
            if (logs.isEmpty()) {
                return;
            }
            for (AuthLog authLog : logs) {
                afterId = authLog.getId();
                boolean changed = false;
                if (authLog.getIp() != null && !authLog.getIp().isBlank()) {
                    try {
                        String normalized = NativeIdentifierValidator.normalizeIpLiteral(authLog.getIp());
                        if (!normalized.equals(authLog.getIp())) {
                            authLog.setIp(normalized);
                            changed = true;
                        }
                    } catch (IllegalArgumentException error) {
                        report.invalidLegacyIps++;
                    }
                }
                if (authLog.getHwid() != null) {
                    String normalized = authLog.getHwid().trim();
                    if (!NativeIdentifierValidator.isValidHwid(normalized)) {
                        report.invalidLegacyHwids++;
                    }
                    if (!normalized.equals(authLog.getHwid())) {
                        authLog.setHwid(normalized);
                        changed = true;
                    }
                }
                if (changed) {
                    dao.update(authLog);
                    report.normalizedPendingLogs++;
                }
            }
        }
    }

    private static ListNormalization normalizeIpList(List<String> source) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        int invalid = 0;
        for (String item : source) {
            if (item == null || item.isBlank()) {
                continue;
            }
            try {
                values.add(NativeIdentifierValidator.normalizeIpLiteral(item));
            } catch (IllegalArgumentException error) {
                if (values.add(item.trim())) {
                    invalid++;
                }
            }
        }
        return new ListNormalization(new ArrayList<>(values), invalid);
    }

    private static ListNormalization normalizeHwidList(List<String> source) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        int invalid = 0;
        for (String item : source) {
            if (item == null || item.isBlank()) {
                continue;
            }
            String normalized = item.trim();
            boolean added = values.add(normalized);
            if (added && !NativeIdentifierValidator.isValidHwid(normalized)) {
                invalid++;
            }
        }
        return new ListNormalization(new ArrayList<>(values), invalid);
    }

    private static String replaceMarker(String reason, Map<String, String> replacements) {
        if (reason == null) {
            return null;
        }
        for (Map.Entry<String, String> replacement : replacements.entrySet()) {
            if (reason.startsWith(replacement.getKey())) {
                return replacement.getValue() + reason.substring(replacement.getKey().length());
            }
        }
        return reason;
    }

    private static String ruleMarker(String type, String value) {
        return "[license-ban-rule:" + type + "=" + value + "]";
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private record ListNormalization(List<String> values, int invalidValues) {
    }

    private static final class MutableReport {
        private int normalizedLicenseIpRows;
        private int normalizedLicenseHwidRows;
        private int normalizedBanRecords;
        private int normalizedBanMarkers;
        private int normalizedPendingLogs;
        private int invalidLegacyIps;
        private int invalidLegacyHwids;

        private MigrationReport result(boolean skipped) {
            return new MigrationReport(
                    normalizedLicenseIpRows,
                    normalizedLicenseHwidRows,
                    normalizedBanRecords,
                    normalizedBanMarkers,
                    normalizedPendingLogs,
                    invalidLegacyIps,
                    invalidLegacyHwids,
                    skipped);
        }
    }

    public record MigrationReport(
            int normalizedLicenseIpRows,
            int normalizedLicenseHwidRows,
            int normalizedBanRecords,
            int normalizedBanMarkers,
            int normalizedPendingLogs,
            int invalidLegacyIps,
            int invalidLegacyHwids,
            boolean skipped
    ) {
        private static MigrationReport skippedReport() {
            return new MigrationReport(0, 0, 0, 0, 0, 0, 0, true);
        }

        String summary() {
            return "licenseIpRows=" + normalizedLicenseIpRows
                    + ",licenseHwidRows=" + normalizedLicenseHwidRows
                    + ",banRecords=" + normalizedBanRecords
                    + ",banMarkers=" + normalizedBanMarkers
                    + ",pendingLogs=" + normalizedPendingLogs
                    + ",invalidIps=" + invalidLegacyIps
                    + ",invalidHwids=" + invalidLegacyHwids;
        }
    }
}

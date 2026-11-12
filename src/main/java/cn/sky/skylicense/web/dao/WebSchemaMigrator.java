package cn.sky.skylicense.web.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Transactional, forward-only migrations for the Web SQLite database. */
final class WebSchemaMigrator {
    static final int CURRENT_SCHEMA_VERSION = 9;

    private static final Map<String, Set<String>> REQUIRED_COLUMNS = requiredColumns();

    private WebSchemaMigrator() {
    }

    static void assertSupportedVersion(Connection connection) throws SQLException {
        int version = schemaVersion(connection);
        if (version > CURRENT_SCHEMA_VERSION) {
            throw new SQLException(
                    "Database schema version " + version
                            + " is newer than supported version " + CURRENT_SCHEMA_VERSION);
        }
    }

    static MigrationResult migrate(Connection connection) throws SQLException {
        int originalVersion = schemaVersion(connection);
        int version = originalVersion;
        if (version > CURRENT_SCHEMA_VERSION) {
            throw new SQLException(
                    "Database schema version " + version
                            + " is newer than supported version " + CURRENT_SCHEMA_VERSION);
        }

        boolean originalAutoCommit = connection.getAutoCommit();
        try {
            connection.setAutoCommit(false);
            if (version < 1) {
                migrateToVersion1(connection);
                version = 1;
            }
            if (version < 2) {
                migrateToVersion2(connection);
                version = 2;
            }
            if (version < 3) {
                migrateToVersion3(connection);
                version = 3;
            }
            if (version < 4) {
                migrateToVersion4(connection);
                version = 4;
            }
            if (version < 5) {
                migrateToVersion5(connection);
                version = 5;
            }
            if (version < 6) {
                migrateToVersion6(connection);
                version = 6;
            }
            if (version < 7) {
                migrateToVersion7(connection);
                version = 7;
            }
            if (version < 8) {
                migrateToVersion8(connection);
                version = 8;
            }
            if (version < 9) {
                migrateToVersion9(connection);
                version = 9;
            }
            verifyRequiredColumns(connection);
            setSchemaVersion(connection, version);
            connection.commit();
            return new MigrationResult(
                    originalVersion,
                    version,
                    originalVersion < 7 && version >= 7);
        } catch (SQLException | RuntimeException error) {
            connection.rollback();
            throw error;
        } finally {
            connection.setAutoCommit(originalAutoCommit);
        }
    }

    /**
     * Indicates whether this connection upgraded a pre-audit database. The
     * operation-log service may perform its authenticated trust-on-first-use
     * backfill only for that connection; a later process must fail closed if a
     * checkpoint is missing.
     */
    record MigrationResult(int originalVersion, int currentVersion, boolean auditBackfillRequired) {
    }

    private static void migrateToVersion1(Connection connection) throws SQLException {
        addColumnIfMissing(connection, "license", "expiration_date", "TEXT");
        addColumnIfMissing(
                connection, "license", "max_daily_auth", "INTEGER NOT NULL DEFAULT 0");
        addColumnIfMissing(connection, "license", "last_modified_time", "TEXT");
        addColumnIfMissing(
                connection, "ban_record", "program_id", "INTEGER NOT NULL DEFAULT 0");
        addColumnIfMissing(
                connection, "auth_log", "program_id", "INTEGER NOT NULL DEFAULT 0");
        addColumnIfMissing(
                connection, "auth_log", "user_id", "INTEGER NOT NULL DEFAULT 0");

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "UPDATE auth_log SET program_id = COALESCE((SELECT program_id FROM license "
                            + "WHERE license.id = auth_log.license_id), 0) WHERE program_id = 0");
            statement.executeUpdate(
                    "UPDATE auth_log SET user_id = COALESCE((SELECT user_id FROM license "
                            + "WHERE license.id = auth_log.license_id), 0) WHERE user_id = 0");
        }
    }

    private static void migrateToVersion2(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "CREATE UNIQUE INDEX IF NOT EXISTS program_name_nocase_uidx "
                            + "ON program(name COLLATE NOCASE)");
            statement.executeUpdate(
                    "CREATE UNIQUE INDEX IF NOT EXISTS program_version_identity_uidx "
                            + "ON program_version(program_id, version)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS ban_record_lookup_idx "
                            + "ON ban_record(type, value, status)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS ban_record_program_idx "
                            + "ON ban_record(program_id, status)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS license_program_status_idx "
                            + "ON license(program_id, status)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS auth_log_program_time_idx "
                            + "ON auth_log(program_id, timestamp)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS auth_log_license_result_time_idx "
                            + "ON auth_log(license_id, result, timestamp)");
        }
    }

    private static void migrateToVersion3(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS web_session_user_idx "
                            + "ON web_session(user_id, created_at)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS web_session_expiry_idx "
                            + "ON web_session(expires_at)");
        }
    }

    private static void migrateToVersion4(Connection connection) throws SQLException {
        addColumnIfMissing(
                connection,
                "web_session",
                "csrf_token",
                "TEXT NOT NULL DEFAULT ''");
        try (Statement statement = connection.createStatement()) {
            // Version 3 rows identify signed JWT cookies and cannot be upgraded to
            // independent opaque credentials. Force a clean login after upgrade.
            statement.executeUpdate("DELETE FROM web_session");
        }
    }

    private static void migrateToVersion5(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet collision = statement.executeQuery(
                     "SELECT lower(trim(username)) AS normalized_username, COUNT(*) "
                             + "FROM web_user GROUP BY normalized_username "
                             + "HAVING COUNT(*) > 1 LIMIT 1")) {
            if (collision.next()) {
                throw new SQLException(
                        "Cannot enable case-insensitive username uniqueness because existing accounts collide");
            }
        }
        try (Statement statement = connection.createStatement();
             ResultSet invalid = statement.executeQuery(
                     "SELECT id FROM web_user WHERE length(trim(username)) = 0 LIMIT 1")) {
            if (invalid.next()) {
                throw new SQLException("Cannot normalize an empty existing username");
            }
        }
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "UPDATE web_user SET username = trim(username) WHERE username <> trim(username)");
            statement.executeUpdate(
                    "CREATE UNIQUE INDEX IF NOT EXISTS web_user_username_nocase_uidx "
                            + "ON web_user(username COLLATE NOCASE)");
        }
    }

    private static void migrateToVersion6(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS ban_record_expiration_idx "
                            + "ON ban_record(status, expiration_date)");
        }
    }

    private static void migrateToVersion7(Connection connection) throws SQLException {
        // Existing rows are populated and authenticated by OperationLogService after
        // the schema transaction. Defaults keep this DDL backward compatible while
        // allowing the service to fail closed if backfill cannot be completed.
        addColumnIfMissing(connection, "operation_log", "event_id", "TEXT");
        addColumnIfMissing(
                connection,
                "operation_log",
                "outcome",
                "TEXT NOT NULL DEFAULT 'LEGACY'");
        addColumnIfMissing(
                connection,
                "operation_log",
                "occurred_at_ms",
                "INTEGER NOT NULL DEFAULT 0");
        addColumnIfMissing(connection, "operation_log", "completed_at_ms", "INTEGER");
        addColumnIfMissing(connection, "operation_log", "chain_previous_mac", "TEXT");
        addColumnIfMissing(connection, "operation_log", "chain_mac", "TEXT");
        addColumnIfMissing(connection, "operation_log", "integrity_mac", "TEXT");

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS operation_log_outcome_idx "
                            + "ON operation_log(outcome, occurred_at_ms)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS operation_log_event_idx "
                            + "ON operation_log(event_id)");
        }
    }

    private static void migrateToVersion8(Connection connection) throws SQLException {
        // Primitive id fields in the legacy ORMLite entities do not generate
        // foreign keys. Install explicit guards before the database is exposed
        // to application or native-session writers.
        DatabaseRelationshipIntegrity.install(connection);
    }

    private static void migrateToVersion9(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS web_mfa_challenge (
                      token_digest TEXT PRIMARY KEY NOT NULL,
                      user_id INTEGER NOT NULL,
                      account_reference TEXT NOT NULL,
                      address_reference TEXT NOT NULL,
                      expires_at INTEGER NOT NULL,
                      remaining_attempts INTEGER NOT NULL,
                      created_at INTEGER NOT NULL
                    )
                    """);
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS web_login_attempt (
                      attempt_key TEXT PRIMARY KEY NOT NULL,
                      scope TEXT NOT NULL,
                      failure_count INTEGER NOT NULL,
                      window_started_at INTEGER NOT NULL,
                      locked_until INTEGER NOT NULL,
                      updated_at INTEGER NOT NULL
                    )
                    """);
        }
        addColumnIfMissing(
                connection, "web_user", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0");
        addColumnIfMissing(connection, "web_user", "mfa_secret", "TEXT");
        addColumnIfMissing(connection, "web_user", "mfa_pending_secret", "TEXT");
        addColumnIfMissing(connection, "web_user", "mfa_pending_created_at", "INTEGER");
        addColumnIfMissing(connection, "web_user", "mfa_recovery_hashes", "TEXT");
        addColumnIfMissing(
                connection,
                "web_user",
                "mfa_last_time_step",
                "INTEGER NOT NULL DEFAULT 0");
        addColumnIfMissing(connection, "web_user", "mfa_updated_at", "INTEGER");

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS web_mfa_challenge_user_idx "
                            + "ON web_mfa_challenge(user_id, created_at)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS web_mfa_challenge_expiry_idx "
                            + "ON web_mfa_challenge(expires_at)");
            statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS web_login_attempt_scope_idx "
                            + "ON web_login_attempt(scope, updated_at)");
            try (ResultSet invalid = statement.executeQuery(
                    "SELECT id FROM web_user WHERE mfa_enabled NOT IN (0, 1) "
                            + "OR (mfa_enabled = 1 AND (mfa_secret IS NULL "
                            + "OR length(mfa_secret) = 0 OR mfa_recovery_hashes IS NULL "
                            + "OR length(mfa_recovery_hashes) = 0)) LIMIT 1")) {
                if (invalid.next()) {
                    throw new SQLException(
                            "existing MFA state is malformed for web_user id "
                                    + invalid.getLong(1));
                }
            }
        }
        // The v8 migration installed the legacy relationship guards.  Re-run the
        // idempotent installer so the challenge-to-user guard is present as well.
        DatabaseRelationshipIntegrity.install(connection);
    }

    private static void addColumnIfMissing(
            Connection connection,
            String table,
            String column,
            String declaration
    ) throws SQLException {
        if (columns(connection, table).contains(column)) {
            return;
        }
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "ALTER TABLE \"" + table + "\" ADD COLUMN \"" + column + "\" "
                            + declaration);
        }
    }

    private static void verifyRequiredColumns(Connection connection) throws SQLException {
        for (Map.Entry<String, Set<String>> entry : REQUIRED_COLUMNS.entrySet()) {
            Set<String> actual = columns(connection, entry.getKey());
            if (!actual.containsAll(entry.getValue())) {
                Set<String> missing = new LinkedHashSet<>(entry.getValue());
                missing.removeAll(actual);
                throw new SQLException(
                        "Database table " + entry.getKey() + " is missing columns " + missing);
            }
        }
    }

    private static Set<String> columns(Connection connection, String table) throws SQLException {
        Set<String> columns = new LinkedHashSet<>();
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("PRAGMA table_info(\"" + table + "\")")) {
            while (result.next()) {
                columns.add(result.getString("name"));
            }
        }
        return columns;
    }

    private static int schemaVersion(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("PRAGMA user_version")) {
            if (!result.next()) {
                throw new SQLException("Unable to read SQLite schema version");
            }
            return result.getInt(1);
        }
    }

    private static void setSchemaVersion(Connection connection, int version) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA user_version = " + version);
        }
    }

    private static Map<String, Set<String>> requiredColumns() {
        Map<String, Set<String>> columns = new LinkedHashMap<>();
        columns.put("web_user", Set.of(
                "id", "username", "password", "role", "max_programs", "status",
                "create_time", "last_login_time", "email", "mfa_enabled", "mfa_secret",
                "mfa_pending_secret", "mfa_pending_created_at", "mfa_recovery_hashes",
                "mfa_last_time_step", "mfa_updated_at"));
        columns.put("program", Set.of(
                "id", "user_id", "name", "description", "status", "create_time"));
        columns.put("program_version", Set.of(
                "id", "program_id", "version", "file_name", "file_path", "entry_class",
                "entry_point", "upload_time", "release_notes"));
        columns.put("license", Set.of(
                "id", "code", "program_id", "user_id", "qq", "bindable_ips",
                "bindable_hwids", "status", "ips", "hwids", "create_time",
                "last_auth_time", "ban_reason", "notes", "expiration_date",
                "max_daily_auth", "last_modified_time"));
        columns.put("auth_log", Set.of(
                "id", "license_id", "code", "ip", "hwid", "result", "timestamp",
                "program_id", "user_id"));
        columns.put("operation_log", Set.of(
                "id", "user_id", "username", "action", "target", "detail", "ip",
                "timestamp", "event_id", "outcome", "occurred_at_ms", "completed_at_ms",
                "chain_previous_mac", "chain_mac", "integrity_mac"));
        columns.put("ban_record", Set.of(
                "id", "type", "value", "reason", "operator_id", "program_id",
                "create_time", "expiration_date", "status"));
        columns.put("system_metadata", Set.of("meta_key", "meta_value"));
        columns.put("web_session", Set.of(
                "token_digest", "user_id", "csrf_token", "expires_at", "created_at"));
        columns.put("web_mfa_challenge", Set.of(
                "token_digest", "user_id", "account_reference", "address_reference",
                "expires_at", "remaining_attempts", "created_at"));
        columns.put("web_login_attempt", Set.of(
                "attempt_key", "scope", "failure_count", "window_started_at",
                "locked_until", "updated_at"));
        columns.put("operation_log_state", Set.of(
                "singleton_id", "anchor_id", "anchor_mac", "head_id", "head_mac",
                "row_count", "state_mac", "updated_at_ms"));
        return Map.copyOf(columns);
    }
}

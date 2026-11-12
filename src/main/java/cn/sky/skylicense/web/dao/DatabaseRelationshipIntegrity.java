package cn.sky.skylicense.web.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Database-level relationship invariants for the Web license store.
 *
 * <p>ORMLite does not add foreign-key constraints for the primitive id fields
 * used by the legacy schema.  These triggers provide the write-time boundary,
 * while the bounded queries below detect corruption or an out-of-band edit at
 * startup and during readiness checks.  Historical auth rows are intentionally
 * retained after a license is deleted, so an auth row whose license no longer
 * exists is allowed; rows that still have a parent must remain consistent.</p>
 */
public final class DatabaseRelationshipIntegrity {

    private static final Map<String, TriggerDefinition> TRIGGERS = triggerDefinitions();

    private DatabaseRelationshipIntegrity() {
    }

    /** Installs the idempotent write-time guards as part of the schema migration. */
    static void install(Connection connection) throws SQLException {
        boolean mfaTablesExist = tableExists(connection, "web_mfa_challenge");
        try (Statement statement = connection.createStatement()) {
            for (TriggerDefinition definition : TRIGGERS.values()) {
                if (definition.requiresMfaTables() && !mfaTablesExist) {
                    continue;
                }
                statement.execute(definition.sql());
            }
            statement.execute(
                    "CREATE INDEX IF NOT EXISTS ban_record_operator_idx "
                            + "ON ban_record(operator_id, status)");
        }
    }

    /** Verifies both trigger definitions and the currently stored relationships. */
    public static void verify(Connection connection) throws SQLException {
        if (connection == null) {
            throw new SQLException("database connection is required for relationship verification");
        }
        verifyTriggers(connection);
        verifyData(connection);
    }

    /** Verifies only stored relationships, for read-only preflight of older schemas. */
    public static void verifyData(Connection connection) throws SQLException {
        check(connection, "program.user_id", """
                SELECT p.id
                FROM program p
                WHERE p.user_id <= 0
                   OR NOT EXISTS (SELECT 1 FROM web_user u WHERE u.id = p.user_id)
                LIMIT 1
                """);
        check(connection, "program_version.program_id", """
                SELECT v.id
                FROM program_version v
                WHERE v.program_id <= 0
                   OR NOT EXISTS (SELECT 1 FROM program p WHERE p.id = v.program_id)
                LIMIT 1
                """);
        check(connection, "license.owner", """
                SELECT l.id
                FROM license l
                LEFT JOIN program p ON p.id = l.program_id
                LEFT JOIN web_user u ON u.id = l.user_id
                WHERE l.program_id <= 0
                   OR l.user_id <= 0
                   OR p.id IS NULL
                   OR u.id IS NULL
                   OR p.user_id <> l.user_id
                LIMIT 1
                """);
        check(connection, "auth_log.context", """
                SELECT a.id
                FROM auth_log a
                LEFT JOIN license l ON l.id = a.license_id
                WHERE a.license_id < 0
                   OR a.program_id < 0
                   OR a.user_id < 0
                   OR (a.license_id = 0 AND (a.program_id <> 0 OR a.user_id <> 0))
                   OR (l.id IS NOT NULL AND (
                         (a.program_id <> 0 AND a.program_id <> l.program_id)
                      OR (a.user_id <> 0 AND a.user_id <> l.user_id)
                      OR (a.code IS NOT NULL AND a.code <> l.code)
                   ))
                LIMIT 1
                """);
        check(connection, "ban_record references", """
                SELECT b.id
                FROM ban_record b
                WHERE b.program_id < 0
                   OR b.operator_id < 0
                   OR (b.program_id > 0 AND NOT EXISTS (
                         SELECT 1 FROM program p WHERE p.id = b.program_id))
                   OR (b.operator_id > 0 AND NOT EXISTS (
                         SELECT 1 FROM web_user u WHERE u.id = b.operator_id))
                LIMIT 1
                """);
        check(connection, "web_session.user_id", """
                SELECT s.user_id
                FROM web_session s
                WHERE s.user_id <= 0
                   OR NOT EXISTS (SELECT 1 FROM web_user u WHERE u.id = s.user_id)
                LIMIT 1
                """);
        if (tableExists(connection, "web_mfa_challenge")) {
            check(connection, "web_mfa_challenge.user_id", """
                    SELECT c.user_id
                    FROM web_mfa_challenge c
                    WHERE c.user_id <= 0
                       OR NOT EXISTS (SELECT 1 FROM web_user u WHERE u.id = c.user_id)
                    LIMIT 1
                    """);
        }
    }

    private static void verifyTriggers(Connection connection) throws SQLException {
        boolean mfaTablesExist = tableExists(connection, "web_mfa_challenge");
        for (TriggerDefinition definition : TRIGGERS.values()) {
            if (definition.requiresMfaTables() && !mfaTablesExist) {
                continue;
            }
            String actual;
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?")) {
                statement.setString(1, definition.name());
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        throw new SQLException(
                                "database relationship trigger is missing: " + definition.name());
                    }
                    actual = result.getString(1);
                }
            }
            if (!canonicalSql(actual).equals(canonicalSql(definition.sql()))) {
                throw new SQLException(
                        "database relationship trigger was modified: " + definition.name());
            }
        }
    }

    private static void check(Connection connection, String relation, String sql)
            throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            if (result.next()) {
                throw new SQLException(
                        "database relationship integrity failure: " + relation
                                + " (row=" + result.getString(1) + ")");
            }
        }
    }

    private static boolean tableExists(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")) {
            statement.setString(1, table);
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private static String canonicalSql(String sql) {
        if (sql == null) {
            return "";
        }
        return sql.toLowerCase(Locale.ROOT)
                .replace("if not exists", "")
                .replaceAll("[\\s;\\\"`\\[\\]]+", "");
    }

    private static Map<String, TriggerDefinition> triggerDefinitions() {
        Map<String, TriggerDefinition> definitions = new LinkedHashMap<>();
        add(definitions, "sky_rel_program_user_insert", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_program_user_insert
                BEFORE INSERT ON program
                WHEN NEW.user_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM web_user WHERE id = NEW.user_id)
                BEGIN
                  SELECT RAISE(ABORT, 'program.user_id does not reference web_user');
                END
                """);
        add(definitions, "sky_rel_program_user_update", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_program_user_update
                BEFORE UPDATE OF user_id ON program
                WHEN NEW.user_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM web_user WHERE id = NEW.user_id)
                  OR EXISTS (SELECT 1 FROM license
                             WHERE program_id = OLD.id AND user_id <> NEW.user_id)
                BEGIN
                  SELECT RAISE(ABORT, 'program owner relationship is invalid');
                END
                """);
        add(definitions, "sky_rel_program_version_insert", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_program_version_insert
                BEFORE INSERT ON program_version
                WHEN NEW.program_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM program WHERE id = NEW.program_id)
                BEGIN
                  SELECT RAISE(ABORT, 'program_version.program_id does not reference program');
                END
                """);
        add(definitions, "sky_rel_program_version_update", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_program_version_update
                BEFORE UPDATE OF program_id ON program_version
                WHEN NEW.program_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM program WHERE id = NEW.program_id)
                BEGIN
                  SELECT RAISE(ABORT, 'program_version.program_id does not reference program');
                END
                """);
        add(definitions, "sky_rel_license_insert", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_license_insert
                BEFORE INSERT ON license
                WHEN NEW.program_id <= 0
                  OR NEW.user_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM program WHERE id = NEW.program_id)
                  OR NOT EXISTS (SELECT 1 FROM web_user WHERE id = NEW.user_id)
                  OR EXISTS (SELECT 1 FROM program
                             WHERE id = NEW.program_id AND user_id <> NEW.user_id)
                BEGIN
                  SELECT RAISE(ABORT, 'license owner relationship is invalid');
                END
                """);
        add(definitions, "sky_rel_license_update", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_license_update
                BEFORE UPDATE OF program_id, user_id ON license
                WHEN NEW.program_id <= 0
                  OR NEW.user_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM program WHERE id = NEW.program_id)
                  OR NOT EXISTS (SELECT 1 FROM web_user WHERE id = NEW.user_id)
                  OR EXISTS (SELECT 1 FROM program
                             WHERE id = NEW.program_id AND user_id <> NEW.user_id)
                BEGIN
                  SELECT RAISE(ABORT, 'license owner relationship is invalid');
                END
                """);
        add(definitions, "sky_rel_auth_log_insert", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_auth_log_insert
                BEFORE INSERT ON auth_log
                WHEN NEW.license_id < 0
                  OR NEW.program_id < 0
                  OR NEW.user_id < 0
                  OR (NEW.license_id = 0 AND (NEW.program_id <> 0 OR NEW.user_id <> 0))
                  OR (NEW.license_id > 0 AND NOT EXISTS (
                         SELECT 1 FROM license WHERE id = NEW.license_id))
                  OR EXISTS (SELECT 1 FROM license l
                             WHERE l.id = NEW.license_id
                               AND ((NEW.program_id <> 0 AND NEW.program_id <> l.program_id)
                                 OR (NEW.user_id <> 0 AND NEW.user_id <> l.user_id)
                                 OR (NEW.code IS NOT NULL AND NEW.code <> l.code)))
                BEGIN
                  SELECT RAISE(ABORT, 'auth_log relationship is invalid');
                END
                """);
        add(definitions, "sky_rel_auth_log_update", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_auth_log_update
                BEFORE UPDATE OF license_id, program_id, user_id, code ON auth_log
                WHEN (NEW.license_id <> OLD.license_id
                   OR NEW.program_id <> OLD.program_id
                   OR NEW.user_id <> OLD.user_id
                   OR COALESCE(NEW.code, '') <> COALESCE(OLD.code, ''))
                 AND (NEW.license_id < 0
                   OR NEW.program_id < 0
                   OR NEW.user_id < 0
                   OR (NEW.license_id = 0 AND (NEW.program_id <> 0 OR NEW.user_id <> 0))
                   OR (NEW.license_id > 0 AND NOT EXISTS (
                         SELECT 1 FROM license WHERE id = NEW.license_id))
                   OR EXISTS (SELECT 1 FROM license l
                              WHERE l.id = NEW.license_id
                                AND ((NEW.program_id <> 0 AND NEW.program_id <> l.program_id)
                                  OR (NEW.user_id <> 0 AND NEW.user_id <> l.user_id)
                                  OR (NEW.code IS NOT NULL AND NEW.code <> l.code))))
                BEGIN
                  SELECT RAISE(ABORT, 'auth_log relationship is invalid');
                END
                """);
        add(definitions, "sky_rel_ban_record_insert", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_ban_record_insert
                BEFORE INSERT ON ban_record
                WHEN NEW.program_id < 0
                  OR NEW.operator_id < 0
                  OR (NEW.program_id > 0 AND NOT EXISTS (
                         SELECT 1 FROM program WHERE id = NEW.program_id))
                  OR (NEW.operator_id > 0 AND NOT EXISTS (
                         SELECT 1 FROM web_user WHERE id = NEW.operator_id))
                BEGIN
                  SELECT RAISE(ABORT, 'ban_record relationship is invalid');
                END
                """);
        add(definitions, "sky_rel_ban_record_update", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_ban_record_update
                BEFORE UPDATE OF program_id, operator_id ON ban_record
                WHEN NEW.program_id < 0
                  OR NEW.operator_id < 0
                  OR (NEW.program_id > 0 AND NOT EXISTS (
                         SELECT 1 FROM program WHERE id = NEW.program_id))
                  OR (NEW.operator_id > 0 AND NOT EXISTS (
                         SELECT 1 FROM web_user WHERE id = NEW.operator_id))
                BEGIN
                  SELECT RAISE(ABORT, 'ban_record relationship is invalid');
                END
                """);
        add(definitions, "sky_rel_web_session_insert", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_web_session_insert
                BEFORE INSERT ON web_session
                WHEN NEW.user_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM web_user WHERE id = NEW.user_id)
                BEGIN
                  SELECT RAISE(ABORT, 'web_session.user_id does not reference web_user');
                END
                """);
        add(definitions, "sky_rel_web_session_update", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_web_session_update
                BEFORE UPDATE OF user_id ON web_session
                WHEN NEW.user_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM web_user WHERE id = NEW.user_id)
                BEGIN
                  SELECT RAISE(ABORT, 'web_session.user_id does not reference web_user');
                END
                """);
        addMfa(definitions, "sky_rel_web_mfa_challenge_insert", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_web_mfa_challenge_insert
                BEFORE INSERT ON web_mfa_challenge
                WHEN NEW.user_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM web_user WHERE id = NEW.user_id)
                BEGIN
                  SELECT RAISE(ABORT, 'web_mfa_challenge.user_id does not reference web_user');
                END
                """);
        addMfa(definitions, "sky_rel_web_mfa_challenge_update", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_web_mfa_challenge_update
                BEFORE UPDATE OF user_id ON web_mfa_challenge
                WHEN NEW.user_id <= 0
                  OR NOT EXISTS (SELECT 1 FROM web_user WHERE id = NEW.user_id)
                BEGIN
                  SELECT RAISE(ABORT, 'web_mfa_challenge.user_id does not reference web_user');
                END
                """);
        addMfa(definitions, "sky_rel_restrict_user_mfa_delete", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_restrict_user_mfa_delete
                BEFORE DELETE ON web_user
                WHEN EXISTS (SELECT 1 FROM web_mfa_challenge WHERE user_id = OLD.id)
                BEGIN
                  SELECT RAISE(ABORT, 'web_user has dependent MFA challenges');
                END
                """);
        add(definitions, "sky_rel_restrict_user_delete", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_restrict_user_delete
                BEFORE DELETE ON web_user
                WHEN EXISTS (SELECT 1 FROM program WHERE user_id = OLD.id)
                  OR EXISTS (SELECT 1 FROM license WHERE user_id = OLD.id)
                  OR EXISTS (SELECT 1 FROM auth_log WHERE user_id = OLD.id)
                  OR EXISTS (SELECT 1 FROM ban_record WHERE operator_id = OLD.id)
                  OR EXISTS (SELECT 1 FROM web_session WHERE user_id = OLD.id)
                BEGIN
                  SELECT RAISE(ABORT, 'web_user has dependent records');
                END
                """);
        add(definitions, "sky_rel_restrict_program_delete", """
                CREATE TRIGGER IF NOT EXISTS sky_rel_restrict_program_delete
                BEFORE DELETE ON program
                WHEN EXISTS (SELECT 1 FROM program_version WHERE program_id = OLD.id)
                  OR EXISTS (SELECT 1 FROM license WHERE program_id = OLD.id)
                  OR EXISTS (SELECT 1 FROM auth_log WHERE program_id = OLD.id)
                  OR EXISTS (SELECT 1 FROM ban_record WHERE program_id = OLD.id)
                BEGIN
                  SELECT RAISE(ABORT, 'program has dependent records');
                END
                """);

        return Map.copyOf(definitions);
    }

    private static void add(Map<String, TriggerDefinition> definitions, String name, String sql) {
        definitions.put(name, new TriggerDefinition(name, sql, false));
    }

    private static void addMfa(
            Map<String, TriggerDefinition> definitions,
            String name,
            String sql
    ) {
        definitions.put(name, new TriggerDefinition(name, sql, true));
    }

    private record TriggerDefinition(String name, String sql, boolean requiresMfaTables) {
    }
}

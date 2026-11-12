package cn.sky.skylicense.web.dao;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebDataAccessorTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void newDatabaseUsesHardenedConnectionSettingsAndCurrentSchema() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("new.db").toString());
            assertTrue(accessor.isOpen());
            assertTrue(accessor.isHealthy());
            try (Connection connection = accessor.getDataSource().getConnection()) {
                assertEquals("wal", queryString(connection, "PRAGMA journal_mode"));
                assertTrue(queryInt(connection, "PRAGMA busy_timeout") >= 10_000);
                assertEquals(1, queryInt(connection, "PRAGMA foreign_keys"));
                assertEquals(
                        WebSchemaMigrator.CURRENT_SCHEMA_VERSION,
                        queryInt(connection, "PRAGMA user_version"));
                assertEquals("ok", queryString(connection, "PRAGMA quick_check"));
                assertTrue(columns(connection, "web_session").containsAll(Set.of(
                        "token_digest", "user_id", "csrf_token", "expires_at", "created_at")));
                assertEquals(1, queryInt(connection,
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' "
                                + "AND name = 'web_user_username_nocase_uidx'"));
                assertEquals(1, queryInt(connection,
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' "
                                + "AND name = 'ban_record_expiration_idx'"));
            }
        } finally {
            accessor.close();
            assertFalse(accessor.isOpen());
        }
    }

    @Test
    void relationshipTriggersRejectNewOrphanAndMismatchedRows() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("relationship-guards.db").toString());
            long userId;
            long programId;
            long licenseId;
            try (Connection connection = accessor.getDataSource().getConnection();
                 Statement statement = connection.createStatement()) {
                statement.executeUpdate(
                        "INSERT INTO web_user(username, password, role, max_programs, status) "
                                + "VALUES('owner', 'hash', 'USER', 5, 1)");
                try (ResultSet result = statement.executeQuery("SELECT last_insert_rowid()")) {
                    assertTrue(result.next());
                    userId = result.getLong(1);
                }
                statement.executeUpdate(
                        "INSERT INTO program(user_id, name, status) VALUES(" + userId
                                + ", 'Product', 1)");
                try (ResultSet result = statement.executeQuery("SELECT last_insert_rowid()")) {
                    assertTrue(result.next());
                    programId = result.getLong(1);
                }

                assertThrows(SQLException.class, () -> statement.executeUpdate(
                        "INSERT INTO program(user_id, name, status) VALUES(999999, 'Orphan', 1)"));

                statement.executeUpdate(
                        "INSERT INTO license(code, program_id, user_id, status) VALUES('CODE', "
                                + programId + ", " + userId + ", 1)");
                try (ResultSet result = statement.executeQuery("SELECT last_insert_rowid()")) {
                    assertTrue(result.next());
                    licenseId = result.getLong(1);
                }

                // Native failures for an unknown code intentionally use the 0/0 sentinel.
                statement.executeUpdate(
                        "INSERT INTO auth_log(license_id, code, result, program_id, user_id) "
                                + "VALUES(0, 'UNKNOWN', 'FAILED', 0, 0)");
                assertThrows(SQLException.class, () -> statement.executeUpdate(
                        "INSERT INTO auth_log(license_id, code, result, program_id, user_id) "
                                + "VALUES(" + licenseId + ", 'CODE', 'OK', 999, " + userId + ")"));

                assertThrows(SQLException.class, () -> statement.executeUpdate(
                        "DELETE FROM web_user WHERE id = " + userId));
            }
            assertTrue(accessor.isHealthy());
        } finally {
            accessor.close();
        }
    }

    @Test
    void readinessFailsWhenARequiredRelationshipTriggerIsRemoved() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("missing-relationship-trigger.db").toString());
            try (Connection connection = accessor.getDataSource().getConnection();
                 Statement statement = connection.createStatement()) {
                statement.execute("DROP TRIGGER sky_rel_program_user_insert");
            }
            assertFalse(accessor.isHealthy());
            assertThrows(SQLException.class, accessor::assertRelationshipIntegrity);
        } finally {
            accessor.close();
        }
    }

    @Test
    void versionThreeJwtSessionRowsAreClearedDuringOpaqueSessionMigration() throws Exception {
        Path database = temporaryDirectory.resolve("jwt-session-migration.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE web_session ("
                    + "token_digest VARCHAR(43) PRIMARY KEY, user_id INTEGER NOT NULL, "
                    + "expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)");
            statement.executeUpdate(
                    "INSERT INTO web_session(token_digest, user_id, expires_at, created_at) "
                            + "VALUES('" + "D".repeat(43) + "', 1, "
                            + (System.currentTimeMillis() + 3_600_000L) + ", "
                            + System.currentTimeMillis() + ")");
            statement.execute("PRAGMA user_version = 3");
        }

        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(database.toString());
            try (Connection connection = accessor.getDataSource().getConnection()) {
                assertEquals(
                        WebSchemaMigrator.CURRENT_SCHEMA_VERSION,
                        queryInt(connection, "PRAGMA user_version"));
                assertTrue(columns(connection, "web_session").contains("csrf_token"));
                assertEquals(0, queryInt(connection, "SELECT COUNT(*) FROM web_session"));
            }
        } finally {
            accessor.close();
        }
    }

    @Test
    void versionFourUsernamesAreTrimmedAndBecomeCaseInsensitiveUnique() throws Exception {
        Path database = temporaryDirectory.resolve("username-migration.db");
        WebDataAccessor initial = new WebDataAccessor();
        initial.connect(database.toString());
        initial.close();
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("DROP INDEX web_user_username_nocase_uidx");
            statement.executeUpdate(
                    "INSERT INTO web_user(username, password, role, max_programs, status) "
                            + "VALUES('  MixedCase  ', 'hash', 'USER', 5, 1)");
            statement.execute("PRAGMA user_version = 4");
        }

        WebDataAccessor migrated = new WebDataAccessor();
        try {
            migrated.connect(database.toString());
            try (Connection connection = migrated.getDataSource().getConnection()) {
                assertEquals("MixedCase", queryString(
                        connection, "SELECT username FROM web_user"));
                assertThrows(SQLException.class, () -> {
                    try (Statement statement = connection.createStatement()) {
                        statement.executeUpdate(
                                "INSERT INTO web_user(username, password, role) "
                                        + "VALUES('mixedcase', 'hash', 'USER')");
                    }
                });
            }
        } finally {
            migrated.close();
        }
    }

    @Test
    void versionFiveMigrationRollsBackWhenLegacyUsernamesCollide() throws Exception {
        Path database = temporaryDirectory.resolve("username-collision.db");
        WebDataAccessor initial = new WebDataAccessor();
        initial.connect(database.toString());
        initial.close();
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("DROP INDEX web_user_username_nocase_uidx");
            statement.executeUpdate(
                    "INSERT INTO web_user(username, password, role) "
                            + "VALUES('Alice', 'hash', 'USER')");
            statement.executeUpdate(
                    "INSERT INTO web_user(username, password, role) "
                            + "VALUES('alice', 'hash', 'USER')");
            statement.execute("PRAGMA user_version = 4");
        }

        WebDataAccessor migrated = new WebDataAccessor();
        try {
            SQLException error = assertThrows(
                    SQLException.class, () -> migrated.connect(database.toString()));
            assertTrue(error.getMessage().contains("case-insensitive username uniqueness"));
            try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database)) {
                assertEquals(4, queryInt(connection, "PRAGMA user_version"));
                assertEquals(0, queryInt(connection,
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' "
                                + "AND name = 'web_user_username_nocase_uidx'"));
                assertEquals(2, queryInt(connection, "SELECT COUNT(*) FROM web_user"));
            }
        } finally {
            migrated.close();
        }
    }

    @Test
    void versionZeroDatabaseIsMigratedAndAuthLogOwnershipIsBackfilled() throws Exception {
        Path database = temporaryDirectory.resolve("legacy-web.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE web_user ("
                    + "id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, "
                    + "role TEXT NOT NULL, max_programs INTEGER, status INTEGER, "
                    + "create_time TEXT, last_login_time TEXT, email TEXT)");
            statement.executeUpdate("CREATE TABLE program ("
                    + "id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL, "
                    + "description TEXT, status INTEGER, create_time TEXT)");
            statement.executeUpdate(
                    "INSERT INTO web_user(id, username, password, role, max_programs, status) "
                            + "VALUES(41, 'legacy-owner', 'hash', 'USER', 5, 1)");
            statement.executeUpdate(
                    "INSERT INTO program(id, user_id, name, status) "
                            + "VALUES(31, 41, 'LegacyProgram', 1)");
            statement.executeUpdate("CREATE TABLE license ("
                    + "id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, "
                    + "program_id INTEGER NOT NULL, user_id INTEGER NOT NULL, qq TEXT, "
                    + "bindable_ips INTEGER, bindable_hwids INTEGER, status INTEGER, "
                    + "ips TEXT, hwids TEXT, create_time TEXT, last_auth_time TEXT, "
                    + "ban_reason TEXT, notes TEXT)");
            statement.executeUpdate("CREATE TABLE auth_log ("
                    + "id INTEGER PRIMARY KEY, license_id INTEGER, code TEXT, ip TEXT, "
                    + "hwid TEXT, result TEXT, timestamp TEXT)");
            statement.executeUpdate("CREATE TABLE ban_record ("
                    + "id INTEGER PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL, "
                    + "reason TEXT, operator_id INTEGER, create_time TEXT, "
                    + "expiration_date TEXT, status INTEGER)");
            statement.executeUpdate(
                    "INSERT INTO license(id, code, program_id, user_id, status) "
                            + "VALUES(7, 'LEGACY', 31, 41, 1)");
            statement.executeUpdate(
                    "INSERT INTO auth_log(id, license_id, code, result) "
                            + "VALUES(11, 7, 'LEGACY', 'OK')");
        }

        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(database.toString());
            try (Connection connection = accessor.getDataSource().getConnection()) {
                assertTrue(columns(connection, "license").containsAll(Set.of(
                        "expiration_date", "max_daily_auth", "last_modified_time")));
                assertTrue(columns(connection, "ban_record").contains("program_id"));
                assertTrue(columns(connection, "auth_log").containsAll(Set.of(
                        "program_id", "user_id")));
                assertEquals(31, queryInt(
                        connection, "SELECT program_id FROM auth_log WHERE id = 11"));
                assertEquals(41, queryInt(
                        connection, "SELECT user_id FROM auth_log WHERE id = 11"));
                assertEquals(0, queryInt(
                        connection, "SELECT max_daily_auth FROM license WHERE id = 7"));
                assertEquals(
                        WebSchemaMigrator.CURRENT_SCHEMA_VERSION,
                        queryInt(connection, "PRAGMA user_version"));
            }
        } finally {
            accessor.close();
        }
    }

    @Test
    void databaseFromANewerServerIsRejectedBeforeSchemaChanges() throws Exception {
        Path database = temporaryDirectory.resolve("future.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA user_version = 999");
        }

        WebDataAccessor accessor = new WebDataAccessor();
        try {
            SQLException error = assertThrows(
                    SQLException.class,
                    () -> accessor.connect(database.toString()));
            assertTrue(error.getMessage().contains("newer than supported"));
            try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database)) {
                assertTrue(columns(connection, "web_user").isEmpty());
                assertEquals(999, queryInt(connection, "PRAGMA user_version"));
            }
        } finally {
            accessor.close();
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

    private static int queryInt(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            assertTrue(result.next());
            return result.getInt(1);
        }
    }

    private static String queryString(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            assertTrue(result.next());
            return result.getString(1);
        }
    }
}

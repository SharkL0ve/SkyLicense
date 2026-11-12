package cn.sky.skylicense.security;

import cn.sky.skylicense.web.dao.WebDataAccessor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeploymentPreflightTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void readOnlyDatabasePreflightChecksHealthSchemaAndAdministrator() throws Exception {
        Path database = temporaryDirectory.resolve("healthy.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE web_user (role TEXT NOT NULL, status INTEGER NOT NULL)");
            statement.execute("INSERT INTO web_user(role, status) VALUES ('ADMIN', 1)");
            statement.execute("PRAGMA user_version=6");
        }
        makeOwnerOnly(database);

        DeploymentPreflight.DatabaseSummary summary =
                DeploymentPreflight.validateDatabase(database);
        assertTrue(summary.exists());
        assertEquals(6, summary.schemaVersion());
        assertTrue(summary.activeAdministratorExists());
    }

    @Test
    void absentDatabaseIsReportedWithoutBeingCreated() throws Exception {
        Path database = temporaryDirectory.resolve("missing.db");
        DeploymentPreflight.DatabaseSummary summary =
                DeploymentPreflight.validateDatabase(database);
        assertFalse(summary.exists());
        assertFalse(Files.exists(database));
    }

    @Test
    void emptySqliteSidecarsRemainValidAcrossPreflightRuns() throws Exception {
        Path database = temporaryDirectory.resolve("checkpointed.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE web_user (role TEXT NOT NULL, status INTEGER NOT NULL)");
            statement.execute("INSERT INTO web_user(role, status) VALUES ('ADMIN', 1)");
            statement.execute("PRAGMA user_version=6");
        }
        makeOwnerOnly(database);

        Path wal = Path.of(database + "-wal");
        Path sharedMemory = Path.of(database + "-shm");
        Files.write(wal, new byte[0]);
        Files.write(sharedMemory, new byte[0]);
        makeOwnerOnly(wal);
        makeOwnerOnly(sharedMemory);

        assertDoesNotThrow(() -> DeploymentPreflight.validateDatabase(database));
        assertDoesNotThrow(() -> DeploymentPreflight.validateDatabase(database));
    }

    @Test
    void walPreflightHardensSidecarsCreatedByReadOnlyConnections() throws Exception {
        Path database = temporaryDirectory.resolve("wal-checkpointed.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode=WAL");
            statement.execute("CREATE TABLE web_user (role TEXT NOT NULL, status INTEGER NOT NULL)");
            statement.execute("INSERT INTO web_user(role, status) VALUES ('ADMIN', 1)");
            statement.execute("PRAGMA user_version=6");
            statement.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        }
        makeOwnerOnly(database);

        assertDoesNotThrow(() -> DeploymentPreflight.validateDatabase(database));
        for (String suffix : new String[]{"-wal", "-shm"}) {
            Path sidecar = Path.of(database + suffix);
            if (Files.exists(sidecar, LinkOption.NOFOLLOW_LINKS)) {
                assertDoesNotThrow(
                        () -> SecureFiles.requireOwnerOnly(sidecar, false, "database sidecar"));
            }
        }
        assertDoesNotThrow(() -> DeploymentPreflight.validateDatabase(database));
    }

    @Test
    void newerOrCorruptDatabaseFailsPreflight() throws Exception {
        Path newer = temporaryDirectory.resolve("newer.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + newer);
             Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA user_version=999");
        }
        makeOwnerOnly(newer);
        assertThrows(
                IllegalStateException.class,
                () -> DeploymentPreflight.validateDatabase(newer));

        Path corrupt = temporaryDirectory.resolve("corrupt.db");
        Files.write(corrupt, new byte[]{1, 2, 3, 4});
        makeOwnerOnly(corrupt);
        assertThrows(Exception.class, () -> DeploymentPreflight.validateDatabase(corrupt));
    }

    @Test
    void currentSchemaWithoutRelationshipTriggerFailsPreflight() throws Exception {
        Path database = temporaryDirectory.resolve("missing-trigger.db");
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(database.toString());
        accessor.close();

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("DROP TRIGGER sky_rel_program_user_insert");
        }
        makeOwnerOnly(database);

        Exception error = assertThrows(
                Exception.class,
                () -> DeploymentPreflight.validateDatabase(database));
        assertTrue(error.getMessage().contains("relationship trigger"));
    }

    @Test
    void currentSchemaWithOrphanRelationshipFailsPreflight() throws Exception {
        Path database = temporaryDirectory.resolve("orphan-relationship.db");
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(database.toString());
        accessor.close();

        String triggerSql;
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            try (var result = statement.executeQuery(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' "
                            + "AND name='sky_rel_program_user_insert'")) {
                assertTrue(result.next());
                triggerSql = result.getString(1);
            }
            statement.execute("DROP TRIGGER sky_rel_program_user_insert");
            statement.executeUpdate(
                    "INSERT INTO program(user_id, name, status) VALUES(999999, 'orphan', 1)");
            statement.execute(triggerSql);
        }
        makeOwnerOnly(database);

        Exception error = assertThrows(
                Exception.class,
                () -> DeploymentPreflight.validateDatabase(database));
        assertTrue(error.getMessage().contains("program.user_id"));
    }

    @Test
    void privateFileHardeningPassesOnTheActiveFilesystemAndRejectsPosixGroupRead()
            throws Exception {
        Path privateFile = temporaryDirectory.resolve("private.bin");
        Files.writeString(privateFile, "private");
        SecureFiles.makePrivateReadWrite(privateFile);
        assertDoesNotThrow(
                () -> SecureFiles.requireOwnerOnly(privateFile, false, "private fixture"));

        PosixFileAttributeView posix = Files.getFileAttributeView(
                privateFile, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            Files.setPosixFilePermissions(privateFile, java.util.EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ));
            assertThrows(
                    java.io.IOException.class,
                    () -> SecureFiles.requireOwnerOnly(privateFile, false, "private fixture"));
        }
    }

    private static void makeOwnerOnly(Path path) throws Exception {
        SecureFiles.makePrivateReadWrite(path);
    }
}

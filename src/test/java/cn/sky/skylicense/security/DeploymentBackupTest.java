package cn.sky.skylicense.security;

import cn.sky.skylicense.config.Storage;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.ProgramVersion;
import cn.sky.skylicense.web.entity.WebUser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeploymentBackupTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void createsVerifiesAndExtractsAnAuthenticatedOfflineSnapshot() throws Exception {
        Fixture fixture = fixture();
        Path archive = fixture.backupDirectory().resolve("deployment.skybackup");

        DeploymentBackup.Summary created = DeploymentBackup.create(
                fixture.liveDirectory(),
                fixture.storage(),
                fixture.preflight(),
                archive,
                fixture.authenticationKey());
        assertEquals(4, created.fileCount());
        assertTrue(created.tlsCertificateIncluded());
        assertFalse(created.tlsPrivateKeyIncluded());

        DeploymentBackup.VerifiedArchive verified =
                DeploymentBackup.verify(archive, fixture.authenticationKey());
        assertEquals(created.fileCount(), verified.summary().fileCount());
        assertEquals(created.databaseSchemaVersion(),
                verified.summary().databaseSchemaVersion());

        Path restored = temporaryDirectory.resolve("restored");
        DeploymentBackup.extract(verified, restored);
        assertEquals(
                "{\"fixture\":true}",
                Files.readString(restored.resolve("config.json"), StandardCharsets.UTF_8));
        assertEquals(
                "protected",
                Files.readString(
                        restored.resolve("resources/program/version.jar"),
                        StandardCharsets.UTF_8));
        assertTrue(Files.isRegularFile(restored.resolve("web_magiclicense.db")));
        assertTrue(Files.isRegularFile(restored.resolve("certs/auth-chain.pem")));
        assertFalse(Files.exists(restored.resolve("certs/auth-key.pem")));
        assertFalse(Files.exists(restored.resolve(DeploymentLock.FILE_NAME)));

        byte[] wrongKey = fixture.authenticationKey().clone();
        wrongKey[0] ^= 0x01;
        assertThrows(
                SecurityException.class,
                () -> DeploymentBackup.verify(archive, wrongKey));
    }

    @Test
    void excludesConfiguredCredentialFilesInsideTheResourceTree() throws Exception {
        Fixture fixture = fixture();
        Path credential = fixture.liveDirectory()
                .resolve("resources/program/deployment-secret.txt");
        Files.writeString(credential, "must-not-be-archived", StandardCharsets.UTF_8);
        SecureFiles.makePrivateReadOnly(credential);
        Path archive = fixture.backupDirectory().resolve("credential-exclusion.skybackup");

        DeploymentBackup.Summary created = DeploymentBackup.create(
                fixture.liveDirectory(),
                fixture.storage(),
                fixture.preflight(),
                archive,
                fixture.authenticationKey(),
                Set.of(credential));

        assertEquals(4, created.fileCount());
        try (ZipFile zip = new ZipFile(archive.toFile(), StandardCharsets.UTF_8)) {
            assertNull(zip.getEntry("resources/program/deployment-secret.txt"));
        }
    }

    @Test
    void rejectsChangedPayloadAndUnsafeArchiveEntry() throws Exception {
        Fixture fixture = fixture();
        Path archive = fixture.backupDirectory().resolve("deployment.skybackup");
        DeploymentBackup.create(
                fixture.liveDirectory(),
                fixture.storage(),
                fixture.preflight(),
                archive,
                fixture.authenticationKey());

        Path changed = fixture.backupDirectory().resolve("changed.skybackup");
        rewriteEntry(archive, changed, "config.json", "changed".getBytes(StandardCharsets.UTF_8));
        assertThrows(
                SecurityException.class,
                () -> DeploymentBackup.verify(changed, fixture.authenticationKey()));

        Path traversal = fixture.backupDirectory().resolve("traversal.skybackup");
        renameEntry(archive, traversal, "config.json", "../config.json");
        assertThrows(
                IOException.class,
                () -> DeploymentBackup.verify(traversal, fixture.authenticationKey()));
    }

    @Test
    void currentSchemaBackupExcludesUnreferencedResourceJars() throws Exception {
        SecureFiles.preparePrivateDirectory(temporaryDirectory);
        Path live = SecureFiles.preparePrivateDirectory(temporaryDirectory.resolve("catalog-live"));
        Path backup = SecureFiles.preparePrivateDirectory(
                temporaryDirectory.resolve("catalog-backup"));
        Path certs = SecureFiles.preparePrivateDirectory(live.resolve("certs"));
        Path resourceDirectory = SecureFiles.preparePrivateDirectory(
                live.resolve("resources/1/1"));
        Files.writeString(live.resolve("config.json"), "{\"fixture\":true}");
        Files.writeString(certs.resolve("auth-chain.pem"), "fixture certificate");

        Path catalogResource = resourceDirectory.resolve("catalog.jar");
        writeValidResourceJar(catalogResource, "BackupProduct", "1.0.0");
        SecureFiles.makePrivateReadOnly(catalogResource);
        Path orphan = resourceDirectory.resolve("orphan.jar");
        writeValidResourceJar(orphan, "OrphanProduct", "1.0.0");
        SecureFiles.makePrivateReadOnly(orphan);

        Path database = live.resolve("web_magiclicense.db");
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(database.toString());
        try {
            WebUser owner = WebUser.builder()
                    .username("backup-admin")
                    .password("stored-password")
                    .role("ADMIN")
                    .maxPrograms(1)
                    .status(1)
                    .createTime(TimeUtil.getCurtTime())
                    .build();
            accessor.getUserDao().create(owner);
            Program program = Program.builder()
                    .userId(owner.getId())
                    .name("BackupProduct")
                    .status(1)
                    .createTime(TimeUtil.getCurtTime())
                    .build();
            accessor.getProgramDao().create(program);
            accessor.getProgramVersionDao().create(ProgramVersion.builder()
                    .programId(program.getId())
                    .version("1.0.0")
                    .fileName(catalogResource.getFileName().toString())
                    .filePath(catalogResource.toString())
                    .entryClass(DeploymentBackupTest.class.getName().replace('.', '/'))
                    .entryPoint("protectedEntryPoint")
                    .uploadTime(TimeUtil.getCurtTime())
                    .build());
        } finally {
            accessor.close();
        }

        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x33);
        DeploymentPreflight.Result preflight = new DeploymentPreflight.Result(
                live,
                null,
                new DeploymentPreflight.DatabaseSummary(
                        true, WebDataAccessor.supportedSchemaVersion(), true),
                1);
        Path archive = backup.resolve("catalog.skybackup");
        DeploymentBackup.create(live, new Storage(), preflight, archive, key);

        try (ZipFile zip = new ZipFile(archive.toFile(), StandardCharsets.UTF_8)) {
            assertTrue(zip.getEntry("resources/1/1/catalog.jar") != null);
            assertNull(zip.getEntry("resources/1/1/orphan.jar"));
        }

        Path restored = temporaryDirectory.resolve("catalog-restored");
        DeploymentBackup.extract(
                DeploymentBackup.verify(archive, key),
                restored);
        assertTrue(Files.isRegularFile(restored.resolve("resources/1/1/catalog.jar")));
        assertFalse(Files.exists(restored.resolve("resources/1/1/orphan.jar")));
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + restored.resolve("web_magiclicense.db"));
             Statement statement = connection.createStatement();
             var rows = statement.executeQuery(
                     "SELECT file_path FROM program_version ORDER BY id")) {
            assertTrue(rows.next());
            assertEquals("resources/1/1/catalog.jar", rows.getString(1));
            assertFalse(rows.next());
            assertEquals(
                    1,
                    ResourceCatalog.snapshot(
                            connection,
                            restored.resolve("resources")).size());
        }
    }

    private static void writeValidResourceJar(Path path, String name, String version)
            throws Exception {
        String className = DeploymentBackupTest.class.getName();
        String classEntry = className.replace('.', '/') + ".class";
        byte[] classBytes;
        try (InputStream input = DeploymentBackupTest.class.getClassLoader()
                .getResourceAsStream(classEntry)) {
            if (input == null) {
                throw new IOException("test class bytes are unavailable");
            }
            classBytes = input.readAllBytes();
        }
        String profile = "Name: " + name + "\n"
                + "Version: " + version + "\n"
                + "EntryClass: " + className + "\n"
                + "EntryPoint: protectedEntryPoint\n"
                + "InfPort: false\n";
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(path))) {
            jar.putNextEntry(new JarEntry("settings.yml"));
            jar.write(profile.getBytes(StandardCharsets.UTF_8));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry(classEntry));
            jar.write(classBytes);
            jar.closeEntry();
        }
    }

    public static void protectedEntryPoint() {
        // Valid no-op entry point for the backup resource fixture.
    }

    private Fixture fixture() throws Exception {
        SecureFiles.preparePrivateDirectory(temporaryDirectory);
        Path live = SecureFiles.preparePrivateDirectory(temporaryDirectory.resolve("live"));
        Path backup = SecureFiles.preparePrivateDirectory(temporaryDirectory.resolve("backup"));
        Path certs = SecureFiles.preparePrivateDirectory(live.resolve("certs"));
        Path resources = SecureFiles.preparePrivateDirectory(
                live.resolve("resources/program"));

        Files.writeString(
                live.resolve("config.json"),
                "{\"fixture\":true}",
                StandardCharsets.UTF_8);
        Files.writeString(
                certs.resolve("auth-chain.pem"),
                "fixture certificate",
                StandardCharsets.US_ASCII);
        Path resource = resources.resolve("version.jar");
        Files.writeString(resource, "protected", StandardCharsets.UTF_8);
        SecureFiles.makePrivateReadOnly(resource);

        Path database = live.resolve("web_magiclicense.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY, value TEXT)");
            statement.execute("INSERT INTO fixture(value) VALUES ('healthy')");
            statement.execute("PRAGMA user_version=6");
        }
        SecureFiles.makePrivateReadWrite(database);

        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x5a);
        Storage storage = new Storage();
        DeploymentPreflight.Result preflight = new DeploymentPreflight.Result(
                live,
                null,
                new DeploymentPreflight.DatabaseSummary(true, 6, true),
                1);
        return new Fixture(live, backup, storage, preflight, key);
    }

    private static void rewriteEntry(
            Path source,
            Path destination,
            String target,
            byte[] replacement
    ) throws Exception {
        try (ZipFile input = new ZipFile(source.toFile(), StandardCharsets.UTF_8);
             OutputStream raw = Files.newOutputStream(destination);
             ZipOutputStream output = new ZipOutputStream(raw, StandardCharsets.UTF_8)) {
            var entries = input.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                ZipEntry copy = new ZipEntry(entry.getName());
                copy.setTime(0);
                output.putNextEntry(copy);
                if (target.equals(entry.getName())) {
                    output.write(replacement);
                } else {
                    try (InputStream content = input.getInputStream(entry)) {
                        content.transferTo(output);
                    }
                }
                output.closeEntry();
            }
        }
        SecureFiles.makePrivateReadOnly(destination);
    }

    private static void renameEntry(
            Path source,
            Path destination,
            String target,
            String replacement
    ) throws Exception {
        try (ZipFile input = new ZipFile(source.toFile(), StandardCharsets.UTF_8);
             OutputStream raw = Files.newOutputStream(destination);
             ZipOutputStream output = new ZipOutputStream(raw, StandardCharsets.UTF_8)) {
            var entries = input.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                ZipEntry copy = new ZipEntry(
                        target.equals(entry.getName()) ? replacement : entry.getName());
                copy.setTime(0);
                output.putNextEntry(copy);
                try (InputStream content = input.getInputStream(entry)) {
                    content.transferTo(output);
                }
                output.closeEntry();
            }
        }
        SecureFiles.makePrivateReadOnly(destination);
    }

    private record Fixture(
            Path liveDirectory,
            Path backupDirectory,
            Storage storage,
            DeploymentPreflight.Result preflight,
            byte[] authenticationKey
    ) {
    }
}

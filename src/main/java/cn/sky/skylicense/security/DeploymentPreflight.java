package cn.sky.skylicense.security;

import cn.sky.skylicense.config.Storage;
import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dao.DatabaseRelationshipIntegrity;
import cn.sky.skylicense.web.service.OperationLogService;
import org.sqlite.SQLiteConfig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;

/** Read-only deployment validation for release automation and service provisioning. */
public final class DeploymentPreflight {
    private DeploymentPreflight() {
    }

    public static Result validate(Path workingDirectory, Storage storage) {
        try {
            Path root = requireWorkingDirectory(workingDirectory);
            StartupSecurity.validate(storage);
            OperationLogSanitizer.validateEnvironment();
            OperationLogService.validateEnvironment();
            MfaSecretProtector.validateEnvironment();
            requireRegularReadableFile(root.resolve("config.json"), "configuration");

            TlsMaterialValidator.Summary tls = StartupSecurity.validateTlsFiles(storage);
            Path privateKey = resolve(root, storage.getAuthTlsPrivateKey());
            SecureFiles.requireOwnerOnly(privateKey, false, "TLS private key");

            Path resourceDirectory = root.resolve("resources").normalize();
            requireProvisionableDirectory(resourceDirectory, "resource directory");
            if (Files.exists(resourceDirectory, LinkOption.NOFOLLOW_LINKS)) {
                SecureFiles.requireOwnerOnly(resourceDirectory, true, "resource directory");
            }
            Path databasePath = root.resolve(WebDataAccessor.DEFAULT_DATABASE_PATH).normalize();
            DatabaseSummary database = validateDatabase(databasePath);
            int resourceCount = validateResourceCatalog(
                    databasePath, database, resourceDirectory);
            StartupSecurity.validateBootstrapAdminEnvironment(database.activeAdministratorExists());
            return new Result(root, tls, database, resourceCount);
        } catch (IllegalStateException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException("Deployment preflight failed", error);
        }
    }

    static DatabaseSummary validateDatabase(Path database) throws Exception {
        Path normalized = database.toAbsolutePath().normalize();
        Path parent = normalized.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(parent) || !Files.isWritable(parent)) {
            throw new IllegalStateException("database parent directory is not readable and writable");
        }
        if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
            return new DatabaseSummary(false, 0, false);
        }
        requireRegularReadableFile(normalized, "database");
        if (!Files.isWritable(normalized)) {
            throw new IllegalStateException("database file is not writable: " + normalized);
        }
        SecureFiles.requireOwnerOnly(normalized, false, "database");
        validateOptionalSidecar(normalized.resolveSibling(normalized.getFileName() + "-wal"));
        validateOptionalSidecar(normalized.resolveSibling(normalized.getFileName() + "-shm"));

        SQLiteConfig sqlite = new SQLiteConfig();
        sqlite.setReadOnly(true);
        sqlite.setExplicitReadOnly(true);
        Exception failure = null;
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + normalized,
                sqlite.toProperties())) {
            validateQuickCheck(connection);
            int schemaVersion = querySchemaVersion(connection);
            if (schemaVersion > WebDataAccessor.supportedSchemaVersion()) {
                throw new IllegalStateException(
                        "database schema v" + schemaVersion + " is newer than supported v"
                                + WebDataAccessor.supportedSchemaVersion());
            }
            if (schemaVersion >= 8) {
                DatabaseRelationshipIntegrity.verify(connection);
            }
            boolean administratorExists = hasActiveAdministrator(connection);
            return new DatabaseSummary(true, schemaVersion, administratorExists);
        } catch (Exception error) {
            failure = error;
            throw error;
        } finally {
            hardenSqliteSidecars(normalized, failure);
        }
    }

    private static int validateResourceCatalog(
            Path database,
            DatabaseSummary summary,
            Path resourceDirectory
    ) throws Exception {
        if (!summary.exists() || summary.schemaVersion() < 8) {
            int legacyCount = ResourceManager.validateResources(resourceDirectory);
            if (!summary.exists() && legacyCount > 0) {
                throw new IllegalStateException(
                        "protected resources require a database catalog");
            }
            return legacyCount;
        }
        SQLiteConfig sqlite = new SQLiteConfig();
        sqlite.setReadOnly(true);
        sqlite.setExplicitReadOnly(true);
        Path normalized = database.toAbsolutePath().normalize();
        Exception failure = null;
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + normalized,
                sqlite.toProperties())) {
            return ResourceManager.validateResources(
                    resourceDirectory,
                    ResourceCatalog.snapshot(connection, resourceDirectory));
        } catch (Exception error) {
            failure = error;
            throw error;
        } finally {
            hardenSqliteSidecars(normalized, failure);
        }
    }

    private static void hardenSqliteSidecars(Path database, Exception priorFailure)
            throws IOException {
        try {
            for (String suffix : new String[]{"-wal", "-shm"}) {
                Path sidecar = database.resolveSibling(database.getFileName() + suffix);
                if (Files.exists(sidecar, LinkOption.NOFOLLOW_LINKS)) {
                    SecureFiles.makePrivateReadWrite(sidecar);
                }
            }
        } catch (IOException hardeningFailure) {
            if (priorFailure != null) {
                priorFailure.addSuppressed(hardeningFailure);
                return;
            }
            throw hardeningFailure;
        }
    }

    private static Path requireWorkingDirectory(Path workingDirectory) throws IOException {
        if (workingDirectory == null) {
            throw new IllegalStateException("working directory is required");
        }
        Path root = workingDirectory.toRealPath(LinkOption.NOFOLLOW_LINKS);
        BasicFileAttributes attributes = Files.readAttributes(
                root, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isDirectory() || attributes.isOther() || Files.isSymbolicLink(root)
                || !Files.isReadable(root) || !Files.isWritable(root)) {
            throw new IllegalStateException("working directory must be a readable writable directory");
        }
        SecureFiles.requireOwnerOnly(root, true, "working directory");
        return root;
    }

    private static Path resolve(Path root, String configuredPath) {
        Path path = Path.of(configuredPath);
        return (path.isAbsolute() ? path : root.resolve(path)).normalize().toAbsolutePath();
    }

    private static void requireProvisionableDirectory(Path directory, String label) throws IOException {
        if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            BasicFileAttributes attributes = Files.readAttributes(
                    directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isDirectory() || attributes.isOther() || Files.isSymbolicLink(directory)
                    || !Files.isReadable(directory) || !Files.isWritable(directory)) {
                throw new IllegalStateException(label + " is not a readable writable directory");
            }
            return;
        }
        Path parent = directory.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || !Files.isWritable(parent)) {
            throw new IllegalStateException(label + " cannot be created by the service account");
        }
    }

    private static void requireRegularReadableFile(Path path, String label) throws IOException {
        requireRegularReadableFile(path, label, true);
    }

    private static void requireRegularReadableFile(
            Path path,
            String label,
            boolean requireNonEmpty
    ) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(
                path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.isOther() || Files.isSymbolicLink(path)
                || !Files.isReadable(path) || (requireNonEmpty && attributes.size() == 0)) {
            String contentRequirement = requireNonEmpty ? "non-empty " : "";
            throw new IllegalStateException(
                    label + " must be a readable " + contentRequirement + "regular file: " + path);
        }
    }

    private static void validateOptionalSidecar(Path sidecar) throws IOException {
        if (!Files.exists(sidecar, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        // SQLite legitimately leaves a zero-length WAL after a read-only open
        // or successful checkpoint. Its own parser remains authoritative for
        // sidecar contents; the deployment boundary still rejects links,
        // special files, foreign ACLs and read-only placeholders here.
        requireRegularReadableFile(sidecar, "database sidecar", false);
        if (!Files.isWritable(sidecar)) {
            throw new IllegalStateException("database sidecar is not writable: " + sidecar);
        }
        SecureFiles.requireOwnerOnly(sidecar, false, "database sidecar");
    }

    private static void validateQuickCheck(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("PRAGMA quick_check")) {
            boolean row = false;
            while (result.next()) {
                row = true;
                if (!"ok".equalsIgnoreCase(result.getString(1))) {
                    throw new IllegalStateException(
                            "SQLite quick_check failed: " + result.getString(1));
                }
            }
            if (!row) {
                throw new IllegalStateException("SQLite quick_check returned no result");
            }
        }
    }

    private static int querySchemaVersion(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("PRAGMA user_version")) {
            if (!result.next()) {
                throw new IllegalStateException("SQLite user_version returned no result");
            }
            return result.getInt(1);
        }
    }

    private static boolean hasActiveAdministrator(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement();
             ResultSet tables = statement.executeQuery(
                     "SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_user'")) {
            if (!tables.next()) {
                return false;
            }
        }
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "SELECT COUNT(*) FROM web_user WHERE role='ADMIN' AND status=1")) {
            return result.next() && result.getLong(1) > 0;
        }
    }

    public record Result(
            Path workingDirectory,
            TlsMaterialValidator.Summary tls,
            DatabaseSummary database,
            int resourceCount
    ) {
        public long certificateDaysRemaining() {
            return Duration.between(Instant.now(), tls.notAfter()).toDays();
        }
    }

    public record DatabaseSummary(
            boolean exists,
            int schemaVersion,
            boolean activeAdministratorExists
    ) {
    }
}

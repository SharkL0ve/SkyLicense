package cn.sky.skylicense.security;

import cn.sky.skylicense.config.Storage;
import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.sqlite.SQLiteConfig;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/** Authenticated offline snapshots for database, configuration, resources, and TLS chain. */
public final class DeploymentBackup {
    public static final String HMAC_ENVIRONMENT = "SKYLICENSE_BACKUP_HMAC_KEY";
    private static final String FORMAT = "SkyLicense deployment backup";
    private static final int FORMAT_VERSION = 1;
    private static final String MANIFEST_ENTRY = "backup-manifest.json";
    private static final String AUTHENTICATOR_ENTRY = "backup-manifest.hmac";
    private static final byte[] AUTHENTICATOR_DOMAIN =
            "SkyLicense deployment backup v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final long MAX_MANIFEST_BYTES = 4L * 1024 * 1024;
    private static final long MAX_FILE_BYTES = 16L * 1024 * 1024 * 1024;
    private static final long MAX_TOTAL_BYTES = 64L * 1024 * 1024 * 1024;
    private static final int MAX_ENTRIES = 25_000;
    private static final int BUFFER_BYTES = 64 * 1024;
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private DeploymentBackup() {
    }

    public static Summary create(
            Path workingDirectory,
            Storage storage,
            DeploymentPreflight.Result preflight,
            Path destination
    ) throws Exception {
        byte[] key = keyFromEnvironment();
        try {
            return create(workingDirectory, storage, preflight, destination, key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static Summary create(
            Path workingDirectory,
            Storage storage,
            DeploymentPreflight.Result preflight,
            Path destination,
            byte[] authenticationKey
    ) throws Exception {
        return create(
                workingDirectory,
                storage,
                preflight,
                destination,
                authenticationKey,
                configuredSecretFiles());
    }

    static Summary create(
            Path workingDirectory,
            Storage storage,
            DeploymentPreflight.Result preflight,
            Path destination,
            byte[] authenticationKey,
            Set<Path> excludedSecretFiles
    ) throws Exception {
        validateAuthenticationKey(authenticationKey);
        if (excludedSecretFiles == null) {
            throw new IllegalArgumentException("excluded secret files must not be null");
        }
        Path root = workingDirectory.toRealPath(LinkOption.NOFOLLOW_LINKS);
        if (!preflight.database().exists()) {
            throw new IllegalStateException("cannot back up a deployment without a database");
        }
        Path archive = destination.toAbsolutePath().normalize();
        if (archive.startsWith(root)) {
            throw new IllegalArgumentException(
                    "backup destination must be outside the live deployment directory");
        }
        Path parent = archive.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("backup destination parent does not exist");
        }
        SecureFiles.requireOwnerOnly(parent, true, "backup destination directory");
        if (Files.exists(archive, LinkOption.NOFOLLOW_LINKS)) {
            throw new FileAlreadyExistsException(archive.toString());
        }

        Path database = root.resolve(WebDataAccessor.DEFAULT_DATABASE_PATH).normalize();
        checkpointDatabase(database);
        DeploymentPreflight.DatabaseSummary databaseSummary =
                DeploymentPreflight.validateDatabase(database);

        Set<Path> catalogResources = catalogResources(
                database, databaseSummary.schemaVersion(), root.resolve("resources"));
        List<SourceFile> sources = collectSources(
                root, storage, excludedSecretFiles, catalogResources);
        Path temporary = Files.createTempFile(parent, ".skylicense-backup-", ".part");
        SecureFiles.makePrivateReadWrite(temporary);
        boolean moved = false;
        Manifest manifest;
        try {
            List<FileRecord> files = new ArrayList<>();
            try (OutputStream raw = Files.newOutputStream(
                    temporary,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    LinkOption.NOFOLLOW_LINKS);
                 ZipOutputStream zip = new ZipOutputStream(raw, StandardCharsets.UTF_8)) {
                zip.setLevel(Deflater.BEST_COMPRESSION);
                for (SourceFile source : sources) {
                    files.add(writeFile(zip, source));
                }
                files.sort(Comparator.comparing(FileRecord::path));
                String certificateEntry = certificateEntry(root, storage);
                manifest = new Manifest(
                        FORMAT,
                        FORMAT_VERSION,
                        Instant.now().toString(),
                        databaseSummary.schemaVersion(),
                        preflight.resourceCount(),
                        certificateEntry,
                        false,
                        externalSecretNames(),
                        files);
                byte[] manifestBytes = GSON.toJson(manifest).getBytes(StandardCharsets.UTF_8);
                if (manifestBytes.length > MAX_MANIFEST_BYTES) {
                    throw new IOException("backup manifest exceeds its size limit");
                }
                writeBytes(zip, MANIFEST_ENTRY, manifestBytes);
                byte[] authenticator = authenticate(authenticationKey, manifestBytes);
                try {
                    writeBytes(
                            zip,
                            AUTHENTICATOR_ENTRY,
                            HexFormat.of().formatHex(authenticator)
                                    .getBytes(StandardCharsets.US_ASCII));
                } finally {
                    Arrays.fill(authenticator, (byte) 0);
                }
            }
            moveNoReplace(temporary, archive);
            moved = true;
            SecureFiles.makePrivateReadOnly(archive);
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
        return summary(archive, manifest);
    }

    public static Summary verify(Path archive) throws Exception {
        byte[] key = keyFromEnvironment();
        try {
            return verify(archive, key).summary();
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static VerifiedArchive verify(Path archive, byte[] authenticationKey) throws Exception {
        validateAuthenticationKey(authenticationKey);
        Path normalized = requireArchive(archive);
        try (ZipFile zip = new ZipFile(normalized.toFile(), StandardCharsets.UTF_8)) {
            Map<String, ZipEntry> entries = collectEntries(zip);
            byte[] manifestBytes = readBounded(
                    zip,
                    requireEntry(entries, MANIFEST_ENTRY),
                    MAX_MANIFEST_BYTES,
                    MANIFEST_ENTRY);
            byte[] encodedAuthenticator = readBounded(
                    zip,
                    requireEntry(entries, AUTHENTICATOR_ENTRY),
                    64,
                    AUTHENTICATOR_ENTRY);
            byte[] expected = authenticate(authenticationKey, manifestBytes);
            byte[] supplied = decodeHex32(encodedAuthenticator, AUTHENTICATOR_ENTRY);
            try {
                if (!MessageDigest.isEqual(expected, supplied)) {
                    throw new SecurityException("backup manifest authentication failed");
                }
            } finally {
                Arrays.fill(expected, (byte) 0);
                Arrays.fill(supplied, (byte) 0);
            }

            Manifest manifest;
            try {
                manifest = GSON.fromJson(
                        new String(manifestBytes, StandardCharsets.UTF_8), Manifest.class);
            } catch (RuntimeException error) {
                throw new IOException("backup manifest is malformed", error);
            }
            validateManifest(manifest, entries.keySet());
            long total = 0;
            for (FileRecord file : manifest.files()) {
                ZipEntry entry = requireEntry(entries, file.path());
                if (entry.isDirectory()) {
                    throw new IOException("backup file entry is a directory: " + file.path());
                }
                HashResult hash = hashEntry(zip, entry, MAX_FILE_BYTES);
                total = Math.addExact(total, hash.size());
                if (total > MAX_TOTAL_BYTES) {
                    throw new IOException("backup expands beyond the total size limit");
                }
                if (hash.size() != file.size()
                        || !hash.sha256().equals(file.sha256())) {
                    throw new SecurityException(
                            "backup file hash or size mismatch: " + file.path());
                }
            }
            return new VerifiedArchive(normalized, manifest, summary(normalized, manifest));
        }
    }

    public static Summary extract(Path archive, Path destination) throws Exception {
        byte[] key = keyFromEnvironment();
        try {
            VerifiedArchive verified = verify(archive, key);
            extract(verified, destination);
            return verified.summary();
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static void extract(VerifiedArchive verified, Path destination) throws Exception {
        Path root = destination.toAbsolutePath().normalize();
        Path parent = root.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("restore destination parent does not exist");
        }
        SecureFiles.requireOwnerOnly(parent, true, "restore destination parent");
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new FileAlreadyExistsException(root.toString());
        }
        Files.createDirectory(root);
        SecureFiles.preparePrivateDirectory(root);
        SecureFiles.preparePrivateDirectory(root.resolve("resources"));

        try (ZipFile zip = new ZipFile(verified.path().toFile(), StandardCharsets.UTF_8)) {
            Map<String, ZipEntry> entries = collectEntries(zip);
            for (FileRecord file : verified.manifest().files()) {
                Path target = resolveEntry(root, file.path());
                Path targetParent = target.getParent();
                if (targetParent == null) {
                    throw new IOException("backup entry has no parent: " + file.path());
                }
                SecureFiles.preparePrivateDirectory(targetParent);
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                long total = 0;
                try (InputStream input = zip.getInputStream(requireEntry(entries, file.path()));
                     OutputStream output = Files.newOutputStream(
                             target,
                             StandardOpenOption.CREATE_NEW,
                             StandardOpenOption.WRITE,
                             LinkOption.NOFOLLOW_LINKS)) {
                    byte[] buffer = new byte[BUFFER_BYTES];
                    int read;
                    while ((read = input.read(buffer)) != -1) {
                        total = Math.addExact(total, read);
                        if (total > MAX_FILE_BYTES) {
                            throw new IOException("backup entry exceeds its size limit");
                        }
                        digest.update(buffer, 0, read);
                        output.write(buffer, 0, read);
                    }
                }
                String hash = HexFormat.of().formatHex(digest.digest());
                if (total != file.size() || !hash.equals(file.sha256())) {
                    throw new SecurityException(
                            "extracted backup file hash or size mismatch: " + file.path());
                }
                if (file.path().startsWith("resources/")
                        || file.path().equals(verified.manifest().tlsCertificatePath())) {
                    SecureFiles.makePrivateReadOnly(target);
                } else {
                    SecureFiles.makePrivateReadWrite(target);
                }
            }
        }
        relocateResourceCatalog(root, verified.manifest());
    }

    private static void relocateResourceCatalog(Path root, Manifest manifest) throws Exception {
        if (manifest.databaseSchemaVersion() < 8) {
            return;
        }
        List<String> resourceEntries = manifest.files().stream()
                .map(FileRecord::path)
                .filter(path -> path.startsWith("resources/"))
                .toList();
        if (resourceEntries.size() != manifest.protectedResourceCount()) {
            throw new IOException("backup resource count does not match its manifest files");
        }

        Path database = root.resolve(WebDataAccessor.DEFAULT_DATABASE_PATH).normalize();
        SQLiteConfig sqlite = new SQLiteConfig();
        sqlite.setBusyTimeout(10_000);
        sqlite.setSynchronous(SQLiteConfig.SynchronousMode.FULL);
        sqlite.enforceForeignKeys(true);
        Set<String> relocatedEntries = new HashSet<>();
        int relocatedRows = 0;
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + database.toAbsolutePath().normalize(),
                sqlite.toProperties())) {
            connection.setAutoCommit(false);
            try (PreparedStatement query = connection.prepareStatement(
                    "SELECT id, file_path FROM program_version ORDER BY id");
                 PreparedStatement update = connection.prepareStatement(
                         "UPDATE program_version SET file_path = ? WHERE id = ?");
                 ResultSet rows = query.executeQuery()) {
                while (rows.next()) {
                    relocatedRows = Math.addExact(relocatedRows, 1);
                    if (relocatedRows > MAX_ENTRIES) {
                        throw new IOException("backup resource catalog contains too many rows");
                    }
                    long id = rows.getLong(1);
                    String entry = matchResourceEntry(rows.getString(2), resourceEntries);
                    if (!relocatedEntries.add(entry)) {
                        throw new IOException(
                                "backup resource catalog contains a duplicate file mapping: " + entry);
                    }
                    Path restored = resolveEntry(root, entry);
                    if (!Files.isRegularFile(restored, LinkOption.NOFOLLOW_LINKS)
                            || Files.isSymbolicLink(restored)) {
                        throw new IOException(
                                "backup resource catalog file was not restored: " + entry);
                    }
                    update.setString(1, entry);
                    update.setLong(2, id);
                    if (update.executeUpdate() != 1) {
                        throw new IOException(
                                "unable to relocate backup resource catalog row: " + id);
                    }
                }
                if (relocatedRows != manifest.protectedResourceCount()
                        || relocatedEntries.size() != resourceEntries.size()) {
                    throw new IOException(
                            "backup resource catalog does not match the authenticated manifest");
                }
                connection.commit();
            } catch (Exception error) {
                connection.rollback();
                throw error;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (ArithmeticException error) {
            throw new IOException("backup resource catalog row count overflow", error);
        }
        checkpointDatabase(database);
    }

    private static String matchResourceEntry(
            String configuredPath,
            List<String> resourceEntries
    ) throws IOException {
        if (configuredPath == null || configuredPath.isBlank()) {
            throw new IOException("backup resource catalog contains an empty path");
        }
        String normalized = configuredPath.replace('\\', '/');
        List<String> matches = resourceEntries.stream()
                .filter(entry -> normalized.equals(entry) || normalized.endsWith("/" + entry))
                .toList();
        if (matches.isEmpty()) {
            String folded = normalized.toLowerCase(Locale.ROOT);
            matches = resourceEntries.stream()
                    .filter(entry -> {
                        String foldedEntry = entry.toLowerCase(Locale.ROOT);
                        return folded.equals(foldedEntry)
                                || folded.endsWith("/" + foldedEntry);
                    })
                    .toList();
        }
        if (matches.size() != 1) {
            throw new IOException(
                    "backup resource catalog path does not identify exactly one archive entry");
        }
        return matches.get(0);
    }

    private static List<SourceFile> collectSources(
            Path root,
            Storage storage,
            Set<Path> excludedSecretFiles,
            Set<Path> catalogResources
    ) throws IOException {
        Map<String, SourceFile> sources = new HashMap<>();
        Set<Path> secretFiles = new HashSet<>();
        for (Path path : excludedSecretFiles) {
            if (path == null) {
                throw new IllegalArgumentException("excluded secret file path must not be null");
            }
            secretFiles.add(path.toAbsolutePath().normalize());
        }
        addSource(sources, root, root.resolve("config.json"), "configuration");
        addSource(
                sources,
                root,
                root.resolve(WebDataAccessor.DEFAULT_DATABASE_PATH).normalize(),
                "database");

        Path privateKey = configuredPath(root, storage.getAuthTlsPrivateKey());
        Path resources = root.resolve("resources").normalize();
        if (catalogResources != null) {
            for (Path resource : catalogResources) {
                Path normalized = resource.toAbsolutePath().normalize();
                if (normalized.equals(privateKey) || secretFiles.contains(normalized)) {
                    throw new IOException(
                            "database catalog references a configured secret file: " + normalized);
                }
                SecureFiles.requireOwnerOnly(normalized, false, "protected resource");
                addSource(sources, root, normalized, "protected resource");
            }
        } else if (Files.exists(resources, LinkOption.NOFOLLOW_LINKS)) {
            try (var paths = Files.walk(resources)) {
                for (Path path : paths.sorted().toList()) {
                    if (path.equals(resources)) {
                        continue;
                    }
                    if (Files.isSymbolicLink(path)) {
                        throw new IOException("backup source contains a symbolic link: " + path);
                    }
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        SecureFiles.requireOwnerOnly(path, true, "resource directory");
                    } else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                        Path normalized = path.toAbsolutePath().normalize();
                        if (normalized.equals(privateKey) || secretFiles.contains(normalized)) {
                            continue;
                        }
                        SecureFiles.requireOwnerOnly(path, false, "protected resource");
                        addSource(sources, root, path, "protected resource");
                    } else {
                        throw new IOException("backup source contains an unsupported entry: " + path);
                    }
                }
            }
        }

        Path certificate = configuredPath(root, storage.getAuthTlsCertificateChain());
        if (certificate.startsWith(root) && !secretFiles.contains(certificate)) {
            addSource(sources, root, certificate, "TLS certificate chain");
        }
        List<SourceFile> ordered = new ArrayList<>(sources.values());
        ordered.sort(Comparator.comparing(SourceFile::entry));
        if (ordered.size() > MAX_ENTRIES - 2) {
            throw new IOException("backup contains too many entries");
        }
        return ordered;
    }

    private static Set<Path> catalogResources(
            Path database,
            int schemaVersion,
            Path resourceRoot
    ) throws Exception {
        if (schemaVersion < 8) {
            return null;
        }
        SQLiteConfig sqlite = new SQLiteConfig();
        sqlite.setReadOnly(true);
        sqlite.setExplicitReadOnly(true);
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + database.toAbsolutePath().normalize(),
                sqlite.toProperties())) {
            List<ResourceManager.CatalogEntry> catalog =
                    ResourceCatalog.snapshot(connection, resourceRoot);
            if (ResourceManager.validateResources(resourceRoot, catalog) != catalog.size()) {
                throw new IOException("resource catalog validation count mismatch");
            }
            Set<Path> paths = new LinkedHashSet<>();
            for (ResourceManager.CatalogEntry entry : catalog) {
                paths.add(entry.path().toAbsolutePath().normalize());
            }
            return Set.copyOf(paths);
        }
    }

    private static void addSource(
            Map<String, SourceFile> sources,
            Path root,
            Path source,
            String label
    ) throws IOException {
        Path normalized = source.toAbsolutePath().normalize();
        if (!normalized.startsWith(root)
                || Files.isSymbolicLink(normalized)
                || !Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(normalized)) {
            throw new IOException(label + " is not a readable regular file: " + normalized);
        }
        String entry = entryName(root, normalized);
        SourceFile previous = sources.putIfAbsent(entry, new SourceFile(entry, normalized));
        if (previous != null && !previous.path().equals(normalized)) {
            throw new IOException("backup sources collide at entry " + entry);
        }
    }

    private static FileRecord writeFile(ZipOutputStream zip, SourceFile source) throws Exception {
        ZipEntry entry = new ZipEntry(source.entry());
        entry.setTime(0);
        zip.putNextEntry(entry);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long total = 0;
        try (InputStream input = Files.newInputStream(
                source.path(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[BUFFER_BYTES];
            int read;
            while ((read = input.read(buffer)) != -1) {
                total = Math.addExact(total, read);
                if (total > MAX_FILE_BYTES) {
                    throw new IOException("backup source exceeds its size limit: " + source.path());
                }
                digest.update(buffer, 0, read);
                zip.write(buffer, 0, read);
            }
        } finally {
            zip.closeEntry();
        }
        return new FileRecord(source.entry(), total, HexFormat.of().formatHex(digest.digest()));
    }

    private static void writeBytes(ZipOutputStream zip, String name, byte[] value)
            throws IOException {
        ZipEntry entry = new ZipEntry(name);
        entry.setTime(0);
        zip.putNextEntry(entry);
        try {
            zip.write(value);
        } finally {
            zip.closeEntry();
        }
    }

    private static Map<String, ZipEntry> collectEntries(ZipFile zip) throws IOException {
        Map<String, ZipEntry> entries = new HashMap<>();
        var enumeration = zip.entries();
        int count = 0;
        while (enumeration.hasMoreElements()) {
            ZipEntry entry = enumeration.nextElement();
            count = Math.addExact(count, 1);
            if (count > MAX_ENTRIES) {
                throw new IOException("backup contains too many entries");
            }
            validateEntryName(entry.getName());
            if (entries.putIfAbsent(entry.getName(), entry) != null) {
                throw new IOException("backup contains a duplicate entry: " + entry.getName());
            }
        }
        return entries;
    }

    private static void validateManifest(Manifest manifest, Set<String> archiveEntries)
            throws IOException {
        if (manifest == null
                || !FORMAT.equals(manifest.format())
                || manifest.version() != FORMAT_VERSION
                || manifest.createdAt() == null
                || manifest.databaseSchemaVersion() < 0
                || manifest.databaseSchemaVersion() > WebDataAccessor.supportedSchemaVersion()
                || manifest.protectedResourceCount() < 0
                || manifest.tlsPrivateKeyIncluded()
                || manifest.requiredExternalSecrets() == null
                || manifest.files() == null
                || manifest.files().size() > MAX_ENTRIES - 2) {
            throw new IOException("backup manifest contains invalid metadata");
        }
        try {
            Instant.parse(manifest.createdAt());
        } catch (RuntimeException error) {
            throw new IOException("backup manifest timestamp is invalid", error);
        }

        Set<String> expected = new LinkedHashSet<>();
        expected.add(MANIFEST_ENTRY);
        expected.add(AUTHENTICATOR_ENTRY);
        String previous = null;
        for (FileRecord file : manifest.files()) {
            if (file == null || file.size() < 0 || file.size() > MAX_FILE_BYTES
                    || file.sha256() == null
                    || !file.sha256().matches("[0-9a-f]{64}")) {
                throw new IOException("backup manifest contains an invalid file record");
            }
            validateEntryName(file.path());
            if (MANIFEST_ENTRY.equals(file.path()) || AUTHENTICATOR_ENTRY.equals(file.path())) {
                throw new IOException("backup manifest references a reserved entry");
            }
            if (previous != null && previous.compareTo(file.path()) >= 0) {
                throw new IOException("backup manifest file records are not strictly sorted");
            }
            previous = file.path();
            if (!expected.add(file.path())) {
                throw new IOException("backup manifest contains a duplicate file path");
            }
        }
        if (!expected.contains("config.json")
                || !expected.contains("web_magiclicense.db")) {
            throw new IOException("backup manifest is missing a required deployment file");
        }
        if (!expected.equals(new HashSet<>(archiveEntries))) {
            throw new IOException("backup archive entries do not match the authenticated manifest");
        }
        if (manifest.tlsCertificatePath() != null
                && manifest.files().stream().noneMatch(
                        file -> file.path().equals(manifest.tlsCertificatePath()))) {
            throw new IOException("backup manifest TLS certificate path is not present");
        }
    }

    private static void validateEntryName(String name) throws IOException {
        if (name == null || name.isEmpty() || name.length() > 1_024
                || name.startsWith("/") || name.endsWith("/") || name.indexOf('\\') >= 0
                || name.indexOf('\0') >= 0) {
            throw new IOException("backup contains an unsafe entry name");
        }
        for (String component : name.split("/", -1)) {
            if (component.isEmpty() || ".".equals(component) || "..".equals(component)) {
                throw new IOException("backup contains an unsafe entry name: " + name);
            }
        }
    }

    private static Path resolveEntry(Path root, String entry) throws IOException {
        validateEntryName(entry);
        Path target = root.resolve(entry.replace('/', java.io.File.separatorChar)).normalize();
        if (!target.startsWith(root) || target.equals(root)) {
            throw new IOException("backup entry escapes the restore directory: " + entry);
        }
        return target;
    }

    private static byte[] readBounded(
            ZipFile zip,
            ZipEntry entry,
            long maximum,
            String label
    ) throws IOException {
        try (InputStream input = zip.getInputStream(entry);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8_192];
            long total = 0;
            int read;
            while ((read = input.read(buffer)) != -1) {
                total = Math.addExact(total, read);
                if (total > maximum) {
                    throw new IOException(label + " exceeds its size limit");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static HashResult hashEntry(ZipFile zip, ZipEntry entry, long maximum)
            throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long total = 0;
        try (InputStream input = zip.getInputStream(entry)) {
            byte[] buffer = new byte[BUFFER_BYTES];
            int read;
            while ((read = input.read(buffer)) != -1) {
                total = Math.addExact(total, read);
                if (total > maximum) {
                    throw new IOException("backup entry exceeds its size limit: " + entry.getName());
                }
                digest.update(buffer, 0, read);
            }
        }
        return new HashResult(total, HexFormat.of().formatHex(digest.digest()));
    }

    private static void checkpointDatabase(Path database) throws Exception {
        SQLiteConfig sqlite = new SQLiteConfig();
        sqlite.setBusyTimeout(10_000);
        sqlite.setSynchronous(SQLiteConfig.SynchronousMode.FULL);
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + database.toAbsolutePath().normalize(),
                sqlite.toProperties());
             Statement statement = connection.createStatement()) {
            try (ResultSet result = statement.executeQuery("PRAGMA wal_checkpoint(TRUNCATE)")) {
                if (!result.next() || result.getInt(1) != 0) {
                    throw new IllegalStateException("SQLite WAL checkpoint remained busy");
                }
            }
            try (ResultSet result = statement.executeQuery("PRAGMA quick_check")) {
                boolean row = false;
                while (result.next()) {
                    row = true;
                    if (!"ok".equalsIgnoreCase(result.getString(1))) {
                        throw new IllegalStateException(
                                "SQLite quick_check failed before backup: " + result.getString(1));
                    }
                }
                if (!row) {
                    throw new IllegalStateException("SQLite quick_check returned no result");
                }
            }
        }
        SecureFiles.makePrivateReadWrite(database);
        Path wal = database.resolveSibling(database.getFileName() + "-wal");
        if (Files.exists(wal, LinkOption.NOFOLLOW_LINKS)) {
            SecureFiles.makePrivateReadWrite(wal);
            if (Files.size(wal) != 0) {
                throw new IllegalStateException("SQLite WAL remains non-empty after checkpoint");
            }
        }
        Path sharedMemory = database.resolveSibling(database.getFileName() + "-shm");
        if (Files.exists(sharedMemory, LinkOption.NOFOLLOW_LINKS)) {
            SecureFiles.makePrivateReadWrite(sharedMemory);
        }
    }

    private static byte[] keyFromEnvironment() {
        String value = SecretSource.readRequired(HMAC_ENVIRONMENT, 64);
        if (value == null || !value.matches("(?i)[0-9a-f]{64}")) {
            throw new IllegalStateException(
                    HMAC_ENVIRONMENT + " must be a non-zero 64-character hexadecimal value");
        }
        byte[] key = HexFormat.of().parseHex(value);
        try {
            validateAuthenticationKey(key);
            return key;
        } catch (RuntimeException error) {
            Arrays.fill(key, (byte) 0);
            throw error;
        }
    }

    private static Set<Path> configuredSecretFiles() {
        Set<Path> files = new HashSet<>();
        for (String name : List.of(
                "SKYLICENSE_OPERATION_LOG_HMAC_KEY",
                HMAC_ENVIRONMENT,
                "SKYLICENSE_TLS_KEY_PASSWORD",
                "SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD",
                MfaSecretProtector.ENVIRONMENT,
                "SKYLICENSE_OPERATION_LOG_MAX_ROWS")) {
            Path path = SecretSource.configuredFilePath(name);
            if (path != null) {
                files.add(path.toAbsolutePath().normalize());
            }
        }
        return Set.copyOf(files);
    }

    private static List<String> externalSecretNames() {
        List<String> names = new ArrayList<>();
        for (String name : List.of(
                "SKYLICENSE_OPERATION_LOG_HMAC_KEY",
                HMAC_ENVIRONMENT,
                "SKYLICENSE_TLS_KEY_PASSWORD",
                "SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD",
                MfaSecretProtector.ENVIRONMENT)) {
            names.add(name);
            names.add(name + "_FILE");
        }
        return List.copyOf(names);
    }

    private static void validateAuthenticationKey(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("backup authentication key must contain 32 bytes");
        }
        int difference = 0;
        for (byte current : key) {
            difference |= current;
        }
        if (difference == 0) {
            throw new IllegalArgumentException("backup authentication key must not be all zero");
        }
    }

    private static byte[] authenticate(byte[] key, byte[] manifest)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(AUTHENTICATOR_DOMAIN);
        return mac.doFinal(manifest);
    }

    private static byte[] decodeHex32(byte[] value, String label) throws IOException {
        if (value.length != 64) {
            throw new IOException(label + " must contain exactly 64 hexadecimal characters");
        }
        try {
            return HexFormat.of().parseHex(new String(value, StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException error) {
            throw new IOException(label + " is not valid hexadecimal", error);
        }
    }

    private static Path requireArchive(Path archive) throws IOException {
        Path normalized = archive.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(normalized)
                || !Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(normalized)
                || Files.size(normalized) == 0) {
            throw new IOException("backup archive must be a readable non-empty regular file");
        }
        return normalized;
    }

    private static ZipEntry requireEntry(Map<String, ZipEntry> entries, String name)
            throws IOException {
        ZipEntry entry = entries.get(name);
        if (entry == null) {
            throw new IOException("backup is missing entry: " + name);
        }
        return entry;
    }

    private static String certificateEntry(Path root, Storage storage) {
        Path certificate = configuredPath(root, storage.getAuthTlsCertificateChain());
        return certificate.startsWith(root) && !configuredSecretFiles().contains(certificate)
                ? entryName(root, certificate)
                : null;
    }

    private static Path configuredPath(Path root, String configured) {
        Path value = Path.of(configured);
        return (value.isAbsolute() ? value : root.resolve(value)).toAbsolutePath().normalize();
    }

    private static String entryName(Path root, Path path) {
        return root.relativize(path).toString().replace(java.io.File.separatorChar, '/');
    }

    private static void moveNoReplace(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source, destination);
        }
    }

    private static Summary summary(Path archive, Manifest manifest) {
        long total = manifest.files().stream().mapToLong(FileRecord::size).sum();
        return new Summary(
                archive,
                manifest.createdAt(),
                manifest.databaseSchemaVersion(),
                manifest.protectedResourceCount(),
                manifest.files().size(),
                total,
                manifest.tlsCertificatePath() != null,
                manifest.tlsPrivateKeyIncluded());
    }

    private record SourceFile(String entry, Path path) {
    }

    private record HashResult(long size, String sha256) {
    }

    private record FileRecord(String path, long size, String sha256) {
    }

    private record Manifest(
            String format,
            int version,
            String createdAt,
            int databaseSchemaVersion,
            int protectedResourceCount,
            String tlsCertificatePath,
            boolean tlsPrivateKeyIncluded,
            List<String> requiredExternalSecrets,
            List<FileRecord> files
    ) {
    }

    static record VerifiedArchive(Path path, Manifest manifest, Summary summary) {
    }

    public record Summary(
            Path archive,
            String createdAt,
            int databaseSchemaVersion,
            int protectedResourceCount,
            int fileCount,
            long uncompressedBytes,
            boolean tlsCertificateIncluded,
            boolean tlsPrivateKeyIncluded
    ) {
    }
}

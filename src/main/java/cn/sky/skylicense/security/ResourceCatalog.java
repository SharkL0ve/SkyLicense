package cn.sky.skylicense.security;

import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Database-authoritative catalog and crash recovery for protected resources. */
public final class ResourceCatalog {
    private static final Logger LOG = LogManager.getLogger(ResourceCatalog.class);
    private static final int MAX_SCAN_ENTRIES = 100_000;

    private ResourceCatalog() {
    }

    public static List<ResourceManager.CatalogEntry> snapshot(
            WebDataAccessor accessor,
            Path resourceRoot
    ) throws SQLException {
        if (accessor == null || accessor.getDataSource() == null) {
            throw new SQLException("open database accessor is required for the resource catalog");
        }
        try (Connection connection = accessor.getDataSource().getConnection()) {
            return snapshot(connection, resourceRoot);
        }
    }

    public static List<ResourceManager.CatalogEntry> snapshot(
            Connection connection,
            Path resourceRoot
    ) throws SQLException {
        if (connection == null || resourceRoot == null) {
            throw new SQLException("database connection and resource root are required");
        }
        final Path root;
        try {
            root = SecureFiles.canonicalPath(resourceRoot);
        } catch (IOException error) {
            throw new SQLException("resource root cannot be canonicalized safely", error);
        }
        Path deploymentRoot = root.getParent();
        if (deploymentRoot == null) {
            throw new SQLException("resource root has no deployment parent");
        }
        List<ResourceManager.CatalogEntry> entries = new ArrayList<>();
        Set<Path> paths = new HashSet<>();
        Set<String> identities = new HashSet<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT p.name, v.version, v.file_path
                FROM program_version v
                JOIN program p ON p.id = v.program_id
                ORDER BY v.id
                """);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                String name = result.getString(1);
                String version = result.getString(2);
                String configuredPath = result.getString(3);
                if (name == null || name.isBlank()
                        || version == null || version.isBlank()
                        || configuredPath == null || configuredPath.isBlank()) {
                    throw new SQLException("resource catalog contains incomplete metadata");
                }
                final Path parsed;
                try {
                    parsed = Path.of(configuredPath);
                } catch (RuntimeException error) {
                    throw new SQLException("resource catalog contains an invalid path", error);
                }
                final Path path;
                try {
                    path = SecureFiles.canonicalPath(
                            parsed.isAbsolute() ? parsed : deploymentRoot.resolve(parsed));
                } catch (IOException error) {
                    throw new SQLException("resource path cannot be canonicalized safely", error);
                }
                if (path.equals(root) || !path.startsWith(root)) {
                    throw new SQLException(
                            "resource catalog path is outside the resource directory: " + path);
                }
                if (!paths.add(path)) {
                    throw new SQLException("resource catalog contains a duplicate path: " + path);
                }
                String identity = ResourceManager.identifier(name, version);
                if (!identities.add(identity)) {
                    throw new SQLException(
                            "resource catalog contains a duplicate Name/Version: "
                                    + name + " / " + version);
                }
                entries.add(new ResourceManager.CatalogEntry(name, version, path));
            }
        }
        return List.copyOf(entries);
    }

    public static boolean reload(
            WebDataAccessor accessor,
            Path resourceRoot,
            boolean logDetails
    ) {
        synchronized (ResourceManager.class) {
            try {
                return ResourceManager.reloadResources(
                        resourceRoot,
                        snapshot(accessor, resourceRoot),
                        logDetails);
            } catch (SQLException | RuntimeException error) {
                LOG.error("Unable to read the protected-resource database catalog", error);
                return false;
            }
        }
    }

    /**
     * Moves upload leftovers outside the scan tree. Missing catalog files remain
     * a fail-closed error during the following catalog reload.
     */
    public static int quarantineUnreferenced(
            WebDataAccessor accessor,
            Path resourceRoot
    ) throws SQLException, IOException {
        synchronized (ResourceManager.class) {
            Path root = SecureFiles.canonicalPath(resourceRoot);
            Set<Path> expected = new HashSet<>();
            for (ResourceManager.CatalogEntry entry : snapshot(accessor, root)) {
                expected.add(entry.path().toAbsolutePath().normalize());
            }
            if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
                return 0;
            }
            int visited = 0;
            List<Path> leftovers = new ArrayList<>();
            try (var paths = Files.walk(root)) {
                for (Path path : paths.toList()) {
                    visited = Math.addExact(visited, 1);
                    if (visited > MAX_SCAN_ENTRIES) {
                        throw new IOException("resource directory contains too many entries");
                    }
                    BasicFileAttributes attributes = Files.readAttributes(
                            path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    if (Files.isSymbolicLink(path) || attributes.isOther()) {
                        throw new IOException(
                                "resource directory contains a link or reparse point: " + path);
                    }
                    if (!attributes.isRegularFile()) {
                        continue;
                    }
                    String name = path.getFileName().toString();
                    Path normalized = path.toAbsolutePath().normalize();
                    if ((name.endsWith(".jar") && !expected.contains(normalized))
                            || name.endsWith(".jar.part")) {
                        leftovers.add(normalized);
                    }
                }
            } catch (ArithmeticException error) {
                throw new IOException("resource directory entry count overflow", error);
            }
            for (Path leftover : leftovers) {
                ResourceFileStore.quarantine(root, leftover);
                LOG.warn("Quarantined unreferenced protected-resource artifact: {}", leftover);
            }
            return leftovers.size();
        }
    }
}

package cn.sky.skylicense.resource;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.encrypt.BytecodeMutator;
import cn.sky.skylicense.encrypt.EncryptUtil;
import cn.sky.skylicense.netty.SessionManager;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

/** Loads protected plugin inputs and creates a fresh protocol-v4 payload per session. */
public final class ResourceManager {
    private static final byte[] RESOURCE_FORMAT_MAGIC =
            "SKYCLS04".getBytes(StandardCharsets.US_ASCII);
    private static final int METHOD_KEY_LENGTH = 32;
    private static final int MAX_SCAN_ENTRIES = 100_000;
    private static final int MAX_RESOURCE_FILES = 10_000;
    // The lock also covers the filesystem scan so a stale reload cannot
    // overwrite a concurrent upload or deletion.
    private static final Object UPDATE_LOCK = ResourceManager.class;
    private static volatile Map<String, Resource> resources = Map.of();

    private ResourceManager() {
    }

    public static boolean reloadResources(boolean isInfo) {
        return reloadResources(Paths.get("resources"), isInfo);
    }

    static synchronized boolean reloadResources(Path root, boolean isInfo) {
        return reloadResources(root, null, isInfo);
    }

    /** Reloads only resources referenced by the committed database catalog. */
    public static synchronized boolean reloadResources(
            Path root,
            List<CatalogEntry> catalog,
            boolean isInfo
    ) {
        Map<String, Resource> loaded;
        try {
            loaded = loadResources(root, catalog, isInfo, true);
        } catch (IOException | RuntimeException error) {
            SkyLicense.LOG.error("Unable to scan the resource directory", error);
            return false;
        }

        Set<String> revokedIdentifiers;
        synchronized (UPDATE_LOCK) {
            revokedIdentifiers = new HashSet<>();
            for (Map.Entry<String, Resource> entry : resources.entrySet()) {
                Resource replacement = loaded.get(entry.getKey());
                if (replacement == null
                        || !Objects.equals(
                        entry.getValue().getContentSha256(),
                        replacement.getContentSha256())) {
                    revokedIdentifiers.add(entry.getKey());
                }
            }
            resources = Collections.unmodifiableMap(new LinkedHashMap<>(loaded));
            rebuildPluginIndex(resources);
        }
        int revoked = SessionManager.revokeSessionsForResources(revokedIdentifiers);
        if (revoked > 0) {
            SkyLicense.LOG.info(
                    "Revoked {} sessions for resources removed or changed during reload", revoked);
        }
        if (loaded.isEmpty()) {
            SkyLicense.LOG.warn("Resource directory is empty");
        }
        return true;
    }

    /** Performs the complete resource scan without changing the active snapshot. */
    public static int validateResources(Path root) throws IOException {
        return loadResources(root, null, false, false).size();
    }

    /** Validates exactly the resources referenced by the committed catalog. */
    public static int validateResources(Path root, List<CatalogEntry> catalog)
            throws IOException {
        if (catalog == null) {
            throw new IllegalArgumentException("resource catalog is required");
        }
        return loadResources(root, catalog, false, false).size();
    }

    private static Map<String, Resource> loadResources(
            Path root,
            List<CatalogEntry> catalog,
            boolean logDetails,
            boolean createWhenMissing
    ) throws IOException {
        Path normalizedRoot = root.toAbsolutePath().normalize();
        if (createWhenMissing) {
            Files.createDirectories(normalizedRoot);
        } else if (!Files.exists(normalizedRoot, LinkOption.NOFOLLOW_LINKS)) {
            if (catalog != null && !catalog.isEmpty()) {
                throw new IOException("resource catalog is not empty but its directory is missing");
            }
            return Map.of();
        }
        if (!Files.isDirectory(normalizedRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("resource path must be a regular directory: " + normalizedRoot);
        }

        List<Path> resourceFiles = new ArrayList<>();
        int scannedEntries = 0;
        try (Stream<Path> paths = Files.walk(normalizedRoot)) {
            java.util.Iterator<Path> iterator = paths.iterator();
            while (iterator.hasNext()) {
                Path candidate = iterator.next();
                scannedEntries = Math.addExact(scannedEntries, 1);
                if (scannedEntries > MAX_SCAN_ENTRIES) {
                    throw new IOException("resource directory contains too many filesystem entries");
                }
                BasicFileAttributes attributes = Files.readAttributes(
                        candidate,
                        BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                if (Files.isSymbolicLink(candidate) || attributes.isOther()) {
                    throw new IOException(
                            "resource directory contains a link or reparse point: " + candidate);
                }
                if (attributes.isRegularFile()
                        && candidate.getFileName().toString().endsWith(".jar")) {
                    if (resourceFiles.size() >= MAX_RESOURCE_FILES) {
                        throw new IOException("resource directory contains too many JAR files");
                    }
                    resourceFiles.add(candidate.toAbsolutePath().normalize());
                }
            }
        } catch (ArithmeticException error) {
            throw new IOException("resource directory entry count overflow", error);
        }
        List<Path> filesToLoad = selectCatalogFiles(
                normalizedRoot, resourceFiles, catalog, logDetails);
        filesToLoad.sort(Path::compareTo);
        Map<Path, CatalogEntry> catalogByPath = catalogByPath(catalog);
        Map<String, Resource> loaded = new LinkedHashMap<>();
        for (Path path : filesToLoad) {
            Resource resource = Resource.fromJar(path.toFile(), logDetails);
            if (resource == null) {
                throw new IOException("resource JAR is invalid: " + path);
            }
            CatalogEntry expected = catalogByPath.get(path);
            if (expected != null
                    && (!expected.name().equals(resource.getEntryInfo().getName())
                    || !expected.version().equals(resource.getEntryInfo().getVersion()))) {
                throw new IOException(
                        "resource JAR identity does not match database catalog: " + path);
            }
            Resource duplicate = loaded.putIfAbsent(resource.getIdentifier(), resource);
            if (duplicate != null) {
                throw new IOException(
                        "duplicate resource Name/Version: "
                                + resource.getEntryInfo().getName() + " / "
                                + resource.getEntryInfo().getVersion());
            }
        }
        return loaded;
    }

    private static List<Path> selectCatalogFiles(
            Path root,
            List<Path> scannedFiles,
            List<CatalogEntry> catalog,
            boolean logDetails
    ) throws IOException {
        if (catalog == null) {
            return new ArrayList<>(scannedFiles);
        }
        if (catalog.size() > MAX_RESOURCE_FILES) {
            throw new IOException("resource catalog contains too many entries");
        }
        Map<Path, CatalogEntry> expected = catalogByPath(catalog);
        Set<Path> scanned = new HashSet<>(scannedFiles);
        for (Path path : expected.keySet()) {
            if (path.equals(root) || !path.startsWith(root)) {
                throw new IOException("catalog resource is outside the resource directory: " + path);
            }
            if (!scanned.contains(path)) {
                throw new IOException("catalog resource JAR is missing: " + path);
            }
        }
        if (logDetails && scanned.size() > expected.size()) {
            SkyLicense.LOG.warn(
                    "Ignoring {} unreferenced resource JAR files; startup recovery will quarantine them",
                    scanned.size() - expected.size());
        }
        return new ArrayList<>(expected.keySet());
    }

    private static Map<Path, CatalogEntry> catalogByPath(List<CatalogEntry> catalog)
            throws IOException {
        if (catalog == null) {
            return Map.of();
        }
        Map<Path, CatalogEntry> byPath = new LinkedHashMap<>();
        Set<String> identities = new HashSet<>();
        for (CatalogEntry entry : catalog) {
            if (entry == null || entry.name() == null || entry.version() == null
                    || entry.path() == null) {
                throw new IOException("resource catalog contains an incomplete entry");
            }
            Path path = entry.path().toAbsolutePath().normalize();
            CatalogEntry normalized = new CatalogEntry(entry.name(), entry.version(), path);
            if (byPath.putIfAbsent(path, normalized) != null) {
                throw new IOException("resource catalog contains a duplicate path: " + path);
            }
            String identity = identifier(entry.name(), entry.version());
            if (!identities.add(identity)) {
                throw new IOException(
                        "resource catalog contains a duplicate Name/Version: "
                                + entry.name() + " / " + entry.version());
            }
        }
        return byPath;
    }

    public static boolean installResource(Resource resource) {
        if (resource == null || resource.getIdentifier() == null) {
            throw new IllegalArgumentException("resource identity is required");
        }
        synchronized (UPDATE_LOCK) {
            if (resources.containsKey(resource.getIdentifier())) {
                return false;
            }
            Map<String, Resource> updated = new LinkedHashMap<>(resources);
            updated.put(resource.getIdentifier(), resource);
            resources = Collections.unmodifiableMap(updated);
            rebuildPluginIndex(resources);
            return true;
        }
    }

    public static void removeResource(String name, String version) {
        String identifier = identifier(name, version);
        synchronized (UPDATE_LOCK) {
            if (!resources.containsKey(identifier)) {
                return;
            }
            Map<String, Resource> updated = new LinkedHashMap<>(resources);
            updated.remove(identifier);
            resources = Collections.unmodifiableMap(updated);
            rebuildPluginIndex(resources);
        }
        int revoked = SessionManager.revokeSessionsForResource(name, version);
        if (revoked > 0) {
            SkyLicense.LOG.info(
                    "Revoked {} sessions for removed resource {}", revoked, identifier);
        }
    }

    public static String identifier(String name, String version) {
        if (name == null || version == null) {
            throw new IllegalArgumentException("resource name and version are required");
        }
        return name.length() + ":" + name + version.length() + ":" + version;
    }

    private static void rebuildPluginIndex(Map<String, Resource> current) {
        Map<String, List<String>> index = new LinkedHashMap<>();
        for (Resource resource : current.values()) {
            EntryInfo info = resource.getEntryInfo();
            index.computeIfAbsent(info.getName(), ignored -> new ArrayList<>())
                    .add(info.getVersion());
        }
        Map<String, List<String>> immutable = new LinkedHashMap<>();
        for (Entry<String, List<String>> entry : index.entrySet()) {
            immutable.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        PluginManager.plugins = Collections.unmodifiableMap(immutable);
    }

    public static boolean containsPlugin(String pluginIdentifier) {
        return pluginIdentifier != null && resources.containsKey(pluginIdentifier);
    }

    public static String currentContentSha256(String pluginIdentifier) {
        Resource resource = pluginIdentifier == null ? null : resources.get(pluginIdentifier);
        return resource == null ? null : resource.getContentSha256();
    }

    public static boolean contentMatches(String pluginIdentifier, String contentSha256) {
        return contentSha256 != null
                && Objects.equals(currentContentSha256(pluginIdentifier), contentSha256);
    }

    public static void writeString(ByteArrayOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.write(EncryptUtil.intToByteArray(bytes.length));
        output.write(bytes);
    }

    public static byte[] getPluginClasses(
            String pluginIdentifier,
            String className,
            String interfaceName,
            byte[] methodKey
    ) {
        GeneratedResource generated = getPluginClassesWithIdentity(
                pluginIdentifier, className, interfaceName, methodKey);
        return generated == null ? null : generated.payload();
    }

    public static GeneratedResource getPluginClassesWithIdentity(
            String pluginIdentifier,
            String className,
            String interfaceName,
            byte[] methodKey
    ) {
        if (methodKey == null || methodKey.length != METHOD_KEY_LENGTH) {
            throw new IllegalArgumentException("method key must contain 32 bytes");
        }
        Resource resource = resources.get(pluginIdentifier);
        if (resource == null) {
            return null;
        }
        List<ByteCode> byteCodes = resource.getByteCodes();
        EntryInfo entryInfo = resource.getEntryInfo();
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try {
            output.write(RESOURCE_FORMAT_MAGIC);
            output.write(EncryptUtil.intToByteArray(byteCodes.size()));
            Map<String, MethodInfo> methodMap = new HashMap<>();

            for (ByteCode byteCode : byteCodes) {
                writeString(output, byteCode.getClassName());
                byte[] transformedClass = byteCode.isKeep()
                        ? byteCode.getCode().clone()
                        : EncryptUtil.encryptClass(
                                entryInfo.getName(),
                                byteCode.getCode(),
                                methodMap,
                                methodKey,
                                className,
                                interfaceName);
                byte[] modifiedClass = null;
                byte[] compressed = null;
                try {
                    // KeepClasses is the compatibility escape hatch for reflection-sensitive code.
                    modifiedClass = byteCode.isKeep()
                            ? transformedClass
                            : BytecodeMutator.mutate(transformedClass);
                    compressed = EncryptUtil.compress(modifiedClass);
                    output.write(EncryptUtil.intToByteArray(modifiedClass.length));
                    output.write(EncryptUtil.intToByteArray(compressed.length));
                    output.write(compressed);
                } finally {
                    Arrays.fill(transformedClass, (byte) 0);
                    if (modifiedClass != null && modifiedClass != transformedClass) {
                        Arrays.fill(modifiedClass, (byte) 0);
                    }
                    if (compressed != null) {
                        Arrays.fill(compressed, (byte) 0);
                    }
                }
            }

            writeString(output, entryInfo.getEntryClass());
            writeString(output, entryInfo.getEntryPoint());
            output.write(EncryptUtil.intToByteArray(methodMap.size()));
            for (Entry<String, MethodInfo> entry : methodMap.entrySet()) {
                writeString(output, entry.getKey());
                writeString(output, entry.getValue().getClassName());
                writeString(output, entry.getValue().getMethodName());
                writeString(output, entry.getValue().getMethodDesc());
            }
            return new GeneratedResource(output.toByteArray(), resource.getContentSha256());
        } catch (Exception error) {
            SkyLicense.LOG.error("Plugin class writing failed for " + pluginIdentifier, error);
            return null;
        }
    }

    public record GeneratedResource(byte[] payload, String contentSha256) {
        public GeneratedResource {
            if (payload == null || payload.length == 0
                    || contentSha256 == null || contentSha256.length() != 64) {
                throw new IllegalArgumentException("generated resource identity is invalid");
            }
        }
    }

    public record CatalogEntry(String name, String version, Path path) {
    }

}

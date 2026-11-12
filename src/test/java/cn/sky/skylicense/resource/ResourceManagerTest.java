package cn.sky.skylicense.resource;

import cn.sky.skylicense.netty.SessionManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResourceManagerTest {
    @TempDir
    Path temporaryDirectory;

    @BeforeEach
    void prepareSessionLifecycle() {
        SessionManager.destroyAllSessions();
        SessionManager.beginStartup();
    }

    @AfterEach
    void clearGlobalResourceState() {
        assertTrue(ResourceManager.reloadResources(
                temporaryDirectory.resolve("empty"), false));
        SessionManager.destroyAllSessions();
        SessionManager.beginStartup();
    }

    @Test
    void invalidOrDuplicateReloadPreservesThePreviousCompleteSnapshot() throws Exception {
        Path resources = temporaryDirectory.resolve("resources");
        Files.createDirectories(resources);
        writeResource(resources.resolve("stable.jar"), "Stable", "1.0.0");

        assertTrue(ResourceManager.reloadResources(resources, false));
        String stableId = ResourceManager.identifier("Stable", "1.0.0");
        assertTrue(ResourceManager.containsPlugin(stableId));

        Files.writeString(
                resources.resolve("invalid.jar"),
                "not a jar",
                StandardCharsets.UTF_8);
        assertFalse(ResourceManager.reloadResources(resources, false));
        assertTrue(ResourceManager.containsPlugin(stableId));

        Files.delete(resources.resolve("invalid.jar"));
        writeResource(resources.resolve("duplicate.jar"), "Stable", "1.0.0");
        assertFalse(ResourceManager.reloadResources(resources, false));
        assertTrue(ResourceManager.containsPlugin(stableId));
    }

    @Test
    void lengthPrefixedIdentifiersCannotCollideByConcatenation() {
        assertNotEquals(
                ResourceManager.identifier("AB", "C"),
                ResourceManager.identifier("A", "BC"));
    }

    @Test
    void keepClassesAreDeliveredWithoutMethodEncryptionOrMutation() throws Exception {
        Path resources = temporaryDirectory.resolve("kept-resources");
        Files.createDirectories(resources);
        byte[] original = writeResource(resources.resolve("kept.jar"), "Kept", "1.0.0", true);
        assertTrue(ResourceManager.reloadResources(resources, false));

        byte[] payload = ResourceManager.getPluginClasses(
                ResourceManager.identifier("Kept", "1.0.0"),
                "cn/sky/license/SkyLicense",
                "cn/sky/license/SkyLicense$IAuthLib",
                new byte[32]);
        ByteBuffer input = ByteBuffer.wrap(payload);
        byte[] magic = new byte[8];
        input.get(magic);
        assertArrayEquals("SKYCLS04".getBytes(StandardCharsets.US_ASCII), magic);
        assertEquals(1, input.getInt());
        readString(input);
        int originalLength = input.getInt();
        int compressedLength = input.getInt();
        byte[] compressed = new byte[compressedLength];
        input.get(compressed);
        byte[] delivered;
        try (GZIPInputStream gzip = new GZIPInputStream(
                new java.io.ByteArrayInputStream(compressed))) {
            delivered = gzip.readAllBytes();
        }
        assertEquals(originalLength, delivered.length);
        assertArrayEquals(original, delivered);
    }

    @Test
    void resourceWithoutAValidStaticEntryPointIsRejected() throws Exception {
        Path resources = temporaryDirectory.resolve("invalid-entry-resources");
        Files.createDirectories(resources);
        writeResource(
                resources.resolve("invalid-entry.jar"),
                "InvalidEntry",
                "1.0.0",
                false,
                "missingEntryPoint");

        assertFalse(ResourceManager.reloadResources(resources, false));
    }

    @Test
    void removingResourceImmediatelyRevokesMatchingVersionSession() throws Exception {
        Path resources = temporaryDirectory.resolve("revoked-resources");
        Files.createDirectories(resources);
        writeResource(resources.resolve("stable.jar"), "Stable", "1.0.0");
        assertTrue(ResourceManager.reloadResources(resources, false));

        byte[] sessionId = filled(71);
        assertTrue(SessionManager.registerSession(
                sessionId,
                "127.0.0.1",
                "license",
                "Stable",
                "1.0.0",
                filled(72),
                "hwid",
                1,
                filled(73)));

        ResourceManager.removeResource("Stable", "1.0.0");

        SessionManager.SessionInfo session = SessionManager.getSession(sessionId);
        assertTrue(session != null && session.isRevoked());
    }

    @Test
    void unchangedReloadKeepsSessionButContentReplacementRevokesIt() throws Exception {
        Path resources = temporaryDirectory.resolve("changed-resources");
        Files.createDirectories(resources);
        Path artifact = resources.resolve("stable.jar");
        writeResource(artifact, "Stable", "1.0.0", false);
        assertTrue(ResourceManager.reloadResources(resources, false));

        byte[] sessionId = filled(74);
        assertTrue(SessionManager.registerSession(
                sessionId,
                "127.0.0.1",
                "license",
                "Stable",
                "1.0.0",
                filled(75),
                "hwid",
                1,
                filled(76)));
        SessionManager.SessionInfo session = SessionManager.getSession(sessionId);

        assertTrue(ResourceManager.reloadResources(resources, false));
        assertTrue(session != null && !session.isRevoked());

        writeResource(artifact, "Stable", "1.0.0", true);
        assertTrue(ResourceManager.reloadResources(resources, false));
        assertTrue(session != null && session.isRevoked());
    }

    @Test
    void generatedPayloadIdentityChangesWithResourceContent() throws Exception {
        Path resources = temporaryDirectory.resolve("identity-resources");
        Files.createDirectories(resources);
        Path artifact = resources.resolve("stable.jar");
        writeResource(artifact, "Stable", "1.0.0", false);
        assertTrue(ResourceManager.reloadResources(resources, false));

        String identifier = ResourceManager.identifier("Stable", "1.0.0");
        ResourceManager.GeneratedResource first = ResourceManager.getPluginClassesWithIdentity(
                identifier,
                "cn/sky/license/SkyLicense",
                "cn/sky/license/SkyLicense$IAuthLib",
                new byte[32]);
        assertTrue(first != null);
        assertEquals(ResourceManager.currentContentSha256(identifier), first.contentSha256());
        assertTrue(ResourceManager.contentMatches(identifier, first.contentSha256()));

        writeResource(artifact, "Stable", "1.0.0", true);
        assertTrue(ResourceManager.reloadResources(resources, false));

        assertNotEquals(first.contentSha256(), ResourceManager.currentContentSha256(identifier));
        assertFalse(ResourceManager.contentMatches(identifier, first.contentSha256()));
        assertTrue(ResourceManager.contentMatches(
                identifier, ResourceManager.currentContentSha256(identifier)));
    }

    private static byte[] filled(int value) {
        byte[] bytes = new byte[32];
        java.util.Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    public static void run() {
        // Valid no-op entry point used by generated test resource JARs.
    }

    private static void writeResource(Path output, String name, String version) throws Exception {
        writeResource(output, name, version, false);
    }

    private static byte[] writeResource(
            Path output,
            String name,
            String version,
            boolean keep
    ) throws Exception {
        return writeResource(output, name, version, keep, "run");
    }

    private static byte[] writeResource(
            Path output,
            String name,
            String version,
            boolean keep,
            String entryPoint
    ) throws Exception {
        String className = ResourceManagerTest.class.getName();
        String classEntry = className.replace('.', '/') + ".class";
        byte[] classBytes;
        try (InputStream input = ResourceManagerTest.class.getClassLoader()
                .getResourceAsStream(classEntry)) {
            classBytes = input.readAllBytes();
        }
        String profile = "Name: " + name + "\n"
                + "Version: " + version + "\n"
                + "EntryClass: " + className + "\n"
                + "EntryPoint: " + entryPoint + "\n"
                + "InfPort: false\n"
                + (keep ? "KeepClasses:\n  - \"[\\\\s\\\\S]*\"\n" : "");
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(output))) {
            jar.putNextEntry(new JarEntry("settings.yml"));
            jar.write(profile.getBytes(StandardCharsets.UTF_8));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry(classEntry));
            jar.write(classBytes);
            jar.closeEntry();
        }
        return classBytes;
    }

    private static String readString(ByteBuffer input) {
        byte[] bytes = new byte[input.getInt()];
        input.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }
}

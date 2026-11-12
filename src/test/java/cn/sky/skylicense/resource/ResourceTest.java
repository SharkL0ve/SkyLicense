package cn.sky.skylicense.resource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResourceTest {
    @TempDir
    Path temporaryDirectory;

    public static void run() {
        // Valid no-op entry point used by the accepted resource fixture.
    }

    @Test
    void boundedJarWithMatchingClassAndProfileIsAccepted() throws Exception {
        String className = ResourceTest.class.getName();
        String classEntry = className.replace('.', '/') + ".class";
        byte[] classBytes;
        try (InputStream input = ResourceTest.class.getClassLoader()
                .getResourceAsStream(classEntry)) {
            classBytes = input.readAllBytes();
        }
        String profile = "Name: TestPlugin\n"
                + "Version: 1.0.0\n"
                + "EntryClass: " + className + "\n"
                + "EntryPoint: run\n"
                + "InfPort: false\n"
                + "KeepClasses:\n"
                + "  - \"[\\\\s\\\\S]*\"\n";
        Path jar = writeJar(profile.getBytes(StandardCharsets.UTF_8), classEntry, classBytes);

        Resource resource = Resource.fromJar(jar.toFile(), false);

        assertEquals(
                ResourceManager.identifier("TestPlugin", "1.0.0"),
                resource.getIdentifier());
        assertEquals(1, resource.getByteCodes().size());
        assertTrue(resource.getByteCodes().get(0).isKeep());
    }

    @Test
    void oversizedProfileAndMismatchedClassNameAreRejected() throws Exception {
        byte[] oversizedProfile = new byte[64 * 1024 + 1];
        Arrays.fill(oversizedProfile, (byte) 'A');
        assertNull(Resource.fromJar(
                writeJar(oversizedProfile, null, null).toFile(), false));

        String classEntry = ResourceTest.class.getName().replace('.', '/') + ".class";
        byte[] classBytes;
        try (InputStream input = ResourceTest.class.getClassLoader()
                .getResourceAsStream(classEntry)) {
            classBytes = input.readAllBytes();
        }
        String profile = "Name: TestPlugin\nVersion: 1\nEntryClass: test.Main\nEntryPoint: run\n";
        assertNull(Resource.fromJar(
                writeJar(
                        profile.getBytes(StandardCharsets.UTF_8),
                        "different/Name.class",
                        classBytes).toFile(),
                false));
    }

    @Test
    void protocolUnsafeResourceIdentityIsRejected() throws Exception {
        String className = ResourceTest.class.getName();
        String classEntry = className.replace('.', '/') + ".class";
        byte[] classBytes;
        try (InputStream input = ResourceTest.class.getClassLoader()
                .getResourceAsStream(classEntry)) {
            classBytes = input.readAllBytes();
        }
        String profile = "Name: Unsafe@Plugin\n"
                + "Version: 1.0.0\n"
                + "EntryClass: " + className + "\n"
                + "EntryPoint: run\n";

        assertNull(Resource.fromJar(
                writeJar(profile.getBytes(StandardCharsets.UTF_8), classEntry, classBytes)
                        .toFile(),
                false));
    }

    private Path writeJar(byte[] profile, String classEntry, byte[] classBytes) throws Exception {
        Path output = Files.createTempFile(temporaryDirectory, "resource-", ".jar");
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(output))) {
            jar.putNextEntry(new JarEntry("settings.yml"));
            jar.write(profile);
            jar.closeEntry();
            if (classEntry != null) {
                jar.putNextEntry(new JarEntry(classEntry));
                jar.write(classBytes);
                jar.closeEntry();
            }
        }
        return output;
    }
}

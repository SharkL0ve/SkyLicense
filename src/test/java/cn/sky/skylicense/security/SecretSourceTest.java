package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretSourceTest {
    private static final String NAME = "SKYLICENSE_TEST_SECRET";

    @TempDir
    Path temporaryDirectory;

    @Test
    void readsDirectValueOrReportsAnAbsentOptionalValue() {
        assertNull(SecretSource.readOptional(NAME, 64, key -> null));
        assertEquals("direct-secret", SecretSource.readOptional(
                NAME, 64, Map.of(NAME, "direct-secret")::get));
    }

    @Test
    void rejectsAmbiguousAndUnsafeDirectValues() {
        Map<String, String> ambiguous = Map.of(
                NAME, "direct",
                NAME + "_FILE", temporaryDirectory.resolve("secret").toString());
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(NAME, 64, ambiguous::get));
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(
                        NAME, 64, Map.of(NAME, "line-one\nline-two")::get));
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(NAME, 4, Map.of(NAME, "12345")::get));
    }

    @Test
    void readsOwnerOnlyUtf8FileAndRemovesOneTerminalLineEnding() throws Exception {
        Path file = privateFile("secret.txt", "sensitive-value\r\n".getBytes(StandardCharsets.UTF_8));
        Map<String, String> environment = Map.of(NAME + "_FILE", file.toString());

        assertEquals(
                "sensitive-value",
                SecretSource.readOptional(NAME, 64, environment::get));
        assertEquals(file.normalize(), SecretSource.configuredFilePath(NAME, environment::get));
    }

    @Test
    void rejectsRelativeMultilineMalformedAndOversizedFiles() throws Exception {
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(
                        NAME, 64, Map.of(NAME + "_FILE", "relative-secret.txt")::get));

        Path multiline = privateFile(
                "multiline.txt", "one\ntwo\n".getBytes(StandardCharsets.UTF_8));
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(
                        NAME, 64, Map.of(NAME + "_FILE", multiline.toString())::get));

        Path malformed = privateFile("malformed.txt", new byte[]{(byte) 0xc3, (byte) 0x28});
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(
                        NAME, 64, Map.of(NAME + "_FILE", malformed.toString())::get));

        Path oversized = privateFile("oversized.txt", "1234567\n".getBytes(StandardCharsets.UTF_8));
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(
                        NAME, 4, Map.of(NAME + "_FILE", oversized.toString())::get));
    }

    @Test
    void rejectsCredentialSymlinksWhenThePlatformCanCreateThem() throws Exception {
        Path target = privateFile("target.txt", "secret".getBytes(StandardCharsets.UTF_8));
        Path link = temporaryDirectory.resolve("secret-link.txt");
        try {
            Files.createSymbolicLink(link, target);
        } catch (UnsupportedOperationException | IOException | SecurityException unavailable) {
            return;
        }

        IllegalStateException error = assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(
                        NAME, 64, Map.of(NAME + "_FILE", link.toString())::get));
        assertTrue(error.getMessage().contains("FILE")
                || error.getCause() != null);
    }

    @Test
    void rejectsFileWithNonOwnerPermissionsWhenPosixPermissionsAreAvailable() throws Exception {
        Path file = privateFile("permissions.txt", "secret".getBytes(StandardCharsets.UTF_8));
        if (Files.getFileAttributeView(
                file, java.nio.file.attribute.PosixFileAttributeView.class) == null) {
            return;
        }
        Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r-----"));

        Map<String, String> environment = new HashMap<>();
        environment.put(NAME + "_FILE", file.toString());
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(NAME, 64, environment::get));
    }

    private Path privateFile(String name, byte[] content) throws IOException {
        Path file = temporaryDirectory.resolve(name).toAbsolutePath();
        Files.write(file, content);
        SecureFiles.makePrivateReadOnly(file);
        return file;
    }
}

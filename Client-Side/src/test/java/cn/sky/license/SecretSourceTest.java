package cn.sky.license;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecretSourceTest {
    private static final String NAME = "SKYLICENSE_LICENSE_FILE_SECRET";

    @TempDir
    Path temporaryDirectory;

    @Test
    void resolvesDirectAndOwnerOnlyFileForms() throws Exception {
        assertNull(SecretSource.readOptional(NAME, 128, key -> null));

        Map<String, String> direct = new HashMap<>();
        direct.put(NAME, "direct-value");
        assertEquals("direct-value", SecretSource.readOptional(NAME, 128, direct::get));

        Path file = privateFile("secret.txt", "file-value\n".getBytes(StandardCharsets.UTF_8));
        Map<String, String> fromFile = new HashMap<>();
        fromFile.put(NAME + "_FILE", file.toString());
        assertEquals("file-value", SecretSource.readOptional(NAME, 128, fromFile::get));
    }

    @Test
    void rejectsAmbiguousRelativeMultilineAndMalformedSources() throws Exception {
        Map<String, String> ambiguous = new HashMap<>();
        ambiguous.put(NAME, "direct");
        ambiguous.put(NAME + "_FILE", temporaryDirectory.resolve("secret.txt").toString());
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(NAME, 128, ambiguous::get));

        Map<String, String> relative = new HashMap<>();
        relative.put(NAME + "_FILE", "secret.txt");
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(NAME, 128, relative::get));

        Path multiline = privateFile(
                "multiline.txt", "first\nsecond\n".getBytes(StandardCharsets.UTF_8));
        Map<String, String> multilineEnvironment = new HashMap<>();
        multilineEnvironment.put(NAME + "_FILE", multiline.toString());
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(NAME, 128, multilineEnvironment::get));

        Path malformed = privateFile("malformed.txt", new byte[]{(byte) 0xc3, (byte) 0x28});
        Map<String, String> malformedEnvironment = new HashMap<>();
        malformedEnvironment.put(NAME + "_FILE", malformed.toString());
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(NAME, 128, malformedEnvironment::get));
    }

    @Test
    void rejectsCredentialSymlinkWhenSupported() throws Exception {
        Path target = privateFile("target.txt", "secret".getBytes(StandardCharsets.UTF_8));
        Path link = temporaryDirectory.resolve("link.txt");
        try {
            Files.createSymbolicLink(link, target);
        } catch (UnsupportedOperationException | IOException | SecurityException unavailable) {
            return;
        }
        Map<String, String> environment = new HashMap<>();
        environment.put(NAME + "_FILE", link.toString());
        assertThrows(
                IllegalStateException.class,
                () -> SecretSource.readOptional(NAME, 128, environment::get));
    }

    private Path privateFile(String name, byte[] content) throws IOException {
        Path file = temporaryDirectory.resolve(name).toAbsolutePath();
        Files.write(file, content);
        PosixFileAttributeView posix = Files.getFileAttributeView(
                file, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            Files.setPosixFilePermissions(
                    file,
                    EnumSet.of(PosixFilePermission.OWNER_READ));
            return file;
        }

        AclFileAttributeView acl = Files.getFileAttributeView(
                file, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl != null) {
            UserPrincipal owner = Files.getOwner(file, LinkOption.NOFOLLOW_LINKS);
            AclEntry ownerEntry = AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(owner)
                    .setPermissions(EnumSet.of(
                            AclEntryPermission.READ_DATA,
                            AclEntryPermission.READ_ATTRIBUTES,
                            AclEntryPermission.READ_NAMED_ATTRS,
                            AclEntryPermission.READ_ACL,
                            AclEntryPermission.SYNCHRONIZE,
                            AclEntryPermission.DELETE))
                    .build();
            acl.setAcl(Collections.singletonList(ownerEntry));
            return file;
        }

        if (!file.toFile().setReadable(false, false)
                || !file.toFile().setWritable(false, false)
                || !file.toFile().setReadable(true, true)) {
            throw new IOException("unable to restrict test credential file");
        }
        return file;
    }
}

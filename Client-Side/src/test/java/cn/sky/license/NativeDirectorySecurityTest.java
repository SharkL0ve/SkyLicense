package cn.sky.license;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeDirectorySecurityTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void extractedNativeDirectoryIsRestrictedToItsOwner() throws Exception {
        Path directory = SkyLicense.prepareNativeDirectory(temporaryDirectory.resolve("data"));

        assertTrue(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS));
        assertFalse(Files.isSymbolicLink(directory));

        PosixFileAttributeView posix = Files.getFileAttributeView(
                directory, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            Set<PosixFilePermission> expected = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE);
            assertEquals(expected, Files.getPosixFilePermissions(
                    directory, LinkOption.NOFOLLOW_LINKS));
            return;
        }

        AclFileAttributeView acl = Files.getFileAttributeView(
                directory, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl != null) {
            List<AclEntry> entries = acl.getAcl();
            assertEquals(1, entries.size());
            assertEquals(AclEntryType.ALLOW, entries.get(0).type());
            assertEquals(Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS),
                    entries.get(0).principal());
        }
    }
}

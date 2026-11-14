package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecureFilesTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void canonicalizesExistingFilesAndMissingChildren() throws Exception {
        Path existing = Files.createFile(temporaryDirectory.resolve("fixture.txt"));
        assertEquals(existing.toRealPath(LinkOption.NOFOLLOW_LINKS),
                SecureFiles.canonicalPath(existing));
        assertEquals(temporaryDirectory.toRealPath(LinkOption.NOFOLLOW_LINKS)
                        .resolve("missing/child.txt"),
                SecureFiles.canonicalPath(temporaryDirectory.resolve("missing/child.txt")));
    }

    @Test
    void aclValidationRejectsAnyNonOwnerAllowPrincipal() {
        UserPrincipal owner = () -> "owner";
        UserPrincipal other = () -> "other";
        AclEntry ownerAllow = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .build();
        AclEntry otherAllow = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(other)
                .build();
        AclEntry otherDeny = AclEntry.newBuilder()
                .setType(AclEntryType.DENY)
                .setPrincipal(other)
                .build();

        assertDoesNotThrow(() -> SecureFiles.validateOwnerOnlyAcl(
                owner, List.of(ownerAllow, otherDeny), "fixture", Path.of("fixture")));
        assertThrows(java.io.IOException.class, () -> SecureFiles.validateOwnerOnlyAcl(
                owner, List.of(ownerAllow, otherAllow), "fixture", Path.of("fixture")));
    }
}

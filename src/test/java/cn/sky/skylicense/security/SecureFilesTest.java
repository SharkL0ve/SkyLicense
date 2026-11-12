package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecureFilesTest {
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

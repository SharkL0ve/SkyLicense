package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeploymentLockTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void excludesConcurrentOwnersAndCanBeReacquiredAfterClose() throws Exception {
        SecureFiles.preparePrivateDirectory(temporaryDirectory);
        Path lockPath = temporaryDirectory.toRealPath(java.nio.file.LinkOption.NOFOLLOW_LINKS)
                .resolve(DeploymentLock.FILE_NAME);

        try (DeploymentLock first = DeploymentLock.acquire(temporaryDirectory)) {
            assertEquals(lockPath, first.path());
            assertTrue(Files.isRegularFile(lockPath));
            assertDoesNotThrow(() -> SecureFiles.requireOwnerOnly(
                    lockPath, false, "deployment lock"));
            assertThrows(IOException.class, () -> DeploymentLock.acquire(temporaryDirectory));
        }

        assertDoesNotThrow(() -> {
            try (DeploymentLock second = DeploymentLock.acquire(temporaryDirectory)) {
                assertEquals(lockPath, second.path());
            }
        });
    }
}

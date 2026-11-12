package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResourceFileStoreTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void quarantineMovesArtifactOutsideScannedTreeAndCanRestoreIt() throws Exception {
        Path base = SecureFiles.preparePrivateDirectory(
                temporaryDirectory.resolve("resources"));
        Path directory = SecureFiles.preparePrivateDirectory(base.resolve("1").resolve("2"));
        Path artifact = directory.resolve("resource.jar");
        Files.writeString(artifact, "protected", StandardCharsets.UTF_8);

        ResourceFileStore.QuarantinedFile moved =
                ResourceFileStore.quarantine(base, artifact);

        assertTrue(moved.moved());
        assertFalse(Files.exists(artifact));
        assertTrue(Files.isRegularFile(moved.quarantined()));
        assertFalse(moved.quarantined().startsWith(base.toAbsolutePath().normalize()));

        ResourceFileStore.restore(moved);
        assertTrue(Files.isRegularFile(artifact));
        assertFalse(Files.exists(moved.quarantined()));
    }

    @Test
    void discardedQuarantineCannotBeSeenAtOriginalPath() throws Exception {
        Path base = SecureFiles.preparePrivateDirectory(
                temporaryDirectory.resolve("resources"));
        Path artifact = base.resolve("resource.jar");
        Files.writeString(artifact, "protected", StandardCharsets.UTF_8);

        ResourceFileStore.QuarantinedFile moved =
                ResourceFileStore.quarantine(base, artifact);
        ResourceFileStore.discard(moved);

        assertFalse(Files.exists(artifact));
        assertFalse(Files.exists(moved.quarantined()));
    }

    @Test
    void artifactOutsideResourceTreeIsRejectedWithoutChangingIt() throws Exception {
        Path base = SecureFiles.preparePrivateDirectory(
                temporaryDirectory.resolve("resources"));
        Path outside = temporaryDirectory.resolve("outside.jar");
        Files.writeString(outside, "protected", StandardCharsets.UTF_8);

        assertThrows(
                java.io.IOException.class,
                () -> ResourceFileStore.quarantine(base, outside));
        assertTrue(Files.isRegularFile(outside));
    }
}

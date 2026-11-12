package cn.sky.skylicense.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Moves resource artifacts out of the scanned directory before a database
 * deletion. A failed database operation can restore the move; a successful
 * operation cannot be resurrected by a later resource reload.
 */
public final class ResourceFileStore {
    private static final String QUARANTINE_SUFFIX = ".quarantine";

    private ResourceFileStore() {
    }

    public static QuarantinedFile quarantine(Path resourceBase, Path original)
            throws IOException {
        Path base = normalizeBase(resourceBase);
        Path source = normalizePath(original);
        validateUnderBase(base, source);
        if (!Files.exists(source, LinkOption.NOFOLLOW_LINKS)) {
            return new QuarantinedFile(base, source, null);
        }
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("resource artifact is not a regular file: " + source);
        }

        Path quarantineRoot = quarantineRoot(base);
        SecureFiles.preparePrivateDirectory(quarantineRoot);
        Path destination;
        do {
            destination = quarantineRoot.resolve(UUID.randomUUID() + ".jar");
        } while (Files.exists(destination, LinkOption.NOFOLLOW_LINKS));
        SecureFiles.atomicMoveNoReplace(source, destination);
        return new QuarantinedFile(base, source, destination);
    }

    public static void restore(QuarantinedFile artifact) throws IOException {
        if (artifact == null || !artifact.moved()) {
            return;
        }
        Path parent = artifact.original().getParent();
        if (parent == null) {
            throw new IOException("resource artifact has no parent directory");
        }
        SecureFiles.preparePrivateDirectory(parent);
        SecureFiles.atomicMoveNoReplace(artifact.quarantined(), artifact.original());
    }

    public static void discard(QuarantinedFile artifact) throws IOException {
        if (artifact == null || !artifact.moved()) {
            return;
        }
        SecureFiles.deleteFileUnder(quarantineRoot(artifact.base()), artifact.quarantined());
    }

    /** Deletes an artifact only after its database catalog entry has committed away. */
    public static boolean deleteCommitted(Path resourceBase, Path artifact) throws IOException {
        Path base = normalizeBase(resourceBase);
        Path target = normalizePath(artifact);
        validateUnderBase(base, target);
        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("resource artifact is not a regular file: " + target);
        }
        return SecureFiles.deleteFileUnder(base, target);
    }

    private static Path normalizeBase(Path base) throws IOException {
        if (base == null) {
            throw new IOException("resource base directory is required");
        }
        Path normalized = base.toAbsolutePath().normalize();
        if (normalized.getFileName() == null || normalized.getParent() == null) {
            throw new IOException("resource base directory is invalid");
        }
        return normalized;
    }

    private static Path normalizePath(Path path) throws IOException {
        if (path == null) {
            throw new IOException("resource artifact path is required");
        }
        return path.toAbsolutePath().normalize();
    }

    private static void validateUnderBase(Path base, Path candidate) throws IOException {
        if (candidate.equals(base) || !candidate.startsWith(base)) {
            throw new IOException("resource artifact is outside the resource directory");
        }
    }

    private static Path quarantineRoot(Path base) {
        return base.resolveSibling(base.getFileName() + QUARANTINE_SUFFIX);
    }

    public record QuarantinedFile(Path base, Path original, Path quarantined) {
        public boolean moved() {
            return quarantined != null;
        }
    }
}

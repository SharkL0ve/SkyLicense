package cn.sky.skylicense.security;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.ArrayDeque;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** Owner-only file operations used for uploaded protected resources. */
public final class SecureFiles {
    private SecureFiles() {
    }

    /** Resolves existing Windows 8.3 aliases without accepting links or reparse points. */
    public static Path canonicalPath(Path path) throws IOException {
        Path normalized = path.toAbsolutePath().normalize();
        rejectLinkComponents(normalized);
        ArrayDeque<Path> missing = new ArrayDeque<>();
        Path existing = normalized;
        while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            missing.push(existing.getFileName());
            existing = existing.getParent();
            if (existing == null) {
                throw new IOException("path has no existing ancestor: " + normalized);
            }
        }
        Path canonical = existing.toRealPath(LinkOption.NOFOLLOW_LINKS);
        while (!missing.isEmpty()) {
            canonical = canonical.resolve(missing.pop());
        }
        return canonical;
    }

    public static Path preparePrivateDirectory(Path directory) throws IOException {
        Path normalized = directory.toAbsolutePath().normalize();
        rejectLinkComponents(normalized);
        Files.createDirectories(normalized);
        rejectLinkComponents(normalized);
        restrictOwnerOnly(normalized, true, true, true);
        return normalized;
    }

    public static Path createPrivateTempFile(
            Path directory,
            String prefix,
            String suffix
    ) throws IOException {
        Path temporary = Files.createTempFile(directory, prefix, suffix);
        try {
            restrictOwnerOnly(temporary, true, false, false);
            return temporary;
        } catch (IOException error) {
            Files.deleteIfExists(temporary);
            throw error;
        }
    }

    public static void makePrivateReadOnly(Path file) throws IOException {
        rejectLink(file);
        restrictOwnerOnly(file, false, false, false);
    }

    /** Restricts an existing database/file to its owning service account. */
    public static void makePrivateReadWrite(Path file) throws IOException {
        rejectLink(file);
        restrictOwnerOnly(file, true, false, false);
    }

    /** Fails closed when a sensitive path is readable through a group or another account. */
    public static void requireOwnerOnly(Path path, boolean directory, String label)
            throws IOException {
        rejectLink(path);
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            Set<PosixFilePermission> allowed = directory
                    ? EnumSet.of(
                            PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE,
                            PosixFilePermission.OWNER_EXECUTE)
                    : EnumSet.of(
                            PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE);
            EnumSet<PosixFilePermission> unexpected = EnumSet.noneOf(PosixFilePermission.class);
            unexpected.addAll(posix.readAttributes().permissions());
            unexpected.removeAll(allowed);
            if (!unexpected.isEmpty()) {
                throw new IOException(
                        label + " grants group/other permissions; expected owner-only access: "
                                + path);
            }
            return;
        }

        AclFileAttributeView acl = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl == null) {
            throw new IOException("owner-only ACLs are unavailable for " + path);
        }
        validateOwnerOnlyAcl(Files.getOwner(path, LinkOption.NOFOLLOW_LINKS), acl.getAcl(), label, path);
    }

    static void validateOwnerOnlyAcl(
            UserPrincipal owner,
            List<AclEntry> entries,
            String label,
            Path path
    ) throws IOException {
        if (owner == null || owner instanceof GroupPrincipal) {
            throw new IOException(label + " must be owned by a user account: " + path);
        }
        boolean ownerAllow = false;
        for (AclEntry entry : entries) {
            if (entry.type() != AclEntryType.ALLOW) {
                continue;
            }
            if (!owner.equals(entry.principal())) {
                throw new IOException(
                        label + " grants access to a non-owner ACL principal: " + path);
            }
            ownerAllow = true;
        }
        if (!ownerAllow) {
            throw new IOException(label + " has no owner allow entry: " + path);
        }
    }

    public static boolean deleteFileUnder(Path baseDirectory, Path candidate) throws IOException {
        Path base = baseDirectory.toAbsolutePath().normalize();
        Path target = candidate.toAbsolutePath().normalize();
        if (!target.startsWith(base) || target.equals(base)) {
            throw new IOException("refusing to delete a path outside the resource directory");
        }
        rejectLinkComponents(target);
        return Files.deleteIfExists(target);
    }

    public static void atomicMoveNoReplace(Path source, Path destination) throws IOException {
        rejectLink(source);
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("destination already exists");
        }
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source, destination);
        }
    }

    private static void rejectLinkComponents(Path path) throws IOException {
        Path current = path.getRoot();
        for (Path component : path) {
            current = current == null ? component : current.resolve(component);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                rejectLink(current);
            }
        }
    }

    private static void rejectLink(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(
                path,
                BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (Files.isSymbolicLink(path) || attributes.isOther()) {
            throw new IOException("symbolic link or reparse point is not allowed: " + path);
        }
    }

    private static void restrictOwnerOnly(
            Path path,
            boolean writable,
            boolean executable,
            boolean directory
    ) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path,
                PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            EnumSet<PosixFilePermission> permissions = EnumSet.of(PosixFilePermission.OWNER_READ);
            if (writable) {
                permissions.add(PosixFilePermission.OWNER_WRITE);
            }
            if (executable || directory) {
                permissions.add(PosixFilePermission.OWNER_EXECUTE);
            }
            Files.setPosixFilePermissions(path, permissions);
            return;
        }

        AclFileAttributeView acl = Files.getFileAttributeView(
                path,
                AclFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (acl == null) {
            throw new IOException("owner-only ACLs are unavailable for " + path);
        }
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        EnumSet<AclEntryPermission> permissions = EnumSet.of(
                AclEntryPermission.READ_DATA,
                AclEntryPermission.READ_ATTRIBUTES,
                AclEntryPermission.READ_NAMED_ATTRS,
                AclEntryPermission.READ_ACL,
                AclEntryPermission.SYNCHRONIZE,
                AclEntryPermission.DELETE);
        if (writable) {
            permissions.add(AclEntryPermission.WRITE_DATA);
            permissions.add(AclEntryPermission.APPEND_DATA);
            permissions.add(AclEntryPermission.WRITE_ATTRIBUTES);
            permissions.add(AclEntryPermission.WRITE_NAMED_ATTRS);
            permissions.add(AclEntryPermission.WRITE_ACL);
        }
        if (executable || directory) {
            permissions.add(AclEntryPermission.EXECUTE);
        }
        if (directory) {
            permissions.add(AclEntryPermission.DELETE_CHILD);
        }
        AclEntry ownerEntry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(permissions)
                .build();
        acl.setAcl(Collections.singletonList(ownerEntry));
        validateOwnerOnlyAcl(owner, acl.getAcl(), "private file", path);
    }
}

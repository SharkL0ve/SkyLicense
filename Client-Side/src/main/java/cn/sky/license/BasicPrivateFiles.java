package cn.sky.license;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** Private installation identity storage for the portable client. */
final class BasicPrivateFiles {
    private BasicPrivateFiles() { }

    static void directory(Path path) throws IOException {
        rejectLinks(path);
        Files.createDirectories(path);
        restrict(path, true);
    }

    static void file(Path path) throws IOException {
        rejectLinks(path);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) != 32) {
            throw new IOException("invalid installation identity file");
        }
        restrict(path, false);
    }

    private static void rejectLinks(Path path) throws IOException {
        Path current = path.getRoot();
        for (Path part : path) {
            current = current.resolve(part);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                BasicFileAttributes attributes = Files.readAttributes(current, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (attributes.isSymbolicLink() || attributes.isOther()) throw new IOException("linked identity directory");
            }
        }
    }

    private static void restrict(Path path, boolean directory) throws IOException {
        if (Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS) != null) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
            return;
        }
        AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl == null) throw new IOException("private file permissions unavailable");
        acl.setAcl(Collections.singletonList(AclEntry.newBuilder().setType(AclEntryType.ALLOW)
                .setPrincipal(Files.getOwner(path, LinkOption.NOFOLLOW_LINKS))
                .setPermissions(EnumSet.allOf(AclEntryPermission.class)).build()));
    }
}

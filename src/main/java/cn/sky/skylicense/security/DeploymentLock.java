package cn.sky.skylicense.security;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

/** Holds an operating-system lock for the complete server process lifetime. */
public final class DeploymentLock implements AutoCloseable {
    public static final String FILE_NAME = ".skylicense.lock";

    private final Path path;
    private final FileChannel channel;
    private final FileLock lock;
    private final AtomicBoolean closed = new AtomicBoolean();

    private DeploymentLock(Path path, FileChannel channel, FileLock lock) {
        this.path = path;
        this.channel = channel;
        this.lock = lock;
    }

    public static DeploymentLock acquire(Path workingDirectory) throws IOException {
        Path root = workingDirectory.toRealPath(LinkOption.NOFOLLOW_LINKS);
        SecureFiles.requireOwnerOnly(root, true, "working directory");
        Path path = root.resolve(FILE_NAME);
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("deployment lock must be a regular file: " + path);
            }
        }

        FileChannel channel = FileChannel.open(
                path,
                StandardOpenOption.CREATE,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS);
        FileLock lock = null;
        try {
            SecureFiles.makePrivateReadWrite(path);
            try {
                lock = channel.tryLock();
            } catch (OverlappingFileLockException ignored) {
                // Another server in this JVM already owns the deployment.
            }
            if (lock == null) {
                throw new IOException(
                        "another SkyLicense process already owns the deployment: " + root);
            }
            writeOwnerRecord(channel, root);
            return new DeploymentLock(path, channel, lock);
        } catch (IOException | RuntimeException error) {
            if (lock != null) {
                try {
                    lock.release();
                } catch (IOException releaseError) {
                    error.addSuppressed(releaseError);
                }
            }
            try {
                channel.close();
            } catch (IOException closeError) {
                error.addSuppressed(closeError);
            }
            throw error;
        }
    }

    private static void writeOwnerRecord(FileChannel channel, Path root) throws IOException {
        String record = "pid=" + ProcessHandle.current().pid() + "\n"
                + "started_at=" + Instant.now() + "\n"
                + "working_directory=" + root + "\n";
        byte[] bytes = record.getBytes(StandardCharsets.UTF_8);
        channel.position(0);
        channel.truncate(0);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
        channel.force(true);
    }

    public Path path() {
        return path;
    }

    @Override
    public void close() throws IOException {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        IOException failure = null;
        try {
            lock.release();
        } catch (IOException error) {
            failure = error;
        }
        try {
            channel.close();
        } catch (IOException error) {
            if (failure == null) {
                failure = error;
            } else {
                failure.addSuppressed(error);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }
}

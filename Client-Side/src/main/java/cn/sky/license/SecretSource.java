package cn.sky.license;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/** Java 8 compatible secret-file resolver used by the customer SDK. */
final class SecretSource {
    private static final Pattern ENVIRONMENT_NAME =
            Pattern.compile("[A-Z][A-Z0-9_]*");
    private static final int MAX_ENVIRONMENT_NAME_LENGTH = 128;
    private static final int MAX_PATH_LENGTH = 4_096;
    private static final int MAX_SUPPORTED_VALUE_BYTES = 1_048_576;

    private SecretSource() {
    }

    static String readOptional(String environmentName, int maximumUtf8Bytes) {
        return readOptional(environmentName, maximumUtf8Bytes, System::getenv);
    }

    static String readOptional(
            String environmentName,
            int maximumUtf8Bytes,
            Function<String, String> environment
    ) {
        validateArguments(environmentName, maximumUtf8Bytes, environment);
        String direct = environment.apply(environmentName);
        String file = environment.apply(environmentName + "_FILE");
        if (direct != null && file != null) {
            throw new IllegalStateException(
                    environmentName + " and " + environmentName + "_FILE must not both be set");
        }
        if (file == null) {
            return direct == null
                    ? null
                    : normalizeValue(environmentName, direct, maximumUtf8Bytes);
        }
        return readFileValue(
                environmentName,
                configuredFilePath(file, environmentName),
                maximumUtf8Bytes);
    }

    private static void validateArguments(
            String environmentName,
            int maximumUtf8Bytes,
            Function<String, String> environment
    ) {
        if (environmentName == null
                || environmentName.length() > MAX_ENVIRONMENT_NAME_LENGTH
                || !ENVIRONMENT_NAME.matcher(environmentName).matches()
                || environmentName.endsWith("_FILE")) {
            throw new IllegalArgumentException("invalid secret environment name");
        }
        if (maximumUtf8Bytes <= 0 || maximumUtf8Bytes > MAX_SUPPORTED_VALUE_BYTES) {
            throw new IllegalArgumentException("secret value size limit is invalid");
        }
        Objects.requireNonNull(environment, "environment");
    }

    private static Path configuredFilePath(String rawPath, String environmentName) {
        if (rawPath == null
                || rawPath.trim().isEmpty()
                || rawPath.length() > MAX_PATH_LENGTH
                || containsControl(rawPath)) {
            throw new IllegalStateException(
                    environmentName + "_FILE must be an absolute regular file path");
        }
        final Path path;
        try {
            Path configured = Paths.get(rawPath);
            if (!configured.isAbsolute()) {
                throw new IllegalStateException(
                        environmentName + "_FILE must be an absolute path");
            }
            path = configured.normalize();
        } catch (IllegalStateException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new IllegalStateException(
                    environmentName + "_FILE is not a valid path", error);
        }
        try {
            rejectLinkComponents(path);
            BasicFileAttributes attributes = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile()
                    || attributes.isOther()
                    || Files.isSymbolicLink(path)
                    || !Files.isReadable(path)) {
                throw new IllegalStateException(
                        environmentName + "_FILE must reference a readable regular non-symlink file");
            }
            requireOwnerOnly(path, environmentName + "_FILE");
            return path;
        } catch (IllegalStateException error) {
            throw error;
        } catch (IOException error) {
            throw new IllegalStateException(
                    "unable to validate " + environmentName + "_FILE", error);
        }
    }

    private static String readFileValue(
            String environmentName,
            Path path,
            int maximumUtf8Bytes
    ) {
        byte[] encoded = null;
        try {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            long rawLimit = (long) maximumUtf8Bytes + 2L;
            if (before.size() > rawLimit) {
                throw new IllegalStateException(
                        environmentName + "_FILE exceeds its size limit");
            }
            encoded = readBounded(path, rawLimit, environmentName);
            BasicFileAttributes after = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (after.size() != before.size()
                    || (before.fileKey() != null
                    && !Objects.equals(before.fileKey(), after.fileKey()))) {
                throw new IllegalStateException(
                        environmentName + "_FILE changed while it was being read");
            }
            requireOwnerOnly(path, environmentName + "_FILE");
            String value = decodeUtf8(encoded, environmentName + "_FILE");
            value = removeOneTerminalLineEnding(value);
            return normalizeValue(environmentName, value, maximumUtf8Bytes);
        } catch (IllegalStateException error) {
            throw error;
        } catch (IOException error) {
            throw new IllegalStateException(
                    "unable to read " + environmentName + "_FILE", error);
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    private static byte[] readBounded(Path path, long rawLimit, String environmentName)
            throws IOException {
        if (rawLimit > Integer.MAX_VALUE - 1L) {
            throw new IllegalArgumentException("secret file size limit is too large");
        }
        byte[] buffer = new byte[(int) rawLimit + 1];
        int total = 0;
        try (InputStream input = Files.newInputStream(
                path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            int read;
            while ((read = input.read(buffer, total, buffer.length - total)) != -1) {
                total += read;
                if (total > rawLimit || total == buffer.length) {
                    throw new IllegalStateException(
                            environmentName + "_FILE exceeds its size limit");
                }
            }
            return Arrays.copyOf(buffer, total);
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    private static String decodeUtf8(byte[] encoded, String label) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(encoded)).toString();
        } catch (CharacterCodingException error) {
            throw new IllegalStateException(label + " must contain valid UTF-8", error);
        }
    }

    private static String normalizeValue(String environmentName, String value, int maximumUtf8Bytes) {
        if (containsControl(value)) {
            throw new IllegalStateException(
                    environmentName + " must not contain NUL or newline characters");
        }
        byte[] encoded = null;
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            encoded = value.getBytes(StandardCharsets.UTF_8);
            String roundTrip = decoder.decode(ByteBuffer.wrap(encoded)).toString();
            if (!value.equals(roundTrip) || encoded.length > maximumUtf8Bytes) {
                throw new IllegalStateException(
                        environmentName + " exceeds its UTF-8 size limit or is not valid UTF-8");
            }
            return value;
        } catch (CharacterCodingException error) {
            throw new IllegalStateException(environmentName + " must contain valid UTF-8", error);
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    private static String removeOneTerminalLineEnding(String value) {
        if (value.endsWith("\r\n")) {
            return value.substring(0, value.length() - 2);
        }
        if (value.endsWith("\n") || value.endsWith("\r")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }

    private static boolean containsControl(String value) {
        return value.indexOf('\0') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0;
    }

    private static void rejectLinkComponents(Path path) throws IOException {
        Path current = path.getRoot();
        for (Path component : path) {
            current = current == null ? component : current.resolve(component);
            if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }
            BasicFileAttributes attributes = Files.readAttributes(
                    current, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(current) || attributes.isOther()) {
                throw new IOException("secret path contains a symbolic link or reparse point");
            }
        }
    }

    private static void requireOwnerOnly(Path path, String label) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            Set<PosixFilePermission> permissions = posix.readAttributes().permissions();
            EnumSet<PosixFilePermission> unexpected =
                    EnumSet.noneOf(PosixFilePermission.class);
            unexpected.addAll(permissions);
            unexpected.remove(PosixFilePermission.OWNER_READ);
            unexpected.remove(PosixFilePermission.OWNER_WRITE);
            if (!unexpected.isEmpty()) {
                throw new IOException(label + " grants group, other, or execute permissions");
            }
            return;
        }

        AclFileAttributeView acl = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl == null) {
            throw new IOException("owner-only ACLs are unavailable for " + label);
        }
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        if (owner == null || owner instanceof GroupPrincipal) {
            throw new IOException(label + " must be owned by a user account");
        }
        List<AclEntry> entries = acl.getAcl();
        boolean ownerAllow = false;
        for (AclEntry entry : entries) {
            if (entry.type() != AclEntryType.ALLOW) {
                continue;
            }
            if (!owner.equals(entry.principal())) {
                throw new IOException(label + " grants access to a non-owner principal");
            }
            ownerAllow = true;
        }
        if (!ownerAllow) {
            throw new IOException(label + " has no owner allow entry");
        }
    }
}

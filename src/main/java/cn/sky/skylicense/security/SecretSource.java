package cn.sky.skylicense.security;

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
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Resolves sensitive values from either an environment variable or an owner-only file.
 *
 * <p>The two forms are deliberately mutually exclusive.  File values are bounded, decoded
 * strictly as UTF-8, and may contain one terminal line ending so that ordinary secret-manager
 * files can be used without accidentally accepting multiline credentials.</p>
 */
public final class SecretSource {
    private static final Pattern ENVIRONMENT_NAME =
            Pattern.compile("[A-Z][A-Z0-9_]*");
    private static final int MAX_ENVIRONMENT_NAME_LENGTH = 128;
    private static final int MAX_PATH_LENGTH = 4_096;
    private static final int MAX_SUPPORTED_VALUE_BYTES = 1_048_576;

    private SecretSource() {
    }

    /** Returns an optional value using the process environment. */
    public static String readOptional(String environmentName, int maximumUtf8Bytes) {
        return readOptional(environmentName, maximumUtf8Bytes, System::getenv);
    }

    /** Returns a required value using the process environment. */
    public static String readRequired(String environmentName, int maximumUtf8Bytes) {
        String value = readOptional(environmentName, maximumUtf8Bytes);
        if (value == null) {
            throw new IllegalStateException(environmentName + " is required");
        }
        return value;
    }

    /**
     * Returns the configured credential-file path, or {@code null} when the direct value form
     * (or neither form) is selected.  This is used by backup code to exclude secret files.
     */
    static Path configuredFilePath(String environmentName) {
        return configuredFilePath(environmentName, System::getenv);
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
        if (file != null) {
            return readFileValue(environmentName, configuredFilePath(file, environmentName), maximumUtf8Bytes);
        }
        if (direct == null) {
            return null;
        }
        return normalizeValue(environmentName, direct, maximumUtf8Bytes);
    }

    static Path configuredFilePath(
            String environmentName,
            Function<String, String> environment
    ) {
        validateEnvironmentName(environmentName);
        Objects.requireNonNull(environment, "environment");
        String direct = environment.apply(environmentName);
        String file = environment.apply(environmentName + "_FILE");
        if (direct != null && file != null) {
            throw new IllegalStateException(
                    environmentName + " and " + environmentName + "_FILE must not both be set");
        }
        return file == null ? null : configuredFilePath(file, environmentName);
    }

    private static void validateArguments(
            String environmentName,
            int maximumUtf8Bytes,
            Function<String, String> environment
    ) {
        validateEnvironmentName(environmentName);
        if (maximumUtf8Bytes <= 0 || maximumUtf8Bytes > MAX_SUPPORTED_VALUE_BYTES) {
            throw new IllegalArgumentException("secret value size limit is invalid");
        }
        Objects.requireNonNull(environment, "environment");
    }

    private static void validateEnvironmentName(String environmentName) {
        if (environmentName == null
                || environmentName.length() > MAX_ENVIRONMENT_NAME_LENGTH
                || !ENVIRONMENT_NAME.matcher(environmentName).matches()
                || environmentName.endsWith("_FILE")) {
            throw new IllegalArgumentException("invalid secret environment name");
        }
    }

    private static Path configuredFilePath(String rawPath, String environmentName) {
        if (rawPath == null
                || rawPath.isBlank()
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
        } catch (RuntimeException error) {
            if (error instanceof IllegalStateException state) {
                throw state;
            }
            throw new IllegalStateException(
                    environmentName + "_FILE is not a valid path", error);
        }
        try {
            rejectLinkComponents(path);
            BasicFileAttributes attributes = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile()
                    || attributes.isOther()
                    || Files.isSymbolicLink(path)) {
                throw new IllegalStateException(
                        environmentName + "_FILE must reference a regular non-symlink file");
            }
            SecureFiles.requireOwnerOnly(path, false, environmentName + "_FILE");
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
            SecureFiles.requireOwnerOnly(path, false, environmentName + "_FILE");
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
                java.util.Arrays.fill(encoded, (byte) 0);
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
            return java.util.Arrays.copyOf(buffer, total);
        } finally {
            java.util.Arrays.fill(buffer, (byte) 0);
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
            // Encoding through a strict round-trip also rejects unpaired UTF-16 surrogates.
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
                java.util.Arrays.fill(encoded, (byte) 0);
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
}

package cn.sky.skylicense.security;

import cn.sky.skylicense.config.Storage;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.IDN;
import java.security.MessageDigest;
import java.io.File;
import java.util.List;
import java.util.Locale;

/** Resolves production secrets and rejects known development defaults. */
public final class StartupSecurity {
    private static final String ADMIN_ENV = "SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD";
    private static final String TLS_KEY_PASSWORD_ENV = "SKYLICENSE_TLS_KEY_PASSWORD";
    private static final long MAX_TLS_FILE_BYTES = 1024L * 1024L;
    private static final int MAX_TLS_PASSWORD_CHARACTERS = 4_096;
    private static final int MAX_ADMIN_PASSWORD_CHARACTERS = 128;

    private StartupSecurity() {
    }

    public static void validate(Storage storage) {
        if (storage == null) {
            throw new IllegalStateException("configuration storage is missing");
        }
        validatePorts(storage.getAuthPort(), storage.getWebPort());
        validateTlsPath(storage.getAuthTlsCertificateChain(), "authTlsCertificateChain");
        validateTlsPath(storage.getAuthTlsPrivateKey(), "authTlsPrivateKey");
        normalizeTlsServerName(storage.getAuthTlsServerName());
        validateClientBuildPolicy(
                storage.getMinimumClientSecurityEpoch(),
                storage.getAllowedClientBuildIds());
        validateWebOrigins(storage.getAllowedWebOrigins());
    }

    /** Verifies TLS material before any service thread or database is started. */
    public static TlsMaterialValidator.Summary validateTlsFiles(Storage storage) {
        validate(storage);
        return validateTlsFiles(
                storage.getAuthTlsCertificateChain(),
                storage.getAuthTlsPrivateKey(),
                normalizeTlsServerName(storage.getAuthTlsServerName()));
    }

    static TlsMaterialValidator.Summary validateTlsFiles(
            String certificatePath,
            String privateKeyPath,
            String serverName
    ) {
        validateTlsPath(certificatePath, "authTlsCertificateChain");
        validateTlsPath(privateKeyPath, "authTlsPrivateKey");
        File certificate = canonicalFile(certificatePath);
        File privateKey = canonicalFile(privateKeyPath);
        if (!certificate.isFile() || !privateKey.isFile()) {
            throw new IllegalStateException(
                    "TLS certificate/key missing: " + certificate + " / " + privateKey);
        }
        if (!certificate.canRead() || !privateKey.canRead()
                || certificate.length() == 0 || privateKey.length() == 0) {
            throw new IllegalStateException(
                    "TLS certificate/key is empty or not readable: "
                            + certificate + " / " + privateKey);
        }
        if (certificate.equals(privateKey)) {
            throw new IllegalStateException(
                    "TLS certificate and private key must be different files");
        }
        if (certificate.length() > MAX_TLS_FILE_BYTES || privateKey.length() > MAX_TLS_FILE_BYTES) {
            throw new IllegalStateException("TLS certificate/key files must not exceed 1 MiB");
        }
        String password = tlsPrivateKeyPassword();
        if (password != null && password.length() > MAX_TLS_PASSWORD_CHARACTERS) {
            throw new IllegalStateException(
                    "SKYLICENSE_TLS_KEY_PASSWORD must not exceed 4096 characters");
        }
        return TlsMaterialValidator.validate(
                certificate.toPath(),
                privateKey.toPath(),
                password == null || password.isEmpty() ? null : password,
                normalizeTlsServerName(serverName));
    }

    static void validatePorts(int authPort, int webPort) {
        if (authPort < 1 || authPort > 65_535 || webPort < 1 || webPort > 65_535) {
            throw new IllegalStateException("authPort and webPort must be between 1 and 65535");
        }
        if (authPort == webPort) {
            throw new IllegalStateException("authPort and webPort must be different");
        }
    }

    private static void validateTlsPath(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 4_096) {
            throw new IllegalStateException(field + " must be a non-empty path");
        }
    }

    private static File canonicalFile(String path) {
        try {
            return new File(path).getCanonicalFile();
        } catch (java.io.IOException error) {
            throw new IllegalStateException("Unable to resolve TLS path: " + path, error);
        }
    }

    static String normalizeTlsServerName(String value) {
        if (value == null || value.isEmpty() || !value.equals(value.trim())
                || value.length() > 253) {
            throw new IllegalStateException(
                    "authTlsServerName must be a DNS name or numeric IP literal without a port");
        }
        try {
            return NativeIdentifierValidator.normalizeIpLiteral(value);
        } catch (IllegalArgumentException ignored) {
            // Continue with strict IDNA DNS validation.
        }
        if (value.chars().allMatch(character -> character == '.'
                || (character >= '0' && character <= '9'))) {
            throw new IllegalStateException("authTlsServerName contains an invalid IP literal");
        }
        final String ascii;
        try {
            ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("authTlsServerName contains an invalid DNS name", error);
        }
        if (ascii.isEmpty() || ascii.length() > 253 || ascii.endsWith(".")) {
            throw new IllegalStateException(
                    "authTlsServerName must not be empty, oversized, or end with a dot");
        }
        for (String label : ascii.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63
                    || label.startsWith("-") || label.endsWith("-")) {
                throw new IllegalStateException(
                        "authTlsServerName contains an invalid DNS label");
            }
        }
        return ascii;
    }

    public static String bootstrapAdminPassword() {
        String value = SecretSource.readOptional(ADMIN_ENV, MAX_ADMIN_PASSWORD_CHARACTERS * 4);
        validateAdminPasswordValue(value);
        return value;
    }

    public static void validateBootstrapAdminEnvironment(boolean activeAdministratorExists) {
        validateBootstrapAdminValue(
                activeAdministratorExists,
                SecretSource.readOptional(ADMIN_ENV, MAX_ADMIN_PASSWORD_CHARACTERS * 4));
    }

    public static String tlsPrivateKeyPassword() {
        String value = SecretSource.readOptional(
                TLS_KEY_PASSWORD_ENV, MAX_TLS_PASSWORD_CHARACTERS * 4);
        if (value != null && value.length() > MAX_TLS_PASSWORD_CHARACTERS) {
            throw new IllegalStateException(
                    TLS_KEY_PASSWORD_ENV + " must not exceed 4096 characters");
        }
        return value;
    }

    static void validateBootstrapAdminValue(
            boolean activeAdministratorExists,
            String configuredPassword
    ) {
        if (activeAdministratorExists) {
            if (configuredPassword != null) {
                throw new IllegalStateException(
                        ADMIN_ENV + " must be removed after bootstrap administrator creation");
            }
            return;
        }
        validateAdminPasswordValue(configuredPassword);
    }

    public static boolean isClientBuildAllowed(
            Storage storage,
            int securityEpoch,
            byte[] buildId
    ) {
        return isClientBuildAllowed(
                storage.getMinimumClientSecurityEpoch(),
                storage.getAllowedClientBuildIds(),
                securityEpoch,
                buildId);
    }

    static boolean isClientBuildAllowed(
            int minimumEpoch,
            List<String> allowedBuildIds,
            int securityEpoch,
            byte[] buildId
    ) {
        if (securityEpoch < minimumEpoch
                || buildId == null
                || buildId.length != 32
                || allZero(buildId)) {
            return false;
        }
        for (String allowed : allowedBuildIds) {
            byte[] allowedBytes = decodeHex32(allowed);
            if (allowedBytes != null && MessageDigest.isEqual(allowedBytes, buildId)) {
                return true;
            }
        }
        return false;
    }

    static void validateAdminPasswordValue(String value) {
        if (value == null || value.length() < 12) {
            throw new IllegalStateException(
                    ADMIN_ENV + " must contain at least 12 characters for first startup");
        }
        if (value.length() > MAX_ADMIN_PASSWORD_CHARACTERS) {
            throw new IllegalStateException(
                    ADMIN_ENV + " must not exceed 128 characters");
        }

        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            lower |= Character.isLowerCase(character);
            upper |= Character.isUpperCase(character);
            digit |= Character.isDigit(character);
            symbol |= !Character.isLetterOrDigit(character);
        }
        int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
        if (classes < 3) {
            throw new IllegalStateException(
                    ADMIN_ENV + " must use at least three character classes");
        }
    }

    static void validateClientBuildPolicy(int minimumEpoch, List<String> allowedBuildIds) {
        if (minimumEpoch <= 0) {
            throw new IllegalStateException("minimumClientSecurityEpoch must be greater than zero");
        }
        if (allowedBuildIds == null || allowedBuildIds.isEmpty()) {
            throw new IllegalStateException("allowedClientBuildIds must contain a production build id");
        }
        for (String buildId : allowedBuildIds) {
            byte[] decoded = decodeHex32(buildId);
            if (decoded == null || allZero(decoded)) {
                throw new IllegalStateException(
                        "allowedClientBuildIds entries must be non-zero 64-character hexadecimal values");
            }
        }
    }

    static void validateWebOrigins(List<String> origins) {
        if (origins == null) {
            throw new IllegalStateException("allowedWebOrigins must be an array");
        }
        for (String origin : origins) {
            if (origin == null || origin.length() > 512 || origin.indexOf('*') >= 0) {
                throw new IllegalStateException(
                        "allowedWebOrigins must contain exact HTTP(S) origins without wildcards");
            }
            try {
                URI uri = new URI(origin);
                String scheme = uri.getScheme();
                if (!("https".equalsIgnoreCase(scheme)
                        || "http".equalsIgnoreCase(scheme))
                        || uri.getHost() == null
                        || uri.getUserInfo() != null
                        || uri.getQuery() != null
                        || uri.getFragment() != null
                        || !uri.getPath().isEmpty()
                        || uri.getPort() == 0) {
                    throw new IllegalStateException(
                            "allowedWebOrigins contains an invalid origin: " + origin);
                }
                if ("http".equalsIgnoreCase(scheme) && !isLoopbackHost(uri.getHost())) {
                    throw new IllegalStateException(
                            "allowedWebOrigins requires HTTPS except for loopback development origins: "
                                    + origin);
                }
            } catch (URISyntaxException error) {
                throw new IllegalStateException(
                        "allowedWebOrigins contains an invalid origin: " + origin,
                        error);
            }
        }
    }

    private static boolean isLoopbackHost(String host) {
        return "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host)
                || "::1".equals(host)
                || "[::1]".equals(host);
    }

    private static byte[] decodeHex32(String value) {
        if (value == null
                || value.length() != 64
                || !value.chars().allMatch(character ->
                        character <= 0x7f && Character.digit(character, 16) >= 0)) {
            return null;
        }
        byte[] decoded = new byte[32];
        for (int index = 0; index < decoded.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            decoded[index] = (byte) ((high << 4) | low);
        }
        return decoded;
    }

    private static boolean allZero(byte[] value) {
        int difference = 0;
        for (byte current : value) {
            difference |= current;
        }
        return difference == 0;
    }

}

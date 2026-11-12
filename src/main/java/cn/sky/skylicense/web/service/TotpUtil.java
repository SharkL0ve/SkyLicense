package cn.sky.skylicense.web.service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/** Minimal RFC 4226/6238 implementation with fixed interoperable parameters. */
final class TotpUtil {
    static final int PERIOD_SECONDS = 30;
    static final int DIGITS = 6;
    static final int SECRET_BYTES = 20;
    private static final int WINDOW = 1;
    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    private TotpUtil() {
    }

    static byte[] generateSecret() {
        byte[] secret = new byte[SECRET_BYTES];
        RANDOM.nextBytes(secret);
        return secret;
    }

    static String encodeBase32(byte[] value) {
        if (value == null || value.length == 0 || value.length > 128) {
            throw new IllegalArgumentException("TOTP secret length is invalid");
        }
        StringBuilder encoded = new StringBuilder((value.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte item : value) {
            buffer = (buffer << 8) | (item & 0xff);
            bits += 8;
            while (bits >= 5) {
                encoded.append(BASE32[(buffer >>> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) {
            encoded.append(BASE32[(buffer << (5 - bits)) & 31]);
        }
        return encoded.toString();
    }

    static byte[] decodeBase32(String value) {
        if (value == null || value.isEmpty() || value.length() > 256) {
            throw new IllegalArgumentException("TOTP secret encoding is invalid");
        }
        ByteArrayOutputStream decoded = new ByteArrayOutputStream(value.length() * 5 / 8);
        int buffer = 0;
        int bits = 0;
        for (int index = 0; index < value.length(); index++) {
            char character = Character.toUpperCase(value.charAt(index));
            int digit = base32Digit(character);
            if (digit < 0) {
                throw new IllegalArgumentException("TOTP secret encoding is invalid");
            }
            buffer = (buffer << 5) | digit;
            bits += 5;
            if (bits >= 8) {
                decoded.write((buffer >>> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        if (bits > 0 && (buffer & ((1 << bits) - 1)) != 0) {
            throw new IllegalArgumentException("TOTP secret has non-zero trailing bits");
        }
        byte[] result = decoded.toByteArray();
        if (result.length == 0 || result.length > 128) {
            Arrays.fill(result, (byte) 0);
            throw new IllegalArgumentException("TOTP secret length is invalid");
        }
        return result;
    }

    static long verify(byte[] secret, String suppliedCode, long epochSeconds, long lastAcceptedStep) {
        if (secret == null || secret.length == 0 || !isSixDigits(suppliedCode)) {
            return -1L;
        }
        long currentStep = Math.floorDiv(epochSeconds, PERIOD_SECONDS);
        long accepted = -1L;
        for (int offset = -WINDOW; offset <= WINDOW; offset++) {
            long candidateStep = currentStep + offset;
            if (candidateStep <= lastAcceptedStep || candidateStep < 0) {
                continue;
            }
            String expected = codeAt(secret, candidateStep);
            byte[] expectedBytes = expected.getBytes(StandardCharsets.US_ASCII);
            byte[] suppliedBytes = suppliedCode.getBytes(StandardCharsets.US_ASCII);
            try {
                if (MessageDigest.isEqual(expectedBytes, suppliedBytes)) {
                    accepted = Math.max(accepted, candidateStep);
                }
            } finally {
                Arrays.fill(expectedBytes, (byte) 0);
                Arrays.fill(suppliedBytes, (byte) 0);
            }
        }
        return accepted;
    }

    static String codeAt(byte[] secret, long step) {
        if (secret == null || secret.length == 0 || step < 0) {
            throw new IllegalArgumentException("TOTP secret and time-step are required");
        }
        byte[] counter = ByteBuffer.allocate(Long.BYTES).putLong(step).array();
        byte[] digest = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            digest = mac.doFinal(counter);
            int offset = digest[digest.length - 1] & 0x0f;
            int binary = ((digest[offset] & 0x7f) << 24)
                    | ((digest[offset + 1] & 0xff) << 16)
                    | ((digest[offset + 2] & 0xff) << 8)
                    | (digest[offset + 3] & 0xff);
            int value = binary % 1_000_000;
            return String.format(java.util.Locale.ROOT, "%06d", value);
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("HMAC-SHA1 is unavailable", error);
        } finally {
            Arrays.fill(counter, (byte) 0);
            if (digest != null) {
                Arrays.fill(digest, (byte) 0);
            }
        }
    }

    static String enrollmentUri(String issuer, String account, String base32Secret) {
        if (issuer == null || issuer.isBlank() || account == null || account.isBlank()
                || base32Secret == null || base32Secret.isBlank()) {
            throw new IllegalArgumentException("TOTP enrollment identity is required");
        }
        String label = percentEncode(issuer + ":" + account);
        return "otpauth://totp/" + label
                + "?secret=" + percentEncode(base32Secret)
                + "&issuer=" + percentEncode(issuer)
                + "&algorithm=SHA1&digits=" + DIGITS
                + "&period=" + PERIOD_SECONDS;
    }

    private static boolean isSixDigits(String value) {
        return value != null && value.length() == DIGITS
                && value.chars().allMatch(character -> character >= '0' && character <= '9');
    }

    private static int base32Digit(char character) {
        if (character >= 'A' && character <= 'Z') {
            return character - 'A';
        }
        if (character >= '2' && character <= '7') {
            return 26 + character - '2';
        }
        return -1;
    }

    private static String percentEncode(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder encoded = new StringBuilder(bytes.length * 3);
        try {
            for (byte item : bytes) {
                int current = item & 0xff;
                if (current >= 'A' && current <= 'Z'
                        || current >= 'a' && current <= 'z'
                        || current >= '0' && current <= '9'
                        || current == '-' || current == '.' || current == '_' || current == '~') {
                    encoded.append((char) current);
                } else {
                    encoded.append('%');
                    encoded.append(Character.toUpperCase(Character.forDigit(current >>> 4, 16)));
                    encoded.append(Character.toUpperCase(Character.forDigit(current & 0x0f, 16)));
                }
            }
            return encoded.toString();
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}

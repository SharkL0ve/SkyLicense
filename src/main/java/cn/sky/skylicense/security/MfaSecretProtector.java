package cn.sky.skylicense.security;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/** Encrypts TOTP seeds at rest with an installation-specific AES-256-GCM key. */
public final class MfaSecretProtector implements AutoCloseable {
    public static final String ENVIRONMENT = "SKYLICENSE_MFA_ENCRYPTION_KEY";
    private static final String MAGIC = "SKYMFA01";
    private static final byte[] ASSOCIATED_DATA =
            "SkyLicense MFA secret v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int MAX_PLAINTEXT_BYTES = 128;
    private final SecureRandom random = new SecureRandom();
    private final byte[] key;
    private boolean closed;

    private MfaSecretProtector(byte[] key) {
        if (key == null || key.length != KEY_BYTES || isAllZero(key)) {
            throw new IllegalArgumentException("MFA encryption key must contain 32 non-zero bytes");
        }
        this.key = key.clone();
    }

    public static MfaSecretProtector fromEnvironment() {
        byte[] key = decodeEnvironmentKey(SecretSource.readRequired(ENVIRONMENT, KEY_BYTES * 2));
        try {
            return new MfaSecretProtector(key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    public static MfaSecretProtector forKey(byte[] key) {
        return new MfaSecretProtector(key);
    }

    public static void validateEnvironment() {
        byte[] key = decodeEnvironmentKey(SecretSource.readRequired(ENVIRONMENT, KEY_BYTES * 2));
        Arrays.fill(key, (byte) 0);
    }

    public synchronized String encrypt(byte[] plaintext) {
        ensureOpen();
        if (plaintext == null || plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException("MFA secret plaintext length is invalid");
        }
        byte[] nonce = new byte[NONCE_BYTES];
        byte[] ciphertext = null;
        try {
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(ASSOCIATED_DATA);
            ciphertext = cipher.doFinal(plaintext);
            byte[] encoded = new byte[MAGIC.length() + nonce.length + ciphertext.length];
            System.arraycopy(MAGIC.getBytes(StandardCharsets.US_ASCII), 0, encoded, 0, MAGIC.length());
            System.arraycopy(nonce, 0, encoded, MAGIC.length(), nonce.length);
            System.arraycopy(ciphertext, 0, encoded, MAGIC.length() + nonce.length, ciphertext.length);
            try {
                return Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("AES-GCM is unavailable", error);
        } finally {
            Arrays.fill(nonce, (byte) 0);
            if (ciphertext != null) {
                Arrays.fill(ciphertext, (byte) 0);
            }
        }
    }

    public synchronized byte[] decrypt(String encodedValue) {
        ensureOpen();
        if (encodedValue == null || encodedValue.length() > 4_096) {
            throw new IllegalArgumentException("MFA secret ciphertext is invalid");
        }
        byte[] encoded;
        try {
            encoded = Base64.getUrlDecoder().decode(encodedValue);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("MFA secret ciphertext is invalid", error);
        }
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(encoded).equals(encodedValue)) {
            Arrays.fill(encoded, (byte) 0);
            throw new IllegalArgumentException("MFA secret ciphertext is not canonical");
        }
        byte[] ciphertext = null;
        try {
            int minimum = MAGIC.length() + NONCE_BYTES + 16;
            if (encoded.length < minimum
                    || !Arrays.equals(
                    MAGIC.getBytes(StandardCharsets.US_ASCII),
                    Arrays.copyOf(encoded, MAGIC.length()))) {
                throw new IllegalArgumentException("MFA secret ciphertext version is invalid");
            }
            byte[] nonce = Arrays.copyOfRange(encoded, MAGIC.length(), MAGIC.length() + NONCE_BYTES);
            ciphertext = Arrays.copyOfRange(encoded, MAGIC.length() + NONCE_BYTES, encoded.length);
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.DECRYPT_MODE,
                        new SecretKeySpec(key, "AES"),
                        new GCMParameterSpec(TAG_BITS, nonce));
                cipher.updateAAD(ASSOCIATED_DATA);
                byte[] plaintext = cipher.doFinal(ciphertext);
                if (plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT_BYTES) {
                    Arrays.fill(plaintext, (byte) 0);
                    throw new IllegalArgumentException("MFA secret plaintext length is invalid");
                }
                return plaintext;
            } catch (GeneralSecurityException error) {
                throw new IllegalArgumentException("MFA secret ciphertext authentication failed", error);
            } finally {
                Arrays.fill(nonce, (byte) 0);
            }
        } finally {
            Arrays.fill(encoded, (byte) 0);
            if (ciphertext != null) {
                Arrays.fill(ciphertext, (byte) 0);
            }
        }
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            Arrays.fill(key, (byte) 0);
            closed = true;
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("MFA secret protector is closed");
        }
    }

    private static byte[] decodeEnvironmentKey(String value) {
        if (value == null || value.length() != KEY_BYTES * 2
                || !value.chars().allMatch(c -> c <= 0x7f && Character.digit(c, 16) >= 0)) {
            throw new IllegalStateException(
                    ENVIRONMENT + " must be exactly 64 hexadecimal characters");
        }
        byte[] result = new byte[KEY_BYTES];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) ((Character.digit(value.charAt(index * 2), 16) << 4)
                    | Character.digit(value.charAt(index * 2 + 1), 16));
        }
        if (isAllZero(result)) {
            Arrays.fill(result, (byte) 0);
            throw new IllegalStateException(ENVIRONMENT + " must not be all zero");
        }
        return result;
    }

    private static boolean isAllZero(byte[] value) {
        int result = 0;
        for (byte item : value) {
            result |= item;
        }
        return result == 0;
    }
}

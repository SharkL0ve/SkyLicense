package cn.sky.skylicense.utils;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/** Bounded PBKDF2 password hashing with transparent legacy-cost detection. */
public final class PasswordUtil {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SALT_LENGTH = 32;
    private static final int HASH_LENGTH = 32;
    private static final int LEGACY_ITERATIONS = 100_000;
    private static final int CURRENT_ITERATIONS = 600_000;
    private static final int KEY_LENGTH = HASH_LENGTH * 8;
    private static final int MAX_PASSWORD_CHARACTERS = 128;
    private static final int MAX_ENCODED_HASH_CHARACTERS = 256;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    private PasswordUtil() {
    }

    public static String hashPassword(String password) {
        char[] characters = checkedPassword(password);
        byte[] salt = new byte[SALT_LENGTH];
        byte[] hash = null;
        try {
            RANDOM.nextBytes(salt);
            hash = pbkdf2(characters, salt, CURRENT_ITERATIONS, KEY_LENGTH);
            return CURRENT_ITERATIONS
                    + ":" + Base64.getEncoder().encodeToString(salt)
                    + ":" + Base64.getEncoder().encodeToString(hash);
        } finally {
            Arrays.fill(characters, '\0');
            Arrays.fill(salt, (byte) 0);
            if (hash != null) {
                Arrays.fill(hash, (byte) 0);
            }
        }
    }

    public static boolean verifyPassword(String password, String stored) {
        if (password == null
                || password.length() > MAX_PASSWORD_CHARACTERS
                || stored == null
                || stored.isEmpty()
                || stored.length() > MAX_ENCODED_HASH_CHARACTERS) {
            return false;
        }

        char[] characters = password.toCharArray();
        byte[] salt = null;
        byte[] expectedHash = null;
        byte[] actualHash = null;
        try {
            String[] parts = stored.split(":", -1);
            if (parts.length != 3) {
                return false;
            }
            int iterations = Integer.parseInt(parts[0]);
            if (iterations != LEGACY_ITERATIONS && iterations != CURRENT_ITERATIONS) {
                return false;
            }
            salt = Base64.getDecoder().decode(parts[1]);
            expectedHash = Base64.getDecoder().decode(parts[2]);
            if (salt.length != SALT_LENGTH || expectedHash.length != HASH_LENGTH) {
                return false;
            }
            actualHash = pbkdf2(characters, salt, iterations, KEY_LENGTH);
            return MessageDigest.isEqual(expectedHash, actualHash);
        } catch (IllegalArgumentException error) {
            return false;
        } finally {
            Arrays.fill(characters, '\0');
            zeroize(salt, expectedHash, actualHash);
        }
    }

    public static boolean needsRehash(String stored) {
        if (stored == null || stored.length() > MAX_ENCODED_HASH_CHARACTERS) {
            return true;
        }
        int separator = stored.indexOf(':');
        if (separator <= 0) {
            return true;
        }
        try {
            return Integer.parseInt(stored.substring(0, separator)) != CURRENT_ITERATIONS;
        } catch (NumberFormatException error) {
            return true;
        }
    }

    public static boolean meetsStrengthRequirements(String password) {
        if (password == null || password.length() < 12
                || password.length() > MAX_PASSWORD_CHARACTERS) {
            return false;
        }
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        for (int index = 0; index < password.length(); index++) {
            char character = password.charAt(index);
            lower |= Character.isLowerCase(character);
            upper |= Character.isUpperCase(character);
            digit |= Character.isDigit(character);
            symbol |= !Character.isLetterOrDigit(character);
        }
        int classes = (lower ? 1 : 0)
                + (upper ? 1 : 0)
                + (digit ? 1 : 0)
                + (symbol ? 1 : 0);
        return classes >= 3;
    }

    private static char[] checkedPassword(String password) {
        if (password == null || password.isEmpty()
                || password.length() > MAX_PASSWORD_CHARACTERS) {
            throw new IllegalArgumentException("password length is outside the allowed range");
        }
        return password.toCharArray();
    }

    private static byte[] pbkdf2(
            char[] password,
            byte[] salt,
            int iterations,
            int keyLength
    ) {
        PBEKeySpec specification = new PBEKeySpec(password, salt, iterations, keyLength);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(specification).getEncoded();
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("PBKDF2 computation failed", error);
        } finally {
            specification.clearPassword();
        }
    }

    private static void zeroize(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) {
                Arrays.fill(value, (byte) 0);
            }
        }
    }
}

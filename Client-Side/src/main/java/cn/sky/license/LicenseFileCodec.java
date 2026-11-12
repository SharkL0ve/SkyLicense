package cn.sky.license;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/** Versioned authenticated encoding for the local authorization credential. */
final class LicenseFileCodec {
    private static final byte[] MAGIC = "SKYLIC03".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AES_KEY_DOMAIN =
            "SkyLicense license AES key v3\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] HMAC_KEY_DOMAIN =
            "SkyLicense license HMAC key v3\0".getBytes(StandardCharsets.US_ASCII);
    private static final int SALT_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int HMAC_LENGTH = 32;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final String SECRET_ENV = "SKYLICENSE_LICENSE_FILE_SECRET";
    private static final int MAX_SECRET_BYTES = 4_096;

    private LicenseFileCodec() {
    }

    static String decode(byte[] encoded, String secret) throws Exception {
        validateSecret(secret);
        int minimum = MAGIC.length + SALT_LENGTH + IV_LENGTH + GCM_TAG_LENGTH + HMAC_LENGTH;
        if (encoded == null || encoded.length < minimum) {
            throw new IllegalArgumentException("authorization file is truncated");
        }

        byte[] authenticatedData = null;
        byte[] suppliedHmac = null;
        byte[] expectedHmac = null;
        byte[] salt = null;
        byte[] iv = null;
        byte[] ciphertext = null;
        byte[] plaintext = null;
        try {
            authenticatedData = Arrays.copyOfRange(encoded, 0, encoded.length - HMAC_LENGTH);
            suppliedHmac = Arrays.copyOfRange(
                    encoded, encoded.length - HMAC_LENGTH, encoded.length);
            if (!hasMagic(authenticatedData)) {
                throw new IllegalArgumentException("unsupported authorization file format");
            }

            int saltOffset = MAGIC.length;
            int ivOffset = saltOffset + SALT_LENGTH;
            int ciphertextOffset = ivOffset + IV_LENGTH;
            salt = Arrays.copyOfRange(authenticatedData, saltOffset, ivOffset);
            iv = Arrays.copyOfRange(authenticatedData, ivOffset, ciphertextOffset);
            ciphertext = Arrays.copyOfRange(
                    authenticatedData, ciphertextOffset, authenticatedData.length);

            try (KeyMaterial keys = deriveKeyMaterial(secret, salt)) {
                expectedHmac = calculateHmac(authenticatedData, keys.hmacKey);
                if (!MessageDigest.isEqual(suppliedHmac, expectedHmac)) {
                    throw new SecurityException("authorization file HMAC mismatch");
                }

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.DECRYPT_MODE,
                        new SecretKeySpec(keys.aesKey, "AES"),
                        new GCMParameterSpec(128, iv));
                cipher.updateAAD(MAGIC);
                plaintext = cipher.doFinal(ciphertext);
            }
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            zeroize(
                    authenticatedData,
                    suppliedHmac,
                    expectedHmac,
                    salt,
                    iv,
                    ciphertext,
                    plaintext);
        }
    }

    static byte[] encode(String authorizationCode, String secret) throws Exception {
        if (authorizationCode == null) {
            throw new IllegalArgumentException("authorization code must not be null");
        }
        char[] characters = authorizationCode.toCharArray();
        try {
            return encode(characters, secret);
        } finally {
            Arrays.fill(characters, '\0');
        }
    }

    static byte[] encode(char[] authorizationCode, String secret) throws Exception {
        validateSecret(secret);
        if (authorizationCode == null || authorizationCode.length == 0) {
            throw new IllegalArgumentException("authorization code must not be empty");
        }

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] plaintext = null;
        byte[] ciphertext = null;
        byte[] authenticatedData = null;
        byte[] hmac = null;
        try {
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);
            random.nextBytes(iv);
            plaintext = encodeUtf8(authorizationCode);

            try (KeyMaterial keys = deriveKeyMaterial(secret, salt)) {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(keys.aesKey, "AES"),
                        new GCMParameterSpec(128, iv));
                cipher.updateAAD(MAGIC);
                ciphertext = cipher.doFinal(plaintext);

                authenticatedData = new byte[
                        MAGIC.length + salt.length + iv.length + ciphertext.length];
                int offset = 0;
                System.arraycopy(MAGIC, 0, authenticatedData, offset, MAGIC.length);
                offset += MAGIC.length;
                System.arraycopy(salt, 0, authenticatedData, offset, salt.length);
                offset += salt.length;
                System.arraycopy(iv, 0, authenticatedData, offset, iv.length);
                offset += iv.length;
                System.arraycopy(ciphertext, 0, authenticatedData, offset, ciphertext.length);

                hmac = calculateHmac(authenticatedData, keys.hmacKey);
            }

            byte[] output = Arrays.copyOf(authenticatedData, authenticatedData.length + hmac.length);
            System.arraycopy(hmac, 0, output, authenticatedData.length, hmac.length);
            return output;
        } finally {
            zeroize(salt, iv, plaintext, ciphertext, authenticatedData, hmac);
        }
    }

    static String secretFromEnvironment() {
        String secret = SecretSource.readOptional(SECRET_ENV, MAX_SECRET_BYTES);
        validateSecret(secret);
        return secret;
    }

    private static KeyMaterial deriveKeyMaterial(String secret, byte[] salt) throws Exception {
        char[] password = secret.toCharArray();
        PBEKeySpec specification = new PBEKeySpec(
                password, salt, PBKDF2_ITERATIONS, 256);
        byte[] masterKey = null;
        byte[] aesKey = null;
        byte[] hmacKey = null;
        boolean success = false;
        try {
            masterKey = SecretKeyFactory
                    .getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification)
                    .getEncoded();
            aesKey = deriveSubkey(masterKey, AES_KEY_DOMAIN);
            hmacKey = deriveSubkey(masterKey, HMAC_KEY_DOMAIN);
            KeyMaterial result = new KeyMaterial(aesKey, hmacKey);
            success = true;
            return result;
        } finally {
            specification.clearPassword();
            Arrays.fill(password, '\0');
            zeroize(masterKey);
            if (!success) {
                zeroize(aesKey, hmacKey);
            }
        }
    }

    private static byte[] deriveSubkey(byte[] masterKey, byte[] domain) throws Exception {
        Mac derivation = Mac.getInstance("HmacSHA256");
        derivation.init(new SecretKeySpec(masterKey, "HmacSHA256"));
        return derivation.doFinal(domain);
    }

    private static byte[] calculateHmac(byte[] data, byte[] hmacKey) throws Exception {
        Mac authentication = Mac.getInstance("HmacSHA256");
        authentication.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        return authentication.doFinal(data);
    }

    private static boolean hasMagic(byte[] value) {
        if (value.length < MAGIC.length) {
            return false;
        }
        int difference = 0;
        for (int index = 0; index < MAGIC.length; index++) {
            difference |= value[index] ^ MAGIC[index];
        }
        return difference == 0;
    }

    private static byte[] encodeUtf8(char[] value) throws CharacterCodingException {
        ByteBuffer encoded = StandardCharsets.UTF_8
                .newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(value));
        try {
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            return result;
        } finally {
            if (encoded.hasArray()) {
                Arrays.fill(encoded.array(), (byte) 0);
            }
        }
    }

    private static void validateSecret(String secret) {
        byte[] encoded = secret == null ? null : secret.getBytes(StandardCharsets.UTF_8);
        try {
            if (encoded == null || encoded.length < 32) {
                throw new IllegalStateException(
                        SECRET_ENV + " must contain at least 32 unpredictable UTF-8 bytes");
            }
        } finally {
            zeroize(encoded);
        }
    }

    private static void zeroize(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) {
                Arrays.fill(value, (byte) 0);
            }
        }
    }

    private static final class KeyMaterial implements AutoCloseable {
        private final byte[] aesKey;
        private final byte[] hmacKey;

        private KeyMaterial(byte[] aesKey, byte[] hmacKey) {
            this.aesKey = aesKey;
            this.hmacKey = hmacKey;
        }

        @Override
        public void close() {
            zeroize(aesKey, hmacKey);
        }
    }
}

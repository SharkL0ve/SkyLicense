package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MfaSecretProtectorTest {
    @Test
    void encryptsWithFreshNoncesAndRejectsTamperingOrWrongKeys() {
        byte[] firstKey = new byte[32];
        byte[] secondKey = new byte[32];
        Arrays.fill(firstKey, (byte) 0x31);
        Arrays.fill(secondKey, (byte) 0x52);
        byte[] secret = "totp-secret-material".getBytes(StandardCharsets.US_ASCII);

        try (MfaSecretProtector first = MfaSecretProtector.forKey(firstKey);
             MfaSecretProtector second = MfaSecretProtector.forKey(secondKey)) {
            String one = first.encrypt(secret);
            String two = first.encrypt(secret);

            assertNotEquals(one, two);
            assertArrayEquals(secret, first.decrypt(one));
            assertThrows(IllegalArgumentException.class, () -> second.decrypt(one));

            byte[] tamperedBytes = Base64.getUrlDecoder().decode(one);
            try {
                tamperedBytes[tamperedBytes.length - 1] ^= 1;
                String tampered = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(tamperedBytes);
                assertThrows(IllegalArgumentException.class, () -> first.decrypt(tampered));
            } finally {
                Arrays.fill(tamperedBytes, (byte) 0);
            }

            String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            int lastIndex = alphabet.indexOf(one.charAt(one.length() - 1));
            char alias = alphabet.charAt((lastIndex & ~3) | ((lastIndex + 1) & 3));
            String nonCanonical = one.substring(0, one.length() - 1) + alias;
            assertThrows(IllegalArgumentException.class, () -> first.decrypt(nonCanonical));
        } finally {
            Arrays.fill(firstKey, (byte) 0);
            Arrays.fill(secondKey, (byte) 0);
            Arrays.fill(secret, (byte) 0);
        }
    }

    @Test
    void closedProtectorAndZeroKeyFailClosed() {
        byte[] key = new byte[32];
        assertThrows(IllegalArgumentException.class, () -> MfaSecretProtector.forKey(key));
        Arrays.fill(key, (byte) 7);
        MfaSecretProtector protector = MfaSecretProtector.forKey(key);
        protector.close();
        assertThrows(IllegalStateException.class, () -> protector.encrypt(new byte[]{1}));
        Arrays.fill(key, (byte) 0);
    }
}

package cn.sky.skylicense.encrypt;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncryptUtilTest {
    @Test
    void resourceEnvelopeMatchesTheRustProtocolVector() throws Exception {
        byte[] key = hex(
                "65c5f2dad7eb61583e7ab30df7ebefcd260e092f2bf8a8537c90ea1ad65fb4b0");
        byte[] associatedData = hex(
                "536b794c6963656e7365207634207265736f757263652061616400"
                        + "0202020202020202020202020202020202020202020202020202020202020202"
                        + "00000007"
                        + "0303030303030303030303030303030303030303030303030303030303030303"
                        + "00000006706c7567696e00000005312e322e33");
        byte[] nonce = hex("000102030405060708090a0b");
        byte[] envelope = EncryptUtil.encryptEnvelopeWithNonce(
                "cross-language resource vector".getBytes(StandardCharsets.UTF_8),
                key,
                associatedData,
                EncryptUtil.RESOURCE_MAGIC,
                nonce);
        assertArrayEquals(
                hex("534b595245533034000102030405060708090a0b"
                        + "5e037fde97dcb8d1c77718b7f5cfadaac9bce06ded38748d987055c6a5146f"
                        + "bc4bf07f79511d8dbc0ca55bbbfc0f"),
                envelope);
        assertArrayEquals(
                "cross-language resource vector".getBytes(StandardCharsets.UTF_8),
                EncryptUtil.decryptEnvelope(
                        envelope, key, associatedData, EncryptUtil.RESOURCE_MAGIC));
    }

    @Test
    void tamperingAndWrongAssociatedDataAreRejected() throws Exception {
        byte[] envelope = EncryptUtil.encryptEnvelopeWithNonce(
                new byte[]{1, 2, 3},
                new byte[32],
                new byte[]{4},
                EncryptUtil.RESOURCE_MAGIC,
                new byte[12]);
        envelope[envelope.length - 1] ^= 1;
        assertThrows(
                GeneralSecurityException.class,
                () -> EncryptUtil.decryptEnvelope(
                        envelope, new byte[32], new byte[]{4}, EncryptUtil.RESOURCE_MAGIC));
        assertThrows(
                GeneralSecurityException.class,
                () -> EncryptUtil.decryptEnvelope(
                        EncryptUtil.encryptEnvelopeWithNonce(
                                new byte[]{1},
                                new byte[32],
                                new byte[]{4},
                                EncryptUtil.RESOURCE_MAGIC,
                                new byte[12]),
                        new byte[32],
                        new byte[]{5},
                        EncryptUtil.RESOURCE_MAGIC));
    }

    @Test
    void methodEnvelopesMatchTheRustProtocolVectors() throws Exception {
        byte[] key = hex(
                "21e920e117963a013464111f672e1d374649b09ec19b9242c1e97775f3142396");
        byte[] nonce = hex("000102030405060708090a0b");
        assertArrayEquals(
                hex("534b594d54483034000102030405060708090a0b"
                        + "99114bd1ea5c390bec1f0086100ac117b359b19d118db46c19e3f8cc"),
                EncryptUtil.encryptEnvelopeWithNonce(
                        "lookup-token".getBytes(StandardCharsets.UTF_8),
                        key,
                        EncryptUtil.METHOD_LOOKUP_AAD,
                        EncryptUtil.METHOD_LOOKUP_MAGIC,
                        nonce));
        assertArrayEquals(
                hex("534b595354523034000102030405060708090a0b"
                        + "861b47c8fa58390cf7060c86b583f9c0b2450018362367b168e0d3173b"),
                EncryptUtil.encryptEnvelopeWithNonce(
                        "secret-string".getBytes(StandardCharsets.UTF_8),
                        key,
                        EncryptUtil.METHOD_STRING_AAD,
                        EncryptUtil.METHOD_STRING_MAGIC,
                        nonce));
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }
}

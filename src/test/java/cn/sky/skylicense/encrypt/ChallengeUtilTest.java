package cn.sky.skylicense.encrypt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChallengeUtilTest {
    @Test
    void hkdfMatchesTheRustProtocolVector() throws Exception {
        byte[] expected = hex(
                "7c23ae748ee615932f22a1fe2ae7a150"
                        + "45d4a8239082fb995db105658953e8ed");
        byte[] actual = ChallengeUtil.deriveSessionKeyMaterial(
                repeated(7), repeated(8), repeated(9));
        assertArrayEquals(expected, actual);
    }

    @Test
    void v4ChallengeTranscriptMatchesTheRustProtocolVector() throws Exception {
        byte[] actual = ChallengeUtil.computeChallengeResponse(
                repeated(1),
                repeated(2),
                repeated(3),
                repeated(4),
                7,
                repeated(5),
                0x0102030405060708L);
        assertArrayEquals(
                hex("1add0de5d6959627a9a546068984cd133b30d1f10870ec9e4c68539083aeeae7"),
                actual);
    }

    @Test
    void v4ResourceKeysMatchTheRustProtocolVectors() throws Exception {
        byte[] transportKey = ChallengeUtil.deriveResourceTransportKey(
                repeated(1), repeated(2), 7, repeated(3), "plugin", "1.2.3");
        byte[] methodKey = ChallengeUtil.deriveMethodKey(
                repeated(1), repeated(2), 7, repeated(3), "plugin", "1.2.3");
        assertArrayEquals(
                hex("65c5f2dad7eb61583e7ab30df7ebefcd260e092f2bf8a8537c90ea1ad65fb4b0"),
                transportKey);
        assertArrayEquals(
                hex("21e920e117963a013464111f672e1d374649b09ec19b9242c1e97775f3142396"),
                methodKey);
        assertArrayEquals(
                hex("536b794c6963656e7365207634207265736f757263652061616400"
                        + "0202020202020202020202020202020202020202020202020202020202020202"
                        + "00000007"
                        + "0303030303030303030303030303030303030303030303030303030303030303"
                        + "00000006706c7567696e00000005312e322e33"),
                ChallengeUtil.buildResourceAssociatedData(
                        repeated(2), 7, repeated(3), "plugin", "1.2.3"));
    }

    @Test
    void deliveryAcknowledgementMatchesTheRustProtocolVector() throws Exception {
        byte[] signature = ChallengeUtil.computeDeliveryAcknowledgement(
                repeated(1), repeated(2), 0x0102030405060708L, 1);
        assertArrayEquals(
                hex("10af39d561cef7e896178401f4bbee7a613ff9bf440771def5e4be19dd2f1c7f"),
                signature);
        assertTrue(ChallengeUtil.verifyDeliveryAcknowledgement(
                repeated(1), repeated(2), 0x0102030405060708L, 1, signature));

        signature[0] ^= 1;
        assertFalse(ChallengeUtil.verifyDeliveryAcknowledgement(
                repeated(1), repeated(2), 0x0102030405060708L, 1, signature));
    }

    private static byte[] repeated(int value) {
        byte[] output = new byte[32];
        java.util.Arrays.fill(output, (byte) value);
        return output;
    }

    private static byte[] hex(String value) {
        byte[] output = new byte[value.length() / 2];
        for (int index = 0; index < output.length; index++) {
            output[index] = (byte) Integer.parseInt(
                    value.substring(index * 2, index * 2 + 2), 16);
        }
        return output;
    }
}

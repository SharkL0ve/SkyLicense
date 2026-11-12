package cn.sky.skylicense.web.service;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TotpUtilTest {
    @Test
    void matchesRfc6238Sha1VectorsUsingSixDigits() {
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        try {
            assertEquals("287082", TotpUtil.codeAt(secret, 59L / 30L));
            assertEquals("081804", TotpUtil.codeAt(secret, 1_111_111_109L / 30L));
            assertEquals("050471", TotpUtil.codeAt(secret, 1_111_111_111L / 30L));
            assertEquals("005924", TotpUtil.codeAt(secret, 1_234_567_890L / 30L));
            assertEquals("279037", TotpUtil.codeAt(secret, 2_000_000_000L / 30L));
            assertEquals("353130", TotpUtil.codeAt(secret, 20_000_000_000L / 30L));
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    @Test
    void base32RoundTripsAndAcceptedTimeStepCannotReplay() {
        byte[] secret = new byte[TotpUtil.SECRET_BYTES];
        for (int index = 0; index < secret.length; index++) {
            secret[index] = (byte) (index + 1);
        }
        try {
            String encoded = TotpUtil.encodeBase32(secret);
            assertArrayEquals(secret, TotpUtil.decodeBase32(encoded));
            long epochSeconds = 1_800_000_000L;
            long step = epochSeconds / TotpUtil.PERIOD_SECONDS;
            String code = TotpUtil.codeAt(secret, step);
            assertEquals(step, TotpUtil.verify(secret, code, epochSeconds, 0));
            assertEquals(-1L, TotpUtil.verify(secret, code, epochSeconds, step));
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }
}

package cn.sky.license;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LicenseFileCodecTest {
    private static final String SECRET = "deployment-specific-license-secret-2026";

    @Test
    void versionedLicenseFileRoundTrips() throws Exception {
        byte[] encoded = LicenseFileCodec.encode("license-token", SECRET);
        assertEquals(
                "SKYLIC03",
                new String(Arrays.copyOf(encoded, 8), StandardCharsets.US_ASCII));
        assertEquals("license-token", LicenseFileCodec.decode(encoded, SECRET));
    }

    @Test
    void tamperingAndWrongDeploymentSecretAreRejected() throws Exception {
        byte[] encoded = LicenseFileCodec.encode("license-token", SECRET);
        encoded[encoded.length / 2] ^= 0x40;
        assertThrows(
                SecurityException.class,
                () -> LicenseFileCodec.decode(encoded, SECRET));

        byte[] authentic = LicenseFileCodec.encode("license-token", SECRET);
        assertThrows(
                SecurityException.class,
                () -> LicenseFileCodec.decode(
                        authentic,
                        "another-deployment-specific-secret-2026"));
    }

    @Test
    void shortSecretsAreRejectedBeforeCryptographicWork() {
        assertThrows(
                IllegalStateException.class,
                () -> LicenseFileCodec.encode("license-token", "short"));
    }
}

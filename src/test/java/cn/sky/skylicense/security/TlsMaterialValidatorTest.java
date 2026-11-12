package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsMaterialValidatorTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void validTls13CertificateAndPrivateKeyCompleteProofOfPossession() throws Exception {
        TlsTestMaterial.Material material = TlsTestMaterial.create(temporaryDirectory);
        TlsMaterialValidator.Summary summary = TlsMaterialValidator.validate(
                material.certificate(), material.privateKey(), null, "localhost");

        assertEquals(64, summary.leafSha256().length());
        assertTrue(summary.leafSubject().contains("CN=localhost"));
        assertTrue(summary.notAfter().isAfter(Instant.now()));
        assertEquals(1, summary.chainLength());
        assertEquals(2, summary.subjectAlternativeNameCount());
        assertEquals("localhost", summary.serverName());
    }

    @Test
    void mismatchedPrivateKeyIsRejectedByTlsHandshake() throws Exception {
        TlsTestMaterial.Material certificate = TlsTestMaterial.create(
                temporaryDirectory.resolve("certificate"));
        TlsTestMaterial.Material other = TlsTestMaterial.create(
                temporaryDirectory.resolve("other"));
        assertThrows(
                IllegalStateException.class,
                () -> TlsMaterialValidator.validate(
                        certificate.certificate(), other.privateKey(), null, "localhost"));
    }

    @Test
    void malformedCertificateIsRejectedBeforeListenerStartup() throws Exception {
        TlsTestMaterial.Material material = TlsTestMaterial.create(temporaryDirectory);
        Path malformed = temporaryDirectory.resolve("malformed.pem");
        Files.writeString(malformed, "not a certificate");
        assertThrows(
                IllegalStateException.class,
                () -> TlsMaterialValidator.validate(
                        malformed, material.privateKey(), null, "localhost"));
    }

    @Test
    void certificateChainMustNotContainPrivateKeyMaterial() throws Exception {
        TlsTestMaterial.Material material = TlsTestMaterial.create(temporaryDirectory);
        Path mixed = temporaryDirectory.resolve("mixed-chain.pem");
        Files.write(
                mixed,
                concat(Files.readAllBytes(material.certificate()),
                        Files.readAllBytes(material.privateKey())));

        assertThrows(
                IllegalStateException.class,
                () -> TlsMaterialValidator.validate(
                        mixed, material.privateKey(), null, "localhost"));
    }

    @Test
    void certificateMustMatchConfiguredExternalServerName() throws Exception {
        TlsTestMaterial.Material material = TlsTestMaterial.create(temporaryDirectory);

        assertThrows(
                IllegalStateException.class,
                () -> TlsMaterialValidator.validate(
                        material.certificate(),
                        material.privateKey(),
                        null,
                        "license.example.com"));
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] combined = new byte[first.length + second.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        return combined;
    }
}

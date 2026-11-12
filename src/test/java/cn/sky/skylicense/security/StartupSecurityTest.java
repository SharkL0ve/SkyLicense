package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StartupSecurityTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void bootstrapAdminRequiresLengthAndCharacterDiversity() {
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateAdminPasswordValue("admin123"));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateAdminPasswordValue("alllowercaseonly"));
        assertDoesNotThrow(
                () -> StartupSecurity.validateAdminPasswordValue("Admin#Secure-2026"));
        assertDoesNotThrow(
                () -> StartupSecurity.validateBootstrapAdminValue(true, null));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateBootstrapAdminValue(true, "Admin#Secure-2026"));
        assertDoesNotThrow(
                () -> StartupSecurity.validateBootstrapAdminValue(
                        false, "Admin#Secure-2026"));
    }

    @Test
    void clientBuildPolicyRequiresANonZeroAllowlistedBuild() {
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateClientBuildPolicy(0, List.of("09".repeat(32))));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateClientBuildPolicy(1, List.of()));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateClientBuildPolicy(1, List.of("00".repeat(32))));
        assertDoesNotThrow(
                () -> StartupSecurity.validateClientBuildPolicy(1, List.of("09".repeat(32))));

        byte[] buildId = new byte[32];
        java.util.Arrays.fill(buildId, (byte) 9);
        assertTrue(StartupSecurity.isClientBuildAllowed(
                1, List.of("09".repeat(32)), 1, buildId));
        assertFalse(StartupSecurity.isClientBuildAllowed(
                2, List.of("09".repeat(32)), 1, buildId));
    }

    @Test
    void webOriginsAreExactOriginsWithoutCredentialsOrWildcards() {
        assertDoesNotThrow(
                () -> StartupSecurity.validateWebOrigins(List.of()));
        assertDoesNotThrow(
                () -> StartupSecurity.validateWebOrigins(List.of("https://admin.example.com")));
        assertDoesNotThrow(
                () -> StartupSecurity.validateWebOrigins(List.of("http://localhost:3000")));
        assertDoesNotThrow(
                () -> StartupSecurity.validateWebOrigins(List.of("http://127.0.0.1:3000")));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateWebOrigins(List.of("http://admin.example.com")));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateWebOrigins(List.of("https://*.example.com")));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateWebOrigins(List.of("https://user@example.com")));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateWebOrigins(List.of("https://example.com/path")));
    }

    @Test
    void portsMustBeValidAndDistinct() {
        assertDoesNotThrow(() -> StartupSecurity.validatePorts(13331, 8080));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validatePorts(0, 8080));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validatePorts(13331, 13331));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validatePorts(13331, 65_536));
    }

    @Test
    void tlsPreflightRequiresTwoReadableNonEmptyFiles() throws Exception {
        TlsTestMaterial.Material material = TlsTestMaterial.create(temporaryDirectory);
        Path certificate = material.certificate();
        Path privateKey = material.privateKey();

        assertDoesNotThrow(
                () -> StartupSecurity.validateTlsFiles(
                        certificate.toString(), privateKey.toString(), "localhost"));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateTlsFiles(
                        certificate.toString(), certificate.toString(), "localhost"));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateTlsFiles(
                        certificate.toString(),
                        temporaryDirectory.resolve("missing.pem").toString(),
                        "localhost"));

        Path emptyPrivateKey = temporaryDirectory.resolve("empty-key.pem");
        Files.writeString(emptyPrivateKey, "");
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.validateTlsFiles(
                        certificate.toString(), emptyPrivateKey.toString(), "localhost"));
    }

    @Test
    void tlsServerNameMustBeAnUnambiguousDnsNameOrIpLiteral() {
        assertTrue(StartupSecurity.normalizeTlsServerName("LICENSE.example.com")
                .equals("license.example.com"));
        assertTrue(StartupSecurity.normalizeTlsServerName("127.0.0.1")
                .equals("127.0.0.1"));
        assertTrue(StartupSecurity.normalizeTlsServerName("2001:db8::1")
                .equals("2001:db8::1"));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.normalizeTlsServerName("https://license.example.com"));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.normalizeTlsServerName("license.example.com:13331"));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.normalizeTlsServerName("*.example.com"));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.normalizeTlsServerName("999.999.999.999"));
        assertThrows(
                IllegalStateException.class,
                () -> StartupSecurity.normalizeTlsServerName("license.example.com."));
    }
}

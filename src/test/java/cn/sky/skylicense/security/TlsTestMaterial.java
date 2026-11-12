package cn.sky.skylicense.security;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/** Generates short-lived TLS fixtures without committing private keys. */
final class TlsTestMaterial {
    private static final String STORE_PASSWORD = "SkyLicense-Test-Only#2026";

    private TlsTestMaterial() {
    }

    static Material create(Path directory) throws Exception {
        Files.createDirectories(directory);
        String identifier = UUID.randomUUID().toString();
        Path keyStorePath = directory.resolve("tls-" + identifier + ".p12");
        Path certificatePath = directory.resolve("tls-" + identifier + "-cert.pem");
        Path privateKeyPath = directory.resolve("tls-" + identifier + "-key.pem");

        try {
            runKeytool(keyStorePath);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            char[] password = STORE_PASSWORD.toCharArray();
            try (java.io.InputStream input = Files.newInputStream(keyStorePath)) {
                keyStore.load(input, password);
            }
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("test");
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("test", password);
            if (certificate == null || privateKey == null) {
                throw new IllegalStateException("keytool did not create the expected test identity");
            }
            writePem(certificatePath, "CERTIFICATE", certificate.getEncoded());
            writePem(privateKeyPath, "PRIVATE KEY", privateKey.getEncoded());
            return new Material(certificatePath, privateKeyPath);
        } finally {
            Files.deleteIfExists(keyStorePath);
        }
    }

    private static void runKeytool(Path keyStorePath) throws Exception {
        String executableName = System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).contains("win") ? "keytool.exe" : "keytool";
        Path bundledKeytool = Path.of(System.getProperty("java.home"), "bin", executableName);
        String executable = Files.isRegularFile(bundledKeytool)
                ? bundledKeytool.toString()
                : executableName;
        Process process = new ProcessBuilder(
                executable,
                "-genkeypair",
                "-alias", "test",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-sigalg", "SHA256withRSA",
                "-validity", "30",
                "-storetype", "PKCS12",
                "-keystore", keyStorePath.toString(),
                "-storepass", STORE_PASSWORD,
                "-keypass", STORE_PASSWORD,
                "-dname", "CN=localhost",
                "-ext", "SAN=dns:localhost,ip:127.0.0.1",
                "-ext", "KU=digitalSignature,keyEncipherment",
                "-ext", "EKU=serverAuth",
                "-noprompt")
                .redirectErrorStream(true)
                .start();
        byte[] output = process.getInputStream().readAllBytes();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("keytool timed out while creating TLS test material");
        }
        if (process.exitValue() != 0) {
            throw new IllegalStateException(
                    "keytool failed to create TLS test material: "
                            + new String(output, StandardCharsets.UTF_8));
        }
    }

    private static void writePem(Path path, String type, byte[] data) throws Exception {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(data);
        String pem = "-----BEGIN " + type + "-----\n"
                + body + "\n-----END " + type + "-----\n";
        Files.writeString(
                path,
                pem,
                StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
    }

    record Material(Path certificate, Path privateKey) {
    }
}

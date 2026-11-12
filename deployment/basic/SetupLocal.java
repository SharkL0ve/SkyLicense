import cn.sky.license.BasicLicenseClient;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Local-only provisioning with a short-lived localhost certificate. JDK 17+. */
public class SetupLocal {
    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !(args[0].equals("server") || args[0].equals("client"))) {
            throw new IllegalArgumentException("usage: SetupLocal.java server|client <new-directory>");
        }
        Path root = Paths.get(args[1]).toAbsolutePath().normalize();
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Directory already exists; keep it for future starts: " + root);
        char[] password = null;
        if (args[0].equals("server")) {
            String source = System.getenv("SKYLICENSE_SETUP_ADMIN_PASSWORD_FILE");
            if (source != null) {
                password = Files.readString(Paths.get(source), StandardCharsets.UTF_8).stripTrailing().toCharArray();
            } else {
                Console console = System.console();
                if (console == null) throw new IOException("Run setup in an interactive terminal to enter the initial admin password");
                password = console.readPassword("Initial admin password (12-128 characters, 3 character classes): ");
                char[] confirm = console.readPassword("Confirm password: ");
                if (!Arrays.equals(password, confirm)) throw new IOException("Passwords differ");
                Arrays.fill(confirm, '\0');
            }
            String value = new String(password);
            int classes = (value.matches(".*[A-Z].*") ? 1 : 0) + (value.matches(".*[a-z].*") ? 1 : 0)
                    + (value.matches(".*[0-9].*") ? 1 : 0) + (value.matches(".*[^A-Za-z0-9].*") ? 1 : 0);
            if (password.length < 12 || password.length > 128 || classes < 3 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
                throw new IOException("Password does not meet the required format");
            }
        }
        Files.createDirectory(root);
        restrict(root);
        directory(root.resolve("secrets"));
        if (args[0].equals("client")) {
            write(root.resolve("secrets/license-file-secret.txt"), randomHex());
            Path certificate = Paths.get("runtime/certs/auth-chain.pem");
            if (Files.isRegularFile(certificate)) {
                write(root.resolve("ca-cert.pem"), Files.readString(certificate, StandardCharsets.US_ASCII));
            }
            System.out.println("Customer directory prepared: " + root);
            return;
        }
        try {
            directory(root.resolve("resources"));
            directory(root.resolve("certs"));
            for (String name : Arrays.asList("operation-log-hmac", "mfa-encryption-key", "backup-hmac")) {
                write(root.resolve("secrets/" + name + ".txt"), randomHex());
            }
            write(root.resolve("secrets/bootstrap-admin.txt"), new String(password));
            createCertificate(root.resolve("certs"));
            write(root.resolve("config.json"), "{\n  \"debug\": false,\n  \"authPort\": 13331,\n"
                    + "  \"authTlsCertificateChain\": \"certs/auth-chain.pem\",\n"
                    + "  \"authTlsPrivateKey\": \"certs/auth-key.pem\",\n"
                    + "  \"authTlsServerName\": \"localhost\",\n"
                    + "  \"minimumClientSecurityEpoch\": 1,\n"
                    + "  \"allowedClientBuildIds\": [\"" + BasicLicenseClient.BUILD_ID + "\"],\n"
                    + "  \"webPort\": 18443,\n  \"allowedWebOrigins\": []\n}\n");
        } finally { Arrays.fill(password, '\0'); }
        System.out.println("Server directory prepared: " + root);
        System.out.println("Web: https://localhost:18443/ ; authentication: localhost:13331");
        System.out.println("The localhost certificate is for local use and expires in 30 days.");
    }

    private static void createCertificate(Path directory) throws Exception {
        Path storePath = directory.resolve("setup.p12");
        String password = randomHex();
        String binary = System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win") ? "keytool.exe" : "keytool";
        ProcessBuilder builder = new ProcessBuilder(Paths.get(System.getProperty("java.home"), "bin", binary).toString(),
                "-genkeypair", "-alias", "auth", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=localhost",
                "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-ext", "KU=digitalSignature,keyEncipherment", "-ext", "EKU=serverAuth",
                "-validity", "30", "-storetype", "PKCS12", "-keystore", storePath.toString(),
                "-storepass:env", "SKYLICENSE_SETUP_KEYSTORE_PASSWORD", "-keypass:env", "SKYLICENSE_SETUP_KEYSTORE_PASSWORD", "-noprompt");
        builder.environment().put("SKYLICENSE_SETUP_KEYSTORE_PASSWORD", password);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        if (!process.waitFor(45, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IOException("keytool timed out"); }
        if (process.exitValue() != 0) throw new IOException("keytool failed to generate localhost TLS material");
        restrict(storePath);
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(storePath)) { store.load(input, password.toCharArray()); }
            X509Certificate cert = (X509Certificate) store.getCertificate("auth");
            PrivateKey key = (PrivateKey) store.getKey("auth", password.toCharArray());
            write(directory.resolve("auth-chain.pem"), pem("CERTIFICATE", cert.getEncoded()));
            write(directory.resolve("auth-key.pem"), pem("PRIVATE KEY", key.getEncoded()));
        } finally { Files.deleteIfExists(storePath); }
    }

    private static String pem(String label, byte[] value) {
        return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(value)
                + "\n-----END " + label + "-----\n";
    }
    private static String randomHex() { byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); return HexFormat.of().formatHex(bytes); }
    private static void directory(Path path) throws IOException { Files.createDirectory(path); restrict(path); }
    private static void write(Path path, String value) throws IOException {
        Files.writeString(path, value, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW); restrict(path);
    }
    private static void restrict(Path path) throws IOException {
        if (Files.getFileAttributeView(path, PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(Files.isDirectory(path) ? "rwx------" : "rw-------"));
        } else {
            AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (acl == null) throw new IOException("Owner-only permissions are unavailable");
            acl.setAcl(Collections.singletonList(AclEntry.newBuilder().setType(AclEntryType.ALLOW)
                    .setPrincipal(Files.getOwner(path)).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build()));
        }
    }
}

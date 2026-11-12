package cn.sky.skylicense;

import cn.sky.skylicense.config.Configuration;
import cn.sky.skylicense.security.DeploymentBackup;
import cn.sky.skylicense.security.DeploymentLock;
import cn.sky.skylicense.security.DeploymentPreflight;
import cn.sky.skylicense.security.StartupSecurity;
import cn.sky.skylicense.web.WebApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public final class Server {
    private static final String VALIDATE_CONFIG_ARGUMENT = "--validate-config";
    private static final String CREATE_BACKUP_ARGUMENT = "--create-backup";
    private static final String VERIFY_BACKUP_ARGUMENT = "--verify-backup";
    private static final String EXTRACT_BACKUP_ARGUMENT = "--extract-backup";

    private static final String MAX_UPLOAD_FILE_SIZE = "64MB";
    private static final String MAX_UPLOAD_REQUEST_SIZE = "65MB";
    public static SkyLicense skyLicense;
    private static DeploymentLock deploymentLock;

    private Server() {
    }

    public static void main(String[] arguments) throws Exception {
        if (isValidationOnly(arguments)) {
            Configuration configuration = Configuration.loadRequired(new File("config.json"));
            DeploymentPreflight.Result result = DeploymentPreflight.validate(
                    new File(".").toPath(), configuration.getStorage());
            printValidationResult(result);
            return;
        }
        if (arguments.length == 2 && CREATE_BACKUP_ARGUMENT.equals(arguments[0])) {
            createBackup(Path.of(arguments[1]));
            return;
        }
        if (arguments.length == 2 && VERIFY_BACKUP_ARGUMENT.equals(arguments[0])) {
            printBackupResult("backup_verification", DeploymentBackup.verify(Path.of(arguments[1])));
            return;
        }
        if (arguments.length == 3 && EXTRACT_BACKUP_ARGUMENT.equals(arguments[0])) {
            DeploymentBackup.Summary summary = DeploymentBackup.extract(
                    Path.of(arguments[1]), Path.of(arguments[2]));
            printBackupResult("backup_extraction", summary);
            System.out.println("restore_private_key_required=true");
            System.out.println("restore_environment_secrets_required=true");
            return;
        }
        if (containsMaintenanceArgument(arguments)) {
            throw new IllegalArgumentException(
                    "maintenance arguments have an invalid form or cannot be combined");
        }
        holdDeploymentLock(DeploymentLock.acquire(Path.of(".")));
        try {
            startServer(arguments);
        } catch (Exception | Error failure) {
            releaseDeploymentLock();
            throw failure;
        }
    }

    private static void createBackup(Path destination) throws Exception {
        Configuration configuration = Configuration.loadRequired(new File("config.json"));
        try (DeploymentLock lock = DeploymentLock.acquire(Path.of("."))) {
            Path workingDirectory = lock.path().getParent();
            DeploymentPreflight.Result preflight = DeploymentPreflight.validate(
                    workingDirectory, configuration.getStorage());
            DeploymentBackup.Summary summary = DeploymentBackup.create(
                    workingDirectory, configuration.getStorage(), preflight, destination);
            printBackupResult("backup_creation", summary);
        }
    }

    private static void printBackupResult(String operation, DeploymentBackup.Summary result) {
        System.out.println(operation + "=ok");
        System.out.println("backup_archive=" + result.archive());
        System.out.println("backup_created_at=" + result.createdAt());
        System.out.println("backup_database_schema_version=" + result.databaseSchemaVersion());
        System.out.println("backup_protected_resource_count=" + result.protectedResourceCount());
        System.out.println("backup_file_count=" + result.fileCount());
        System.out.println("backup_uncompressed_bytes=" + result.uncompressedBytes());
        System.out.println("backup_tls_certificate_included=" + result.tlsCertificateIncluded());
        System.out.println("backup_tls_private_key_included=" + result.tlsPrivateKeyIncluded());
    }

    private static void startServer(String[] arguments) throws IOException {
        DeploymentPreflight.Result preflight = DeploymentPreflight.validate(
                Path.of("."), SkyLicense.configuration().getStorage());
        var tls = preflight.tls();
        long certificateDays = Duration.between(Instant.now(), tls.notAfter()).toDays();
        if (certificateDays < 30) {
            SkyLicense.LOG.warn(
                    "TLS leaf certificate expires soon: serverName={}, subject={}, "
                            + "notAfter={}, daysRemaining={}",
                    tls.serverName(), tls.leafSubject(), tls.notAfter(), certificateDays);
        } else {
            SkyLicense.LOG.info(
                    "TLS material validated: serverName={}, leafSha256={}, "
                            + "notAfter={}, chainLength={}",
                    tls.serverName(), tls.leafSha256(), tls.notAfter(), tls.chainLength());
        }
        skyLicense = SkyLicense.start();

        int webPort = SkyLicense.configuration().getStorage().getWebPort();
        File certificate = new File(SkyLicense.configuration()
                .getStorage()
                .getAuthTlsCertificateChain())
                .getCanonicalFile();
        File privateKey = new File(SkyLicense.configuration()
                .getStorage()
                .getAuthTlsPrivateKey())
                .getCanonicalFile();
        Map<String, Object> properties = new HashMap<>();
        properties.put("server.port", webPort);
        properties.put("server.ssl.enabled", true);
        properties.put("server.ssl.enabled-protocols", "TLSv1.3");
        properties.put("server.ssl.certificate", certificate.toURI().toString());
        properties.put("server.ssl.certificate-private-key", privateKey.toURI().toString());
        properties.put("server.forward-headers-strategy", "none");
        properties.put("server.max-http-request-header-size", "16KB");
        properties.put("server.shutdown", "graceful");
        properties.put("spring.lifecycle.timeout-per-shutdown-phase", "15s");
        properties.put("server.error.include-message", "never");
        properties.put("server.error.include-stacktrace", "never");
        properties.put("server.error.include-exception", false);
        properties.put("server.error.whitelabel.enabled", false);
        properties.put("spring.main.banner-mode", "off");
        properties.put("server.undertow.max-http-post-size", "2MB");
        properties.put("spring.servlet.multipart.max-file-size", MAX_UPLOAD_FILE_SIZE);
        properties.put("spring.servlet.multipart.max-request-size", MAX_UPLOAD_REQUEST_SIZE);

        String privateKeyPassword = StartupSecurity.tlsPrivateKeyPassword();
        if (privateKeyPassword != null && !privateKeyPassword.isEmpty()) {
            properties.put("server.ssl.key-password", privateKeyPassword);
        }

        SpringApplication application = new SpringApplication(WebApplication.class);
        application.setDefaultProperties(properties);
        try {
            ConfigurableApplicationContext context = application.run(arguments);
            skyLicense.attachWebApplicationContext(context);
        } catch (RuntimeException | Error failure) {
            skyLicense.shutdownServices();
            skyLicense.getWebDataAccessor().close();
            throw failure;
        }
        SkyLicense.LOG.info("Web service started with mandatory TLS 1.3 on port {}", webPort);
    }

    private static synchronized void holdDeploymentLock(DeploymentLock lock) throws IOException {
        if (deploymentLock != null) {
            lock.close();
            throw new IOException("the deployment lock is already held by this process");
        }
        deploymentLock = lock;
    }

    public static synchronized void releaseDeploymentLock() {
        DeploymentLock current = deploymentLock;
        deploymentLock = null;
        if (current == null) {
            return;
        }
        try {
            current.close();
        } catch (IOException error) {
            SkyLicense.LOG.warn("Unable to release deployment lock {}", current.path(), error);
        }
    }

    private static boolean isValidationOnly(String[] arguments) {
        return arguments.length == 1 && VALIDATE_CONFIG_ARGUMENT.equals(arguments[0]);
    }

    private static boolean containsMaintenanceArgument(String[] arguments) {
        return Arrays.stream(arguments).anyMatch(argument ->
                VALIDATE_CONFIG_ARGUMENT.equals(argument)
                        || CREATE_BACKUP_ARGUMENT.equals(argument)
                        || VERIFY_BACKUP_ARGUMENT.equals(argument)
                        || EXTRACT_BACKUP_ARGUMENT.equals(argument));
    }

    private static void printValidationResult(DeploymentPreflight.Result result) {
        System.out.println("deployment_validation=ok");
        System.out.println("working_directory=" + result.workingDirectory());
        System.out.println("tls_leaf_sha256=" + result.tls().leafSha256());
        System.out.println("tls_not_after=" + result.tls().notAfter());
        System.out.println("tls_days_remaining=" + result.certificateDaysRemaining());
        System.out.println("tls_chain_length=" + result.tls().chainLength());
        System.out.println("tls_server_name=" + result.tls().serverName());
        System.out.println("database_exists=" + result.database().exists());
        System.out.println("database_schema_version=" + result.database().schemaVersion());
        System.out.println(
                "active_administrator=" + result.database().activeAdministratorExists());
        System.out.println("protected_resource_count=" + result.resourceCount());
    }
}

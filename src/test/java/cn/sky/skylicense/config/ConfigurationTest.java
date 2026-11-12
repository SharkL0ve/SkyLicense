package cn.sky.skylicense.config;

import com.google.gson.GsonBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigurationTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void requiredConfigurationDoesNotCreateAStartupTemplate() {
        Path path = temporaryDirectory.resolve("missing-config.json");
        assertThrows(
                IllegalStateException.class,
                () -> Configuration.loadRequired(path.toFile()));
        assertFalse(Files.exists(path));
    }

    @Test
    void missingConfigurationIsCreatedAtomicallyAndCanLoadStricterPolicy() throws Exception {
        Path path = temporaryDirectory.resolve("config.json");
        Configuration configuration = new Configuration(path.toFile());

        assertTrue(Files.isRegularFile(path));
        assertTrue(Files.readString(path, StandardCharsets.UTF_8).contains("allowedClientBuildIds"));

        writeConfiguration(path, true, 13331, 2, List.of("09".repeat(32)), List.of());
        assertTrue(configuration.reload());
        assertTrue(configuration.getStorage().isDebug());
        assertEquals(2, configuration.getStorage().getMinimumClientSecurityEpoch());
        assertEquals(List.of("09".repeat(32)),
                configuration.getStorage().getAllowedClientBuildIds());
    }

    @Test
    void reloadRejectsRestartOnlyChangesRollbackAndMalformedJson() throws Exception {
        Path path = temporaryDirectory.resolve("config.json");
        writeConfiguration(path, false, 13331, 2, List.of("09".repeat(32)), List.of());
        Configuration configuration = new Configuration(path.toFile());

        writeConfiguration(path, false, 13332, 2, List.of("09".repeat(32)), List.of());
        assertFalse(configuration.reload());
        assertEquals(13331, configuration.getStorage().getAuthPort());

        writeConfiguration(path, false, 13331, 1, List.of("09".repeat(32)), List.of());
        assertFalse(configuration.reload());
        assertEquals(2, configuration.getStorage().getMinimumClientSecurityEpoch());

        Files.writeString(path, "{", StandardCharsets.UTF_8);
        assertFalse(configuration.reload());
        assertEquals(2, configuration.getStorage().getMinimumClientSecurityEpoch());
    }

    @Test
    void reloadRejectsUnknownDuplicateAndMissingFields() throws Exception {
        Path path = temporaryDirectory.resolve("config.json");
        writeConfiguration(path, false, 13331, 2, List.of("09".repeat(32)), List.of());
        Configuration configuration = new Configuration(path.toFile());
        String valid = Files.readString(path, StandardCharsets.UTF_8);

        Files.writeString(
                path,
                valid.replace("\"debug\": false,", "\"debug\": false,\n  \"unknown\": 1,"),
                StandardCharsets.UTF_8);
        assertFalse(configuration.reload());

        Files.writeString(
                path,
                valid.replace("\"debug\": false,", "\"debug\": false,\n  \"debug\": true,"),
                StandardCharsets.UTF_8);
        assertFalse(configuration.reload());

        Files.writeString(
                path,
                valid.replace("  \"debug\": false,\n", ""),
                StandardCharsets.UTF_8);
        assertFalse(configuration.reload());
        assertFalse(configuration.getStorage().isDebug());
        assertEquals(2, configuration.getStorage().getMinimumClientSecurityEpoch());
    }

    private static void writeConfiguration(
            Path path,
            boolean debug,
            int authPort,
            int minimumEpoch,
            List<String> buildIds,
            List<String> origins
    ) throws Exception {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("debug", debug);
        values.put("authPort", authPort);
        values.put("authTlsCertificateChain", "certs/auth-chain.pem");
        values.put("authTlsPrivateKey", "certs/auth-key.pem");
        values.put("authTlsServerName", "localhost");
        values.put("minimumClientSecurityEpoch", minimumEpoch);
        values.put("allowedClientBuildIds", buildIds);
        values.put("webPort", 8080);
        values.put("allowedWebOrigins", origins);
        Files.writeString(
                path,
                new GsonBuilder().setPrettyPrinting().create().toJson(values),
                StandardCharsets.UTF_8);
    }
}

package cn.sky.skylicense.config;

import cn.sky.skylicense.netty.SessionManager;
import cn.sky.skylicense.security.StartupSecurity;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Loads the process configuration and applies only explicitly safe reloads. */
public final class Configuration {
    private static final Logger LOG = LogManager.getLogger(Configuration.class);
    private static final long MAX_CONFIG_BYTES = 1024L * 1024L;
    private static final int MAX_BUILD_IDS = 1024;
    private static final int MAX_WEB_ORIGINS = 256;
    private static final Set<String> REQUIRED_FIELDS = Set.of(
            "debug",
            "authPort",
            "authTlsCertificateChain",
            "authTlsPrivateKey",
            "authTlsServerName",
            "minimumClientSecurityEpoch",
            "allowedClientBuildIds",
            "webPort",
            "allowedWebOrigins");

    @Getter
    private volatile Storage storage;
    private final File configFile;
    public final Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    public Configuration(File file) {
        this(file, true);
    }

    public static Configuration loadRequired(File file) {
        return new Configuration(file, false);
    }

    private Configuration(File file, boolean createWhenMissing) {
        this.configFile = Objects.requireNonNull(file, "configuration file");
        try {
            if (!configFile.exists()) {
                if (!createWhenMissing) {
                    throw new IllegalStateException(
                            "Required configuration file does not exist: " + configFile.getAbsolutePath());
                }
                storage = new Storage();
                save();
                return;
            }
            storage = readStorage();
        } catch (IOException error) {
            throw new IllegalStateException("Unable to read configuration: " + configFile, error);
        }
    }

    /**
     * Reloads policy fields atomically. Ports, TLS files and CORS are bound at startup and
     * therefore require a process restart. A lower minimum epoch is never accepted.
     */
    public synchronized boolean reload() {
        if (!configFile.isFile()) {
            LOG.error("Configuration reload rejected: file does not exist");
            return false;
        }
        try {
            Storage loaded = readStorage();
            StartupSecurity.validate(loaded);
            validateReloadBoundary(storage, loaded);
            int revoked;
            synchronized (SessionManager.class) {
                storage = loaded;
                revoked = SessionManager.revokeSessionsNotMatching(loaded);
            }
            LOG.info(
                    "Configuration reloaded successfully; revoked {} incompatible client sessions",
                    revoked);
            return true;
        } catch (Exception error) {
            LOG.error(
                    "Configuration reload rejected; previous configuration remains active: {}",
                    error.getMessage());
            return false;
        }
    }

    /** Writes a complete snapshot and replaces the previous file atomically when supported. */
    public synchronized void save() {
        Path destination = configFile.toPath().toAbsolutePath().normalize();
        Path parent = destination.getParent();
        if (parent == null) {
            throw new IllegalStateException("configuration path has no parent directory");
        }
        Path temporary = null;
        try {
            Files.createDirectories(parent);
            temporary = Files.createTempFile(parent, "." + destination.getFileName(), ".part");
            try (FileChannel channel = FileChannel.open(
                    temporary,
                    StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS)) {
                Writer writer = new OutputStreamWriter(
                        Channels.newOutputStream(channel), StandardCharsets.UTF_8);
                gson.toJson(storage, writer);
                writer.flush();
                channel.force(true);
                writer.close();
            }
            try {
                Files.move(
                        temporary,
                        destination,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING);
            }
            temporary = null;
        } catch (IOException error) {
            throw new IllegalStateException("Unable to save configuration: " + destination, error);
        } finally {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException cleanupError) {
                    LOG.warn("Unable to remove temporary configuration file", cleanupError);
                }
            }
        }
    }

    static void validateReloadBoundary(Storage current, Storage candidate) {
        if (current == null) {
            return;
        }
        if (current.getAuthPort() != candidate.getAuthPort()
                || current.getWebPort() != candidate.getWebPort()
                || !Objects.equals(
                        current.getAuthTlsCertificateChain(), candidate.getAuthTlsCertificateChain())
                || !Objects.equals(
                        current.getAuthTlsPrivateKey(), candidate.getAuthTlsPrivateKey())
                || !Objects.equals(
                        current.getAuthTlsServerName(), candidate.getAuthTlsServerName())
                || !Objects.equals(
                        current.getAllowedWebOrigins(), candidate.getAllowedWebOrigins())) {
            throw new IllegalStateException(
                    "ports, TLS identity and allowedWebOrigins require a service restart");
        }
        if (candidate.getMinimumClientSecurityEpoch()
                < current.getMinimumClientSecurityEpoch()) {
            throw new IllegalStateException(
                    "minimumClientSecurityEpoch cannot decrease during reload");
        }
    }

    private Storage readStorage() throws IOException {
        Path path = configFile.toPath().toAbsolutePath().normalize();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("configuration must be a regular non-link file");
        }
        long size = Files.size(path);
        if (size <= 0 || size > MAX_CONFIG_BYTES) {
            throw new IllegalStateException(
                    "configuration size must be between 1 byte and " + MAX_CONFIG_BYTES + " bytes");
        }

        try (BufferedReader buffered = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            JsonReader reader = new JsonReader(buffered);
            reader.setStrictness(Strictness.STRICT);
            reader.setNestingLimit(4);
            Set<String> seen = new HashSet<>();
            boolean debug = false;
            int authPort = 0;
            String certificate = null;
            String privateKey = null;
            String serverName = null;
            int minimumEpoch = 0;
            List<String> buildIds = null;
            int webPort = 0;
            List<String> webOrigins = null;

            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                if (!REQUIRED_FIELDS.contains(name)) {
                    throw new IllegalStateException("unknown configuration field: " + name);
                }
                if (!seen.add(name)) {
                    throw new IllegalStateException("duplicate configuration field: " + name);
                }
                switch (name) {
                    case "debug" -> debug = reader.nextBoolean();
                    case "authPort" -> authPort = reader.nextInt();
                    case "authTlsCertificateChain" -> certificate = reader.nextString();
                    case "authTlsPrivateKey" -> privateKey = reader.nextString();
                    case "authTlsServerName" -> serverName = reader.nextString();
                    case "minimumClientSecurityEpoch" -> minimumEpoch = reader.nextInt();
                    case "allowedClientBuildIds" -> buildIds = readStringArray(
                            reader, MAX_BUILD_IDS, 64, "allowedClientBuildIds");
                    case "webPort" -> webPort = reader.nextInt();
                    case "allowedWebOrigins" -> webOrigins = readStringArray(
                            reader, MAX_WEB_ORIGINS, 512, "allowedWebOrigins");
                    default -> throw new IllegalStateException(
                            "unsupported configuration field: " + name);
                }
            }
            reader.endObject();
            if (!seen.equals(REQUIRED_FIELDS)) {
                Set<String> missing = new HashSet<>(REQUIRED_FIELDS);
                missing.removeAll(seen);
                throw new IllegalStateException("missing configuration fields: " + missing);
            }
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                throw new IllegalStateException("configuration contains trailing data");
            }
            Storage loaded = new Storage(
                    debug,
                    authPort,
                    certificate,
                    privateKey,
                    serverName,
                    minimumEpoch,
                    buildIds,
                    webPort,
                    webOrigins);
            reader.close();
            return loaded;
        }
    }

    private static List<String> readStringArray(
            JsonReader reader,
            int maximumEntries,
            int maximumCharacters,
            String field
    ) throws IOException {
        List<String> values = new ArrayList<>();
        reader.beginArray();
        while (reader.hasNext()) {
            if (values.size() >= maximumEntries) {
                throw new IllegalStateException(field + " contains too many entries");
            }
            String value = reader.nextString();
            if (value.length() > maximumCharacters) {
                throw new IllegalStateException(field + " contains an oversized entry");
            }
            values.add(value);
        }
        reader.endArray();
        return List.copyOf(values);
    }
}

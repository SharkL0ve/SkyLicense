package cn.sky.skylicense.config;

import com.google.gson.annotations.SerializedName;
import lombok.Getter;

import java.util.List;

@Getter
public class Storage {
    @SerializedName("debug")
    private final boolean debug;
    @SerializedName("authPort")
    private final int authPort;
    @SerializedName("authTlsCertificateChain")
    private final String authTlsCertificateChain;
    @SerializedName("authTlsPrivateKey")
    private final String authTlsPrivateKey;
    @SerializedName("authTlsServerName")
    private final String authTlsServerName;
    @SerializedName("minimumClientSecurityEpoch")
    private final int minimumClientSecurityEpoch;
    @SerializedName("allowedClientBuildIds")
    private final List<String> allowedClientBuildIds;
    @SerializedName("webPort")
    private final int webPort;
    @SerializedName("allowedWebOrigins")
    private final List<String> allowedWebOrigins;

    public Storage() {
        this(
                false,
                13331,
                "certs/auth-chain.pem",
                "certs/auth-key.pem",
                "localhost",
                1,
                List.of(),
                8080,
                List.of());
    }

    Storage(
            boolean debug,
            int authPort,
            String authTlsCertificateChain,
            String authTlsPrivateKey,
            String authTlsServerName,
            int minimumClientSecurityEpoch,
            List<String> allowedClientBuildIds,
            int webPort,
            List<String> allowedWebOrigins
    ) {
        this.debug = debug;
        this.authPort = authPort;
        this.authTlsCertificateChain = authTlsCertificateChain;
        this.authTlsPrivateKey = authTlsPrivateKey;
        this.authTlsServerName = authTlsServerName;
        this.minimumClientSecurityEpoch = minimumClientSecurityEpoch;
        this.allowedClientBuildIds = List.copyOf(allowedClientBuildIds);
        this.webPort = webPort;
        this.allowedWebOrigins = List.copyOf(allowedWebOrigins);
    }

    public List<String> getAllowedClientBuildIds() {
        return allowedClientBuildIds == null ? null : List.copyOf(allowedClientBuildIds);
    }

    public List<String> getAllowedWebOrigins() {
        return allowedWebOrigins == null ? null : List.copyOf(allowedWebOrigins);
    }
}

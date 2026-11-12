package cn.sky.skylicense.netty;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.config.Storage;
import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.security.StartupSecurity;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/** Maintains opaque, server-issued session leases and heartbeat replay state. */
public final class SessionManager {
    static final long ACTIVE_LEASE_NANOS = TimeUnit.SECONDS.toNanos(90);
    static final long RETENTION_NANOS = TimeUnit.MINUTES.toNanos(5);
    private static final int MAX_RETAINED_SESSIONS = 100_000;
    private static final ConcurrentHashMap<String, SessionInfo> ACTIVE_SESSIONS =
            new ConcurrentHashMap<>();
    private static boolean acceptingRegistrations = true;

    private SessionManager() {
    }

    public static synchronized boolean registerSessionWithCurrentPolicy(
            byte[] sessionId,
            String clientIp,
            String userName,
            String pluginName,
            String pluginVersion,
            String resourceContentSha256,
            long authLogId,
            byte[] sessionKey,
            String hwid,
            int securityEpoch,
            byte[] buildId
    ) {
        Storage policy = SkyLicense.configuration().getStorage();
        if (!StartupSecurity.isClientBuildAllowed(policy, securityEpoch, buildId)) {
            return false;
        }
        if (authLogId <= 0) {
            return false;
        }
        String pluginIdentifier = resourceIdentifier(pluginName, pluginVersion);
        if (pluginIdentifier == null
                || !ResourceManager.contentMatches(pluginIdentifier, resourceContentSha256)) {
            return false;
        }
        boolean registered = registerSessionInternal(
                sessionId,
                clientIp,
                userName,
                pluginName,
                pluginVersion,
                resourceContentSha256,
                authLogId,
                sessionKey,
                hwid,
                securityEpoch,
                buildId);
        if (!registered) {
            return false;
        }
        if (!ResourceManager.contentMatches(pluginIdentifier, resourceContentSha256)) {
            destroySession(sessionId);
            return false;
        }
        return true;
    }

    public static synchronized boolean registerSession(
            byte[] sessionId,
            String clientIp,
            String userName,
            String pluginName,
            byte[] sessionKey,
            String hwid,
            int securityEpoch,
            byte[] buildId
    ) {
        return registerSession(
                sessionId, clientIp, userName, pluginName, "", sessionKey,
                hwid, securityEpoch, buildId);
    }

    /** Support overload that records the exact protected resource version. */
    public static synchronized boolean registerSession(
            byte[] sessionId,
            String clientIp,
            String userName,
            String pluginName,
            String pluginVersion,
            byte[] sessionKey,
            String hwid,
            int securityEpoch,
            byte[] buildId
    ) {
        String pluginIdentifier = resourceIdentifier(pluginName, pluginVersion);
        return registerSession(
                sessionId, clientIp, userName, pluginName, pluginVersion,
                ResourceManager.currentContentSha256(pluginIdentifier), 0,
                sessionKey, hwid, securityEpoch, buildId);
    }

    /** Support overload that also binds the pending authorization log. */
    public static synchronized boolean registerSession(
            byte[] sessionId,
            String clientIp,
            String userName,
            String pluginName,
            String pluginVersion,
            long authLogId,
            byte[] sessionKey,
            String hwid,
            int securityEpoch,
            byte[] buildId
    ) {
        String pluginIdentifier = resourceIdentifier(pluginName, pluginVersion);
        return registerSession(
                sessionId,
                clientIp,
                userName,
                pluginName,
                pluginVersion,
                ResourceManager.currentContentSha256(pluginIdentifier),
                authLogId,
                sessionKey,
                hwid,
                securityEpoch,
                buildId);
    }

    /** Support overload that records a specific protected-resource content digest. */
    static synchronized boolean registerSession(
            byte[] sessionId,
            String clientIp,
            String userName,
            String pluginName,
            String pluginVersion,
            String resourceContentSha256,
            long authLogId,
            byte[] sessionKey,
            String hwid,
            int securityEpoch,
            byte[] buildId
    ) {
        return registerSessionInternal(
                sessionId,
                clientIp,
                userName,
                pluginName,
                pluginVersion,
                resourceContentSha256,
                authLogId,
                sessionKey,
                hwid,
                securityEpoch,
                buildId);
    }

    private static boolean registerSessionInternal(
            byte[] sessionId,
            String clientIp,
            String userName,
            String pluginName,
            String pluginVersion,
            String resourceContentSha256,
            long authLogId,
            byte[] sessionKey,
            String hwid,
            int securityEpoch,
            byte[] buildId
    ) {
        if (!acceptingRegistrations
                || !validSecret(sessionId)
                || !validSecret(sessionKey)
                || !validSecret(buildId)
                || securityEpoch <= 0
                || clientIp == null || clientIp.isBlank()
                || userName == null || userName.isBlank()
                || pluginName == null || pluginName.isBlank()
                || pluginVersion == null
                || authLogId < 0
                || hwid == null || hwid.isBlank()) {
            return false;
        }
        String encodedId = encodeSessionId(sessionId);
        if (ACTIVE_SESSIONS.containsKey(encodedId)) {
            return false;
        }
        if (ACTIVE_SESSIONS.size() >= MAX_RETAINED_SESSIONS) {
            cleanupStaleSessionsAt(System.nanoTime());
            if (ACTIVE_SESSIONS.size() >= MAX_RETAINED_SESSIONS) {
                SkyLicense.LOG.warn("Session capacity reached; rejecting a new session");
                return false;
            }
        }
        SessionInfo replacement = new SessionInfo(
                clientIp,
                userName,
                pluginName,
                pluginVersion,
                resourceContentSha256,
                authLogId,
                sessionKey,
                hwid,
                securityEpoch,
                buildId,
                System.currentTimeMillis(),
                System.nanoTime());
        SessionInfo previous = ACTIVE_SESSIONS.putIfAbsent(encodedId, replacement);
        if (previous != null) {
            replacement.destroy();
            return false;
        }
        SkyLicense.LOG.info("Session registered for plugin " + pluginName);
        return true;
    }

    /** Opens the registration gate for a fresh server lifecycle. */
    public static synchronized void beginStartup() {
        if (!ACTIVE_SESSIONS.isEmpty()) {
            throw new IllegalStateException("cannot start while retained sessions still exist");
        }
        acceptingRegistrations = true;
    }

    /** Prevents in-flight handshakes from registering after shutdown has begun. */
    public static synchronized void stopAcceptingRegistrations() {
        acceptingRegistrations = false;
    }

    public static SessionInfo getSession(byte[] sessionId) {
        return ACTIVE_SESSIONS.get(encodeSessionId(sessionId));
    }

    public static SessionInfo getSession(String encodedId) {
        return ACTIVE_SESSIONS.get(encodedId);
    }

    public static void revokeSession(String encodedId) {
        SessionInfo info = ACTIVE_SESSIONS.get(encodedId);
        if (info != null) {
            info.revoke();
            SkyLicense.LOG.info("Session revoked");
        }
    }

    public static void destroySession(byte[] sessionId) {
        SessionInfo info = ACTIVE_SESSIONS.remove(encodeSessionId(sessionId));
        if (info != null) {
            info.destroy();
        }
    }

    public static boolean isSessionActive(String encodedId) {
        SessionInfo info = ACTIVE_SESSIONS.get(encodedId);
        return info != null && info.isActive();
    }

    public static int getActiveSessionCount() {
        return Math.toIntExact(ACTIVE_SESSIONS.values().stream()
                .filter(SessionInfo::isActive)
                .count());
    }

    public static Map<String, SessionInfo> getAllSessions() {
        return Collections.unmodifiableMap(new HashMap<>(ACTIVE_SESSIONS));
    }

    public static synchronized void cleanupStaleSessions() {
        cleanupStaleSessionsAt(System.nanoTime());
    }

    /** Revokes leases that no longer satisfy policy while retaining keys for signed REVOKE. */
    public static synchronized int revokeSessionsNotMatching(Storage storage) {
        int revoked = 0;
        for (Map.Entry<String, SessionInfo> entry : ACTIVE_SESSIONS.entrySet()) {
            SessionInfo info = entry.getValue();
            if (StartupSecurity.isClientBuildAllowed(
                    storage, info.getSecurityEpoch(), info.getBuildId())) {
                continue;
            }
            if (!info.isRevoked()) {
                info.revoke();
                revoked++;
            }
        }
        return revoked;
    }

    /** Destroys every active or retained lease during process shutdown. */
    public static synchronized int destroyAllSessions() {
        int destroyed = 0;
        for (Map.Entry<String, SessionInfo> entry : ACTIVE_SESSIONS.entrySet()) {
            if (ACTIVE_SESSIONS.remove(entry.getKey(), entry.getValue())) {
                entry.getValue().destroy();
                destroyed++;
            }
        }
        return destroyed;
    }

    /** Revokes leases issued for a removed resource while retaining keys for signed REVOKE. */
    public static synchronized int revokeSessionsForResource(
            String pluginName,
            String pluginVersion
    ) {
        String identifier = resourceIdentifier(pluginName, pluginVersion);
        return identifier == null
                ? 0
                : revokeSessionsForResources(Collections.singleton(identifier));
    }

    /** Revokes leases for all resource identities removed by an atomic reload. */
    public static synchronized int revokeSessionsForResources(
            java.util.Set<String> identifiers
    ) {
        if (identifiers == null || identifiers.isEmpty()) {
            return 0;
        }
        int revoked = 0;
        for (Map.Entry<String, SessionInfo> entry : ACTIVE_SESSIONS.entrySet()) {
            SessionInfo info = entry.getValue();
            if (!identifiers.contains(info.getPluginIdentifier())) {
                continue;
            }
            if (!info.isRevoked()) {
                info.revoke();
                revoked++;
            }
        }
        return revoked;
    }

    private static void cleanupStaleSessionsAt(long nowNanos) {
        ACTIVE_SESSIONS.entrySet().removeIf(entry -> {
            SessionInfo info = entry.getValue();
            if (!info.retentionElapsed(nowNanos)) {
                return false;
            }
            info.destroy();
            return true;
        });
    }

    private static String encodeSessionId(byte[] sessionId) {
        if (sessionId == null || sessionId.length != 32) {
            throw new IllegalArgumentException("session id must contain 32 bytes");
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sessionId);
    }

    private static boolean validSecret(byte[] value) {
        if (value == null || value.length != 32) {
            return false;
        }
        int aggregate = 0;
        for (byte item : value) {
            aggregate |= item;
        }
        return aggregate != 0;
    }

    private static String resourceIdentifier(String pluginName, String pluginVersion) {
        if (pluginName == null || pluginVersion == null) {
            return null;
        }
        try {
            return ResourceManager.identifier(pluginName, pluginVersion);
        } catch (IllegalArgumentException error) {
            return null;
        }
    }

    public static final class SessionInfo {
        private final String clientIp;
        private final String userName;
        private final String pluginName;
        private final String pluginVersion;
        private final String pluginIdentifier;
        private final String resourceContentSha256;
        private final long authLogId;
        private final byte[] sessionKey;
        private final String hwid;
        private final int securityEpoch;
        private final byte[] buildId;
        private final long createdAt;
        private volatile long lastHeartbeatEpochMillis;
        private volatile long lastHeartbeatNanos;
        private volatile long lastClientTimestamp;
        private volatile boolean revoked;
        private byte[] environmentBaseline;

        SessionInfo(
                String clientIp,
                String userName,
                String pluginName,
                String pluginVersion,
                String resourceContentSha256,
                long authLogId,
                byte[] sessionKey,
                String hwid,
                int securityEpoch,
                byte[] buildId,
                long createdAtEpochMillis,
                long createdAtNanos
        ) {
            this.clientIp = clientIp;
            this.userName = userName;
            this.pluginName = pluginName;
            this.pluginVersion = pluginVersion;
            this.pluginIdentifier = resourceIdentifier(pluginName, pluginVersion);
            this.resourceContentSha256 = resourceContentSha256;
            this.authLogId = authLogId;
            this.sessionKey = sessionKey.clone();
            this.hwid = hwid;
            this.securityEpoch = securityEpoch;
            this.buildId = buildId.clone();
            this.createdAt = createdAtEpochMillis;
            this.lastHeartbeatEpochMillis = createdAtEpochMillis;
            this.lastHeartbeatNanos = createdAtNanos;
        }

        public synchronized boolean acceptHeartbeat(
                long clientTimestamp,
                String observedHwid,
                byte[] environmentEvidence
        ) {
            long nowEpochMillis = System.currentTimeMillis();
            return acceptHeartbeatAt(
                    clientTimestamp,
                    observedHwid,
                    environmentEvidence,
                    nowEpochMillis / 1000L,
                    nowEpochMillis,
                    System.nanoTime());
        }

        synchronized boolean acceptHeartbeatAt(
                long clientTimestamp,
                String observedHwid,
                byte[] environmentEvidence,
                long nowEpochSeconds,
                long nowEpochMillis,
                long nowNanos
        ) {
            if (revoked
                    || elapsedAtLeast(nowNanos, lastHeartbeatNanos, ACTIVE_LEASE_NANOS)
                    || clientTimestamp < nowEpochSeconds - 60
                    || clientTimestamp > nowEpochSeconds + 60
                    || clientTimestamp <= lastClientTimestamp
                    || environmentEvidence == null
                    || environmentEvidence.length != 32
                    || (environmentBaseline != null
                    && !MessageDigest.isEqual(environmentBaseline, environmentEvidence))
                    || observedHwid == null
                    || !MessageDigest.isEqual(
                            hwid.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                            observedHwid.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                revoked = true;
                return false;
            }
            if (environmentBaseline == null) {
                environmentBaseline = environmentEvidence.clone();
            }
            lastClientTimestamp = clientTimestamp;
            lastHeartbeatEpochMillis = nowEpochMillis;
            lastHeartbeatNanos = nowNanos;
            return true;
        }

        public boolean isActive() {
            return isActiveAt(System.nanoTime());
        }

        boolean isActiveAt(long nowNanos) {
            return !revoked
                    && !elapsedAtLeast(nowNanos, lastHeartbeatNanos, ACTIVE_LEASE_NANOS);
        }

        boolean retentionElapsed(long nowNanos) {
            return elapsedAtLeast(nowNanos, lastHeartbeatNanos, RETENTION_NANOS);
        }

        public synchronized void revoke() {
            revoked = true;
        }

        public synchronized void destroy() {
            revoked = true;
            Arrays.fill(sessionKey, (byte) 0);
            Arrays.fill(buildId, (byte) 0);
            if (environmentBaseline != null) {
                Arrays.fill(environmentBaseline, (byte) 0);
                environmentBaseline = null;
            }
        }

        public String getClientIp() { return clientIp; }
        public String getUserName() { return userName; }
        public String getPluginName() { return pluginName; }
        public String getPluginVersion() { return pluginVersion; }
        public String getPluginIdentifier() { return pluginIdentifier; }
        public String getResourceContentSha256() { return resourceContentSha256; }
        public long getAuthLogId() { return authLogId; }
        byte[] getSessionKey() { return sessionKey.clone(); }
        public String getHwid() { return hwid; }
        public int getSecurityEpoch() { return securityEpoch; }
        public byte[] getBuildId() { return buildId.clone(); }
        public long getCreatedAt() { return createdAt; }
        public long getLastHeartbeat() { return lastHeartbeatEpochMillis; }
        public boolean isRevoked() { return revoked; }
    }

    private static boolean elapsedAtLeast(long now, long start, long duration) {
        return now - start >= duration;
    }
}

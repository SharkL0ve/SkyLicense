package cn.sky.skylicense.netty;

import cn.sky.skylicense.config.Storage;
import com.google.gson.Gson;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionManagerRegistrationTest {
    @BeforeEach
    void prepareSessionLifecycle() {
        SessionManager.destroyAllSessions();
        SessionManager.beginStartup();
    }

    @AfterEach
    void cleanUpSessionLifecycle() {
        SessionManager.destroyAllSessions();
        SessionManager.beginStartup();
    }

    @Test
    void rejectsInvalidEpochAndDuplicateSessionIdWithoutReplacingExistingSession() {
        byte[] sessionId = new byte[32];
        byte[] sessionKey = new byte[32];
        byte[] buildId = new byte[32];
        Arrays.fill(sessionId, (byte) 3);
        Arrays.fill(sessionKey, (byte) 5);
        Arrays.fill(buildId, (byte) 7);

        assertFalse(SessionManager.registerSession(
                new byte[32], "127.0.0.1", "user", "plugin",
                sessionKey, "hwid", 0, buildId));
        assertFalse(SessionManager.registerSession(
                new byte[32], "127.0.0.1", "user", "plugin",
                sessionKey, "hwid", 1, buildId));
        assertFalse(SessionManager.registerSession(
                sessionId, "127.0.0.1", "user", "plugin",
                new byte[32], "hwid", 1, buildId));
        assertFalse(SessionManager.registerSession(
                sessionId, "127.0.0.1", "user", "plugin",
                sessionKey, "hwid", 1, new byte[32]));
        assertTrue(SessionManager.registerSession(
                sessionId, "127.0.0.1", "user", "plugin",
                sessionKey, "hwid", 1, buildId));
        assertFalse(SessionManager.registerSession(
                sessionId, "127.0.0.2", "other", "other-plugin",
                sessionKey, "other-hwid", 1, buildId));

        SessionManager.SessionInfo stored = SessionManager.getSession(sessionId);
        assertTrue(stored != null);
        assertTrue(stored.getClientIp().equals("127.0.0.1"));
        SessionManager.destroySession(sessionId);
    }

    @Test
    void tightenedBuildPolicyImmediatelyDestroysIncompatibleSessions() {
        byte[] allowedSessionId = filled(31);
        byte[] revokedSessionId = filled(32);
        byte[] sessionKey = filled(5);
        byte[] allowedBuild = filled(31);
        byte[] revokedBuild = filled(32);
        try {
            assertTrue(SessionManager.registerSession(
                    allowedSessionId, "127.0.0.1", "allowed", "plugin",
                    sessionKey, "hwid-a", 2, allowedBuild));
            assertTrue(SessionManager.registerSession(
                    revokedSessionId, "127.0.0.2", "revoked", "plugin",
                    sessionKey, "hwid-b", 2, revokedBuild));
            SessionManager.SessionInfo revoked = SessionManager.getSession(revokedSessionId);
            assertTrue(revoked != null);

            Storage policy = new Gson().fromJson("""
                    {
                      "debug": false,
                      "authPort": 13331,
                      "authTlsCertificateChain": "certs/auth-chain.pem",
                      "authTlsPrivateKey": "certs/auth-key.pem",
                      "authTlsServerName": "localhost",
                      "minimumClientSecurityEpoch": 2,
                      "allowedClientBuildIds": ["1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f"],
                      "webPort": 8080,
                      "allowedWebOrigins": []
                    }
                    """, Storage.class);

            assertEquals(1, SessionManager.revokeSessionsNotMatching(policy));
            assertTrue(SessionManager.getSession(allowedSessionId) != null);
            assertTrue(SessionManager.getSession(revokedSessionId) == revoked);
            assertFalse(Arrays.equals(new byte[32], revoked.getSessionKey()));
            assertTrue(revoked.isRevoked());

            SessionManager.destroySession(revokedSessionId);
            assertTrue(Arrays.equals(new byte[32], revoked.getSessionKey()));
        } finally {
            SessionManager.destroySession(allowedSessionId);
            SessionManager.destroySession(revokedSessionId);
        }
    }

    @Test
    void shutdownDestroysAllSessionsAndZeroizesKeys() {
        byte[] firstId = filled(41);
        byte[] secondId = filled(42);
        byte[] key = filled(7);
        byte[] build = filled(8);
        try {
            assertTrue(SessionManager.registerSession(
                    firstId, "127.0.0.1", "first", "plugin",
                    key, "hwid-first", 1, build));
            assertTrue(SessionManager.registerSession(
                    secondId, "127.0.0.2", "second", "plugin",
                    key, "hwid-second", 1, build));
            SessionManager.SessionInfo first = SessionManager.getSession(firstId);
            SessionManager.SessionInfo second = SessionManager.getSession(secondId);

            assertEquals(2, SessionManager.destroyAllSessions());
            assertNull(SessionManager.getSession(firstId));
            assertNull(SessionManager.getSession(secondId));
            assertTrue(first != null && first.isRevoked());
            assertTrue(second != null && second.isRevoked());
            assertTrue(Arrays.equals(new byte[32], first.getSessionKey()));
            assertTrue(Arrays.equals(new byte[32], second.getSessionKey()));
        } finally {
            SessionManager.destroySession(firstId);
            SessionManager.destroySession(secondId);
        }
    }

    @Test
    void shutdownRegistrationGateRejectsInFlightHandshake() {
        byte[] sessionId = filled(51);
        byte[] key = filled(52);
        byte[] build = filled(53);

        SessionManager.stopAcceptingRegistrations();

        assertFalse(SessionManager.registerSession(
                sessionId, "127.0.0.1", "late", "plugin",
                key, "hwid-late", 1, build));
        assertNull(SessionManager.getSession(sessionId));
    }

    @Test
    void removingOneResourceRevokesOnlyItsSessionsUntilSignedHeartbeatResponse() {
        byte[] removedId = filled(61);
        byte[] retainedId = filled(62);
        byte[] key = filled(63);
        byte[] build = filled(64);
        assertTrue(SessionManager.registerSession(
                removedId, "127.0.0.1", "license-a", "plugin",
                "1.0.0", key, "hwid-a", 1, build));
        assertTrue(SessionManager.registerSession(
                retainedId, "127.0.0.2", "license-b", "plugin",
                "2.0.0", key, "hwid-b", 1, build));
        SessionManager.SessionInfo removed = SessionManager.getSession(removedId);

        assertEquals(1, SessionManager.revokeSessionsForResource("plugin", "1.0.0"));
        assertTrue(SessionManager.getSession(removedId) == removed);
        assertTrue(SessionManager.getSession(retainedId) != null);
        assertTrue(removed != null && removed.isRevoked());
        assertFalse(Arrays.equals(new byte[32], removed.getSessionKey()));

        SessionManager.destroySession(removedId);
        assertTrue(Arrays.equals(new byte[32], removed.getSessionKey()));
        assertTrue(Arrays.equals(new byte[32], removed.getBuildId()));
    }

    private static byte[] filled(int value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}

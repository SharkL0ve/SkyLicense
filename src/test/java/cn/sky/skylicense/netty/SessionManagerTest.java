package cn.sky.skylicense.netty;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionManagerTest {
    private static final long CREATED_EPOCH_MILLIS = 1_000_000L;
    private static final long CREATED_NANOS = 10_000L;
    private static final byte[] ENVIRONMENT = new byte[32];

    @Test
    void authenticatedHeartbeatRenewsTheMonotonicLease() {
        SessionManager.SessionInfo session = newSession();
        long heartbeatNanos = CREATED_NANOS + SessionManager.ACTIVE_LEASE_NANOS / 3;

        assertTrue(session.acceptHeartbeatAt(
                1_000L,
                "stable-hwid",
                ENVIRONMENT,
                1_000L,
                CREATED_EPOCH_MILLIS + 30_000L,
                heartbeatNanos));
        assertTrue(session.isActiveAt(
                heartbeatNanos + SessionManager.ACTIVE_LEASE_NANOS - 1));
        assertFalse(session.isActiveAt(
                heartbeatNanos + SessionManager.ACTIVE_LEASE_NANOS));
    }

    @Test
    void expiredLeaseIsRevokedAndCannotBeResumed() {
        SessionManager.SessionInfo session = newSession();
        long expiredAt = CREATED_NANOS + SessionManager.ACTIVE_LEASE_NANOS;

        assertFalse(session.acceptHeartbeatAt(
                1_000L,
                "stable-hwid",
                ENVIRONMENT,
                1_000L,
                CREATED_EPOCH_MILLIS + 90_000L,
                expiredAt));
        assertTrue(session.isRevoked());
        assertFalse(session.acceptHeartbeatAt(
                1_001L,
                "stable-hwid",
                ENVIRONMENT,
                1_001L,
                CREATED_EPOCH_MILLIS + 91_000L,
                expiredAt + 1));
    }

    @Test
    void invalidHwidOrReplayPermanentlyRevokesTheSession() {
        SessionManager.SessionInfo wrongHwid = newSession();
        assertFalse(wrongHwid.acceptHeartbeatAt(
                1_000L,
                "different-hwid",
                ENVIRONMENT,
                1_000L,
                CREATED_EPOCH_MILLIS + 1_000L,
                CREATED_NANOS + 1));
        assertTrue(wrongHwid.isRevoked());

        SessionManager.SessionInfo replay = newSession();
        assertTrue(replay.acceptHeartbeatAt(
                1_000L,
                "stable-hwid",
                ENVIRONMENT,
                1_000L,
                CREATED_EPOCH_MILLIS + 1_000L,
                CREATED_NANOS + 1));
        assertFalse(replay.acceptHeartbeatAt(
                1_000L,
                "stable-hwid",
                ENVIRONMENT,
                1_000L,
                CREATED_EPOCH_MILLIS + 2_000L,
                CREATED_NANOS + 2));
        assertTrue(replay.isRevoked());
    }

    @Test
    void destroyZeroizesTheServerSessionKey() {
        SessionManager.SessionInfo session = newSession();
        session.destroy();

        byte[] destroyed = session.getSessionKey();
        assertTrue(session.isRevoked());
        assertArrayEquals(new byte[32], destroyed);
    }

    @Test
    void environmentEvidenceChangeRevokesTheSession() {
        SessionManager.SessionInfo session = newSession();
        assertTrue(session.acceptHeartbeatAt(
                1_000L,
                "stable-hwid",
                ENVIRONMENT,
                1_000L,
                CREATED_EPOCH_MILLIS + 1_000L,
                CREATED_NANOS + 1));

        byte[] changed = ENVIRONMENT.clone();
        changed[0] = 1;
        assertFalse(session.acceptHeartbeatAt(
                1_001L,
                "stable-hwid",
                changed,
                1_001L,
                CREATED_EPOCH_MILLIS + 2_000L,
                CREATED_NANOS + 2));
        assertTrue(session.isRevoked());
    }

    private static SessionManager.SessionInfo newSession() {
        byte[] sessionKey = new byte[32];
        Arrays.fill(sessionKey, (byte) 7);
        return new SessionManager.SessionInfo(
                "127.0.0.1",
                "license",
                "plugin",
                "1.0.0",
                null,
                0L,
                sessionKey,
                "stable-hwid",
                1,
                new byte[32],
                CREATED_EPOCH_MILLIS,
                CREATED_NANOS);
    }
}

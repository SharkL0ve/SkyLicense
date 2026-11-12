package cn.sky.skylicense.netty;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SocketHandlerDeliveryTest {
    @Test
    void confirmationCompletesExactlyOnce() {
        byte[] sessionId = sessionId();
        AtomicInteger successes = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger();
        SocketHandler.PendingDelivery delivery = new SocketHandler.PendingDelivery(
                sessionId,
                successes::incrementAndGet,
                ignored -> failures.incrementAndGet());

        assertTrue(delivery.matchesSessionId(sessionId));
        assertTrue(delivery.beginConfirmation());
        assertTrue(delivery.commitSuccess());
        assertTrue(delivery.complete());
        assertFalse(delivery.complete());
        assertFalse(delivery.fail());
        assertEquals(1, successes.get());
        assertEquals(0, failures.get());
    }

    @Test
    void disconnectOrValidationFailureRollsBackExactlyOnce() {
        AtomicInteger failures = new AtomicInteger();
        SocketHandler.PendingDelivery waiting = new SocketHandler.PendingDelivery(
                sessionId(),
                () -> { },
                ignored -> failures.incrementAndGet());
        assertTrue(waiting.fail());
        assertFalse(waiting.fail());

        SocketHandler.PendingDelivery confirming = new SocketHandler.PendingDelivery(
                sessionId(),
                () -> { },
                ignored -> failures.incrementAndGet());
        assertTrue(confirming.beginConfirmation());
        assertTrue(confirming.fail());
        assertFalse(confirming.complete());
        assertEquals(2, failures.get());
    }

    @Test
    void acknowledgementMustUseTheExpectedSessionId() {
        byte[] expected = sessionId();
        SocketHandler.PendingDelivery delivery = new SocketHandler.PendingDelivery(
                expected, () -> { }, ignored -> { });
        byte[] different = expected.clone();
        different[0] ^= 1;

        assertFalse(delivery.matchesSessionId(different));
        assertTrue(delivery.matchesSessionId(expected));
        delivery.fail();
    }

    @Test
    void confirmationWriteFailureRunsCleanupAfterCommittedSuccess() {
        AtomicInteger successes = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger();
        SocketHandler.PendingDelivery delivery = new SocketHandler.PendingDelivery(
                sessionId(),
                successes::incrementAndGet,
                ignored -> failures.incrementAndGet());

        assertTrue(delivery.beginConfirmation());
        assertFalse(delivery.complete());
        assertTrue(delivery.commitSuccess());
        assertTrue(delivery.fail());
        assertFalse(delivery.complete());
        assertEquals(1, successes.get());
        assertEquals(1, failures.get());
    }

    private static byte[] sessionId() {
        byte[] value = new byte[32];
        Arrays.fill(value, (byte) 7);
        return value;
    }
}

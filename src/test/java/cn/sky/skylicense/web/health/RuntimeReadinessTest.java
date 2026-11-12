package cn.sky.skylicense.web.health;

import cn.sky.skylicense.web.dao.WebDataAccessor;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuntimeReadinessTest {
    @Test
    void databaseProbeIsCachedBrieflyAndRefreshesAfterExpiry() {
        StubAccessor accessor = new StubAccessor();
        AtomicLong clock = new AtomicLong(1_000);
        RuntimeReadiness readiness = new RuntimeReadiness(
                () -> new RuntimeReadiness.RuntimeInputs(true, true, accessor),
                clock::get,
                100);

        assertTrue(readiness.isReady());
        assertTrue(readiness.isReady());
        assertEquals(1, accessor.healthChecks);

        accessor.healthy = false;
        clock.addAndGet(101);
        assertFalse(readiness.isReady());
        assertEquals(2, accessor.healthChecks);
    }

    @Test
    void lifecycleOrListenerFailureMakesReadinessFalse() {
        StubAccessor accessor = new StubAccessor();
        RuntimeReadiness readiness = new RuntimeReadiness(
                () -> new RuntimeReadiness.RuntimeInputs(false, true, accessor),
                () -> 1_000L,
                100);

        assertFalse(readiness.isReady());
        assertEquals(0, accessor.healthChecks);
    }

    @Test
    void auditDegradationMakesReadinessFalseEvenWhenDatabaseIsHealthy() {
        StubAccessor accessor = new StubAccessor();
        AtomicBoolean auditHealthy = new AtomicBoolean(true);
        RuntimeReadiness readiness = new RuntimeReadiness(
                () -> new RuntimeReadiness.RuntimeInputs(true, true, accessor),
                () -> 1_000L,
                100,
                auditHealthy::get);

        assertTrue(readiness.isReady());
        auditHealthy.set(false);
        assertFalse(readiness.isReady());
    }

    private static final class StubAccessor extends WebDataAccessor {
        private boolean open = true;
        private boolean healthy = true;
        private int healthChecks;

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public boolean isHealthy() {
            healthChecks++;
            return healthy;
        }
    }
}

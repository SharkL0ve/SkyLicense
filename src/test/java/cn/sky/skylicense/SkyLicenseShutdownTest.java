package cn.sky.skylicense;

import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SkyLicenseShutdownTest {
    @Test
    void commandThreadShutdownDoesNotInterruptConfigurationPersistence() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        AtomicBoolean interrupted = new AtomicBoolean(true);

        executor.submit(() -> {
            SkyLicense.shutdownCommandExecutor(executor, Thread.currentThread());
            interrupted.set(Thread.currentThread().isInterrupted());
        }).get(5, TimeUnit.SECONDS);

        assertFalse(interrupted.get());
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    @Test
    void externalShutdownStillInterruptsBlockedCommandThread() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        AtomicBoolean interrupted = new AtomicBoolean(false);
        AtomicBoolean started = new AtomicBoolean(false);
        executor.submit(() -> {
            started.set(true);
            try {
                Thread.sleep(TimeUnit.MINUTES.toMillis(1));
            } catch (InterruptedException expected) {
                interrupted.set(true);
                Thread.currentThread().interrupt();
            }
        });
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!started.get() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }

        SkyLicense.shutdownCommandExecutor(executor, null);

        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        assertTrue(interrupted.get());
    }
}

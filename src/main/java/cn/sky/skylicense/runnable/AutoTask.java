package cn.sky.skylicense.runnable;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.netty.SessionManager;

public class AutoTask implements Runnable{
    private static final long BAN_SWEEP_INTERVAL_NANOS = 60_000_000_000L;
    private long lastBanSweepNanos;

    @Override
    public void run() {
        try {
            SessionManager.cleanupStaleSessions();
            expireBanRulesIfDue();
        } catch (RuntimeException error) {
            // A scheduled executor suppresses future executions when a task
            // escapes. Keep housekeeping alive and retain the last snapshot.
            SkyLicense.LOG.error("Periodic license housekeeping failed", error);
        }
    }

    private void expireBanRulesIfDue() {
        long now = System.nanoTime();
        if (lastBanSweepNanos != 0
                && now - lastBanSweepNanos < BAN_SWEEP_INTERVAL_NANOS) {
            return;
        }
        lastBanSweepNanos = now;
        if (SkyLicense.instance == null) {
            return;
        }
        int expired = SkyLicense.instance.getWebBanService().expireDueBans();
        if (expired > 0) {
            SkyLicense.LOG.info("Expired {} ban rules", expired);
        }
    }
}

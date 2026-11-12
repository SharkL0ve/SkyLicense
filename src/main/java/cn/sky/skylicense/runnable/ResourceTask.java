package cn.sky.skylicense.runnable;

import cn.sky.skylicense.SkyLicense;

public class ResourceTask implements Runnable{
    @Override
    public void run() {
        SkyLicense.LOG.info("Automatically refreshing resources...");
        if (SkyLicense.instance == null
                || !SkyLicense.instance.reloadProtectedResources(false)) {
            SkyLicense.LOG.error("Automatic resource refresh failed; keeping previous snapshot.");
        }
    }
}

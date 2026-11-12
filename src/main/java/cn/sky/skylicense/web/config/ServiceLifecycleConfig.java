package cn.sky.skylicense.web.config;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.Server;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import jakarta.annotation.PreDestroy;
import org.springframework.context.annotation.Configuration;

/** Coordinates native-service shutdown before the shared database is closed. */
@Configuration
public class ServiceLifecycleConfig {
    public ServiceLifecycleConfig(WebDataAccessor webDataAccessor) {
        // The dependency keeps the database alive until native services stop.
    }

    @PreDestroy
    public void shutdownServices() {
        try {
            SkyLicense service = SkyLicense.instance;
            if (service != null) {
                service.shutdownServices();
            }
        } finally {
            Server.releaseDeploymentLock();
        }
    }
}

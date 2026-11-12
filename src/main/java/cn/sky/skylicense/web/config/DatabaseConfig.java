package cn.sky.skylicense.web.config;

import cn.sky.skylicense.utils.PasswordUtil;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.security.StartupSecurity;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.security.UsernamePolicy;
import com.j256.ormlite.dao.Dao;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import cn.sky.skylicense.SkyLicense;

@Configuration
public class DatabaseConfig {

    private static final Logger LOG = LogManager.getLogger(DatabaseConfig.class);
    @Bean(destroyMethod = "close")
    public WebDataAccessor webDataAccessor() {
        WebDataAccessor accessor = SkyLicense.instance.getWebDataAccessor();
        if (accessor == null) {
            throw new IllegalStateException("Shared Web database is not initialized");
        }
        return accessor;
    }

    void initDefaultAdmin(WebDataAccessor accessor) {
        initializeBootstrapAdministrator(accessor);
    }

    public static void initializeBootstrapAdministrator(WebDataAccessor accessor) {
        try {
            Dao<WebUser, Long> dao = accessor.getUserDao();
            WebUser admin = dao.queryBuilder()
                    .where().eq("role", "ADMIN").and().eq("status", 1)
                    .queryForFirst();
            StartupSecurity.validateBootstrapAdminEnvironment(admin != null);
            if (admin != null) {
                return;
            }
            if (UsernamePolicy.findCaseInsensitive(dao, "admin") != null) {
                throw new IllegalStateException(
                        "Cannot create bootstrap administrator because username admin is already in use");
            }
            admin = WebUser.builder()
                    .username("admin")
                    .password(PasswordUtil.hashPassword(
                            StartupSecurity.bootstrapAdminPassword()))
                    .role("ADMIN")
                    .maxPrograms(999)
                    .status(1)
                    .createTime(TimeUtil.getCurtTime())
                    .build();
            dao.create(admin);
            LOG.info("Bootstrap administrator account created; remove the bootstrap password environment variable");
        } catch (Exception e) {
            LOG.error("Failed to create default admin", e);
            throw new IllegalStateException("Unable to create the bootstrap administrator", e);
        }
    }
}

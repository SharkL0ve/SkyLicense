package cn.sky.skylicense.web.config;

import cn.sky.skylicense.security.MfaSecretProtector;
import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.service.LoginRateLimiter;
import cn.sky.skylicense.web.service.PersistentLoginRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Owns authentication secrets and persistent throttling for the Web application. */
@Configuration
public class AuthSecurityConfig {
    @Bean(destroyMethod = "close")
    public MfaSecretProtector mfaSecretProtector() {
        return MfaSecretProtector.fromEnvironment();
    }

    @Bean
    public LoginRateLimiter loginRateLimiter(
            WebDataAccessor accessor,
            OperationLogSanitizer sanitizer
    ) {
        return new PersistentLoginRateLimiter(accessor, sanitizer);
    }
}

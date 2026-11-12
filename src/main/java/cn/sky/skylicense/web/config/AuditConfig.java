package cn.sky.skylicense.web.config;

import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Owns the installation-specific audit reference key for the Web application lifecycle. */
@Configuration
public class AuditConfig {
    @Bean(destroyMethod = "close")
    public OperationLogSanitizer operationLogSanitizer() {
        return OperationLogSanitizer.fromEnvironment();
    }
}

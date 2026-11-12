package cn.sky.skylicense.web.config;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.web.security.SessionAuthFilter;
import cn.sky.skylicense.web.security.WebSessionSecurity;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.embedded.undertow.UndertowDeploymentInfoCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
public class WebConfig {
    static final String CONTENT_SECURITY_POLICY = String.join("; ",
            "default-src 'self'",
            "base-uri 'self'",
            "connect-src 'self'",
            "font-src 'self' data:",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "frame-src 'none'",
            "img-src 'self' data: blob:",
            "manifest-src 'self'",
            "media-src 'self'",
            "object-src 'none'",
            "script-src 'self'",
            "script-src-attr 'none'",
            "style-src 'self' 'unsafe-inline'",
            "worker-src 'none'",
            "upgrade-insecure-requests");

    @Bean
    public UndertowDeploymentInfoCustomizer undertowRequestGuard() {
        return deploymentInfo -> deploymentInfo.addInitialHandlerChainWrapper(
                UndertowRequestGuard::wrap);
    }

    @Bean
    public FilterRegistrationBean<Filter> securityHeadersFilter() {
        Filter filter = (request, response, chain) -> {
            if (request instanceof HttpServletRequest httpRequest
                    && response instanceof HttpServletResponse httpResponse) {
                applySecurityHeaders(httpRequest, httpResponse);
            }
            chain.doFilter(request, response);
        };
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(-1);
        return registration;
    }

    static void applySecurityHeaders(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        response.setHeader(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains");
        response.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-Permitted-Cross-Domain-Policies", "none");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        response.setHeader(
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=()");
        String requestUri = request.getRequestURI();
        if ("/api".equals(requestUri)
                || (requestUri != null && requestUri.startsWith("/api/"))) {
            response.setHeader("Cache-Control", "no-store");
        }
    }

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilterRegistration() {
        List<String> allowedOrigins = SkyLicense.configuration()
                .getStorage()
                .getAllowedWebOrigins();
        CorsConfiguration config = corsConfiguration(allowedOrigins);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);

        FilterRegistrationBean<CorsFilter> registration =
                new FilterRegistrationBean<>(new CorsFilter(source));
        registration.setOrder(0);
        return registration;
    }

    static CorsConfiguration corsConfiguration(List<String> allowedOrigins) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedHeaders(List.of(
                "Content-Type",
                "Accept",
                WebSessionSecurity.CSRF_HEADER));
        config.setAllowedMethods(List.of(
                "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowCredentials(!allowedOrigins.isEmpty());
        config.setMaxAge(3600L);
        return config;
    }

    @Bean
    public FilterRegistrationBean<SessionAuthFilter> sessionFilter(SessionAuthFilter filter) {
        FilterRegistrationBean<SessionAuthFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);
        return registration;
    }
}

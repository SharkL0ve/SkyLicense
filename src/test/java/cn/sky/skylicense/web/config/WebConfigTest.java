package cn.sky.skylicense.web.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.web.cors.CorsConfiguration;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebConfigTest {
    @Test
    void appliesRestrictiveBrowserSecurityHeaders() {
        Map<String, String> headers = applyHeaders("/");

        assertEquals("max-age=63072000; includeSubDomains",
                headers.get("Strict-Transport-Security"));
        assertEquals(WebConfig.CONTENT_SECURITY_POLICY,
                headers.get("Content-Security-Policy"));
        assertEquals("nosniff", headers.get("X-Content-Type-Options"));
        assertEquals("DENY", headers.get("X-Frame-Options"));
        assertEquals("none", headers.get("X-Permitted-Cross-Domain-Policies"));
        assertEquals("no-referrer", headers.get("Referrer-Policy"));
        assertEquals("same-origin", headers.get("Cross-Origin-Opener-Policy"));
        assertEquals("same-origin", headers.get("Cross-Origin-Resource-Policy"));
        assertEquals("camera=(), microphone=(), geolocation=(), payment=()",
                headers.get("Permissions-Policy"));
        assertFalse(headers.containsKey("Cache-Control"));
    }

    @Test
    void contentSecurityPolicyAllowsOnlyRequiredFrontendCapabilities() {
        String policy = WebConfig.CONTENT_SECURITY_POLICY;

        assertTrue(policy.contains("script-src 'self'"));
        assertTrue(policy.contains("script-src-attr 'none'"));
        assertTrue(policy.contains("style-src 'self' 'unsafe-inline'"));
        assertTrue(policy.contains("connect-src 'self'"));
        assertTrue(policy.contains("object-src 'none'"));
        assertTrue(policy.contains("frame-ancestors 'none'"));
        assertFalse(policy.contains("'unsafe-eval'"));
        assertFalse(policy.contains("script-src 'self' 'unsafe-inline'"));
        assertFalse(policy.contains("http://"));
        assertFalse(policy.contains("https://"));
    }

    @Test
    void disablesCachingForApiPathsOnly() {
        assertEquals("no-store", applyHeaders("/api").get("Cache-Control"));
        assertEquals("no-store", applyHeaders("/api/auth/me").get("Cache-Control"));
        assertFalse(applyHeaders("/health/live").containsKey("Cache-Control"));
        assertFalse(applyHeaders("/api-docs").containsKey("Cache-Control"));
        assertFalse(applyHeaders("/assets/index.js").containsKey("Cache-Control"));
    }

    @Test
    void corsAllowsCredentialedCsrfRequestsFromExactConfiguredOrigins() {
        CorsConfiguration sameOrigin = WebConfig.corsConfiguration(List.of());
        CorsConfiguration separated = WebConfig.corsConfiguration(
                List.of("https://admin.example.com"));

        assertEquals(List.of("Content-Type", "Accept", "X-CSRF-Token"),
                sameOrigin.getAllowedHeaders());
        assertFalse(sameOrigin.getAllowedHeaders().contains("Authorization"));
        assertEquals(List.of(
                "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
                sameOrigin.getAllowedMethods());
        assertEquals(Boolean.FALSE, sameOrigin.getAllowCredentials());
        assertEquals(Boolean.TRUE, separated.getAllowCredentials());
        assertEquals(List.of("https://admin.example.com"), separated.getAllowedOrigins());
    }

    private static Map<String, String> applyHeaders(String requestUri) {
        Map<String, String> headers = new HashMap<>();
        HttpServletRequest request = proxy(
                HttpServletRequest.class,
                (method, arguments) -> "getRequestURI".equals(method) ? requestUri : null);
        HttpServletResponse response = proxy(
                HttpServletResponse.class,
                (method, arguments) -> {
                    if ("setHeader".equals(method)) {
                        headers.put((String) arguments[0], (String) arguments[1]);
                    }
                    return null;
                });
        WebConfig.applySecurityHeaders(request, response);
        return headers;
    }

    private static <T> T proxy(Class<T> type, Invocation invocation) {
        Object value = Proxy.newProxyInstance(
                type.getClassLoader(),
                new Class<?>[]{type},
                (proxy, method, arguments) -> invocation.invoke(method.getName(), arguments));
        return type.cast(value);
    }

    @FunctionalInterface
    private interface Invocation {
        Object invoke(String method, Object[] arguments);
    }
}

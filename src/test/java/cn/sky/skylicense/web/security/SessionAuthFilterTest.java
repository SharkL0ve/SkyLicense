package cn.sky.skylicense.web.security;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionAuthFilterTest {
    private static final String TOKEN = "T".repeat(43);
    private static final String CSRF = "A".repeat(43);
    private static final UserContext CONTEXT =
            new UserContext(1, "admin", "ADMIN", CSRF, true);
    private static final UserContext ADMIN_WITHOUT_MFA =
            new UserContext(1, "admin", "ADMIN", CSRF, false);

    @AfterEach
    void clearContext() {
        UserContext.clear();
    }

    @Test
    void publicLoginAndOptionsBypassAuthentication() throws Exception {
        SessionAuthFilter filter = filter(CONTEXT);

        Exchange login = exchange(
                "/api/auth/login",
                "POST",
                null,
                null,
                "https://license.example.com:8080");
        filter.doFilter(login.request, login.response, login.chain);
        Exchange options = exchange("/api/users", "OPTIONS", null, null, null);
        filter.doFilter(options.request, options.response, options.chain);

        assertTrue(login.chained.get());
        assertTrue(options.chained.get());
    }

    @Test
    void publicLoginRejectsUntrustedBrowserOriginButAllowsNonBrowserClient()
            throws Exception {
        SessionAuthFilter filter = filter(CONTEXT);
        Exchange malicious = exchange(
                "/api/auth/login", "POST", null, null, "https://evil.example");
        Exchange nonBrowser = exchange(
                "/api/auth/login", "POST", null, null, null);

        filter.doFilter(malicious.request, malicious.response, malicious.chain);
        filter.doFilter(nonBrowser.request, nonBrowser.response, nonBrowser.chain);

        assertEquals(403, malicious.status.value);
        assertFalse(malicious.chained.get());
        assertTrue(nonBrowser.chained.get());
    }

    @Test
    void rejectsMissingRevokedAndUnrelatedPublicNamespaces() throws Exception {
        Exchange missing = exchange("/api/auth/session", "GET", null, null, null);
        filter(CONTEXT).doFilter(missing.request, missing.response, missing.chain);
        Exchange revoked = exchange("/api/auth/session", "GET", TOKEN, null, null);
        filter(null).doFilter(revoked.request, revoked.response, revoked.chain);
        Exchange publicNamespace = exchange("/api/public/status", "GET", null, null, null);
        filter(CONTEXT).doFilter(
                publicNamespace.request, publicNamespace.response, publicNamespace.chain);

        assertEquals(401, missing.status.value);
        assertEquals(401, revoked.status.value);
        assertEquals(401, publicNamespace.status.value);
        assertFalse(missing.chained.get());
        assertFalse(revoked.chained.get());
        assertFalse(publicNamespace.chained.get());
        assertNullDataField(missing);
        assertNullDataField(revoked);
        assertNullDataField(publicNamespace);
    }

    @Test
    void safeRequestAuthenticatesWithoutCsrfAndClearsThreadContext() throws Exception {
        Exchange exchange = exchange("/api/auth/session", "GET", TOKEN, null, null);
        exchange.onChain = () -> assertEquals(CONTEXT, UserContext.get());

        filter(CONTEXT).doFilter(exchange.request, exchange.response, exchange.chain);

        assertTrue(exchange.chained.get());
        assertNull(UserContext.get());
        assertEquals(TOKEN, exchange.attributes.get(WebSessionSecurity.AUTH_TOKEN_ATTRIBUTE));
    }

    @Test
    void unsafeRequestRequiresMatchingCsrfAndTrustedOrigin() throws Exception {
        Exchange missingCsrf = exchange(
                "/api/users", "POST", TOKEN, null, "https://license.example.com:8080");
        filter(CONTEXT).doFilter(
                missingCsrf.request, missingCsrf.response, missingCsrf.chain);
        Exchange wrongOrigin = exchange(
                "/api/users", "POST", TOKEN, CSRF, "https://evil.example");
        filter(CONTEXT).doFilter(
                wrongOrigin.request, wrongOrigin.response, wrongOrigin.chain);
        Exchange accepted = exchange(
                "/api/users", "POST", TOKEN, CSRF, "https://admin.example.net");
        SessionAuthFilter crossSiteFilter = new SessionAuthFilter(
                ignored -> CONTEXT,
                () -> List.of("https://admin.example.net"));
        crossSiteFilter.doFilter(accepted.request, accepted.response, accepted.chain);

        assertEquals(403, missingCsrf.status.value);
        assertEquals(403, wrongOrigin.status.value);
        assertFalse(missingCsrf.chained.get());
        assertFalse(wrongOrigin.chained.get());
        assertTrue(accepted.chained.get());
    }

    @Test
    void highSignalOriginAndCsrfRejectionsAreForwardedToTheAuditSink() throws Exception {
        List<String> reasons = new ArrayList<>();
        SessionAuthFilter audited = new SessionAuthFilter(
                ignored -> CONTEXT,
                List::of,
                (actor, reason, method, ip) -> reasons.add(reason));

        Exchange loginOrigin = exchange(
                "/api/auth/login", "POST", null, null, "https://evil.example");
        audited.doFilter(loginOrigin.request, loginOrigin.response, loginOrigin.chain);

        Exchange csrf = exchange(
                "/api/users", "POST", TOKEN, null, "https://license.example.com:8080");
        audited.doFilter(csrf.request, csrf.response, csrf.chain);

        Exchange origin = exchange(
                "/api/users", "POST", TOKEN, CSRF, "https://evil.example");
        audited.doFilter(origin.request, origin.response, origin.chain);

        assertEquals(List.of(
                "LOGIN_ORIGIN_REJECTED",
                "CSRF_REJECTED",
                "ORIGIN_REJECTED"), reasons);
    }

    @Test
    void administratorWithoutMfaCanOnlyUseBootstrapEndpoints() throws Exception {
        SessionAuthFilter filter = filter(ADMIN_WITHOUT_MFA);
        List<Exchange> allowed = List.of(
                exchange("/api/auth/session", "GET", TOKEN, null, null),
                exchange("/api/auth/me", "GET", TOKEN, null, null),
                exchange("/api/auth/mfa/status", "GET", TOKEN, null, null),
                exchange("/api/auth/logout", "POST", TOKEN, CSRF,
                        "https://license.example.com:8080"),
                exchange("/api/auth/mfa/enrollment", "POST", TOKEN, CSRF,
                        "https://license.example.com:8080"),
                exchange("/api/auth/mfa/enrollment/confirm", "POST", TOKEN, CSRF,
                        "https://license.example.com:8080"),
                exchange("/api/auth/password", "PUT", TOKEN, CSRF,
                        "https://license.example.com:8080"));

        for (Exchange item : allowed) {
            filter.doFilter(item.request, item.response, item.chain);
            assertTrue(item.chained.get());
        }
    }

    @Test
    void administratorWithoutMfaIsDeniedOtherApisAndRejectionIsAudited()
            throws Exception {
        List<String> reasons = new ArrayList<>();
        SessionAuthFilter filter = new SessionAuthFilter(
                ignored -> ADMIN_WITHOUT_MFA,
                List::of,
                (actor, reason, method, ip) -> reasons.add(reason));
        Exchange adminApi = exchange("/api/admin/stats", "GET", TOKEN, null, null);
        Exchange selfDisable = exchange(
                "/api/auth/mfa",
                "DELETE",
                TOKEN,
                CSRF,
                "https://license.example.com:8080");

        filter.doFilter(adminApi.request, adminApi.response, adminApi.chain);
        filter.doFilter(selfDisable.request, selfDisable.response, selfDisable.chain);

        assertEquals(403, adminApi.status.value);
        assertEquals(403, selfDisable.status.value);
        assertFalse(adminApi.chained.get());
        assertFalse(selfDisable.chained.get());
        assertTrue(adminApi.body.toString().contains(
                SessionAuthFilter.ADMIN_MFA_REQUIRED_MESSAGE));
        assertEquals(List.of("ADMIN_MFA_REQUIRED", "ADMIN_MFA_REQUIRED"), reasons);
        assertNull(UserContext.get());
    }

    @Test
    void ordinaryUserWithoutMfaIsNotRestrictedByAdministratorGate() throws Exception {
        UserContext user = new UserContext(2, "operator", "USER", CSRF, false);
        Exchange request = exchange("/api/programs", "GET", TOKEN, null, null);

        filter(user).doFilter(request.request, request.response, request.chain);

        assertTrue(request.chained.get());
    }

    private static SessionAuthFilter filter(UserContext context) {
        return new SessionAuthFilter(ignored -> context, List::of);
    }

    private static Exchange exchange(
            String path,
            String method,
            String token,
            String csrf,
            String origin
    ) {
        return new Exchange(path, method, token, csrf, origin);
    }

    private static void assertNullDataField(Exchange exchange) {
        JsonObject envelope = JsonParser.parseString(exchange.body.toString()).getAsJsonObject();
        assertTrue(envelope.has("data"));
        assertTrue(envelope.get("data").isJsonNull());
    }

    private static final class Exchange {
        private final Map<String, Object> attributes = new HashMap<>();
        private final AtomicBoolean chained = new AtomicBoolean();
        private final MutableInt status = new MutableInt();
        private final StringWriter body = new StringWriter();
        private Runnable onChain = () -> { };
        private final HttpServletRequest request;
        private final HttpServletResponse response;
        private final FilterChain chain;

        private Exchange(String path, String method, String token, String csrf, String origin) {
            request = (HttpServletRequest) Proxy.newProxyInstance(
                    HttpServletRequest.class.getClassLoader(),
                    new Class<?>[]{HttpServletRequest.class},
                    (proxy, called, arguments) -> switch (called.getName()) {
                        case "getRequestURI" -> path;
                        case "getMethod" -> method;
                        case "getCookies" -> token == null
                                ? null
                                : new Cookie[]{new Cookie(WebSessionSecurity.COOKIE_NAME, token)};
                        case "getHeader" -> {
                            String name = (String) arguments[0];
                            if (WebSessionSecurity.CSRF_HEADER.equals(name)) {
                                yield csrf;
                            }
                            yield "Origin".equals(name) ? origin : null;
                        }
                        case "getScheme" -> "https";
                        case "getServerName" -> "license.example.com";
                        case "getServerPort" -> 8080;
                        case "getAttribute" -> attributes.get((String) arguments[0]);
                        case "setAttribute" -> {
                            attributes.put((String) arguments[0], arguments[1]);
                            yield null;
                        }
                        default -> defaultValue(called.getReturnType());
                    });
            response = (HttpServletResponse) Proxy.newProxyInstance(
                    HttpServletResponse.class.getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class},
                    (proxy, called, arguments) -> switch (called.getName()) {
                        case "setStatus" -> {
                            status.value = (int) arguments[0];
                            yield null;
                        }
                        case "getWriter" -> new PrintWriter(body);
                        default -> defaultValue(called.getReturnType());
                    });
            chain = (request, response) -> {
                onChain.run();
                chained.set(true);
            };
        }
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == char.class) {
            return '\0';
        }
        return 0;
    }

    private static final class MutableInt {
        private int value;
    }
}

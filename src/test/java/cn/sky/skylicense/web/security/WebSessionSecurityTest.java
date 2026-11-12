package cn.sky.skylicense.web.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebSessionSecurityTest {
    private static final String SESSION_TOKEN = "S".repeat(43);
    private static final String CSRF_TOKEN = "A".repeat(43);

    @Test
    void sessionCookieUsesHostPrefixAndHardenedAttributes() {
        String sameSite = WebSessionSecurity.buildSessionCookie(SESSION_TOKEN, 3600, false);
        String crossSite = WebSessionSecurity.buildSessionCookie(SESSION_TOKEN, 3600, true);
        String cleared = WebSessionSecurity.buildClearCookie(false);

        assertTrue(sameSite.startsWith("__Host-skylicense_session=" + SESSION_TOKEN));
        assertTrue(sameSite.contains("Path=/"));
        assertTrue(sameSite.contains("Max-Age=3600"));
        assertTrue(sameSite.contains("Secure"));
        assertTrue(sameSite.contains("HttpOnly"));
        assertTrue(sameSite.contains("SameSite=Strict"));
        assertTrue(crossSite.contains("SameSite=None"));
        assertTrue(cleared.contains("Max-Age=0"));
        assertTrue(cleared.contains("SameSite=Strict"));
    }

    @Test
    void rejectsMissingOversizedAndDuplicateSessionCookies() {
        Cookie session = new Cookie(WebSessionSecurity.COOKIE_NAME, SESSION_TOKEN);

        assertNull(WebSessionSecurity.readSessionToken((Cookie[]) null));
        assertEquals(SESSION_TOKEN, WebSessionSecurity.readSessionToken(new Cookie[]{session}));
        assertNull(WebSessionSecurity.readSessionToken(new Cookie[]{session, session}));
        assertNull(WebSessionSecurity.readSessionToken(new Cookie[]{
                new Cookie(WebSessionSecurity.COOKIE_NAME, "x".repeat(44))}));
        assertNull(WebSessionSecurity.readSessionToken(new Cookie[]{
                new Cookie(WebSessionSecurity.COOKIE_NAME, "legacy.jwt.token")}));
    }

    @Test
    void csrfChecksAreMethodAwareAndConstantTimeCompatible() {
        assertFalse(WebSessionSecurity.requiresCsrf("GET"));
        assertFalse(WebSessionSecurity.requiresCsrf("HEAD"));
        assertFalse(WebSessionSecurity.requiresCsrf("OPTIONS"));
        assertTrue(WebSessionSecurity.requiresCsrf("POST"));
        assertTrue(WebSessionSecurity.requiresCsrf("PUT"));
        assertTrue(WebSessionSecurity.requiresCsrf("PATCH"));
        assertTrue(WebSessionSecurity.requiresCsrf("DELETE"));
        assertTrue(WebSessionSecurity.csrfMatches(CSRF_TOKEN, CSRF_TOKEN));
        assertFalse(WebSessionSecurity.csrfMatches(CSRF_TOKEN, "B".repeat(43)));
        assertFalse(WebSessionSecurity.csrfMatches(CSRF_TOKEN, null));
        assertTrue(WebSessionSecurity.isValidOpaqueToken(CSRF_TOKEN));
        assertFalse(WebSessionSecurity.isValidOpaqueToken("unsafe+token"));
    }

    @Test
    void originMustBeSameOriginOrExplicitlyAllowlisted() {
        HttpServletRequest sameOrigin = request("https://license.example.com:8443", 8443);
        HttpServletRequest defaultPort = request("https://license.example.com", 443);
        HttpServletRequest allowed = request("https://admin.example.net", 8443);
        HttpServletRequest absent = request(null, 8443);

        assertTrue(WebSessionSecurity.isRequestOriginAllowed(sameOrigin, List.of()));
        assertTrue(WebSessionSecurity.isRequestOriginAllowed(defaultPort, List.of()));
        assertTrue(WebSessionSecurity.isRequestOriginAllowed(
                allowed, List.of("https://admin.example.net")));
        assertTrue(WebSessionSecurity.isRequestOriginAllowed(absent, List.of()));
        assertFalse(WebSessionSecurity.isRequestOriginAllowed(
                request("https://evil.example", 8443), List.of()));
        assertFalse(WebSessionSecurity.isRequestOriginAllowed(
                request("https://license.example.com:8443/path", 8443), List.of()));
    }

    private static HttpServletRequest request(String origin, int port) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getHeader" -> origin;
                    case "getScheme" -> "https";
                    case "getServerName" -> "license.example.com";
                    case "getServerPort" -> port;
                    default -> defaultValue(method.getReturnType());
                });
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
}

package cn.sky.skylicense.web.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;

/** Browser-session cookie and CSRF invariants shared by the filter and controller. */
public final class WebSessionSecurity {
    public static final String COOKIE_NAME = "__Host-skylicense_session";
    public static final String CSRF_HEADER = "X-CSRF-Token";
    public static final String AUTH_TOKEN_ATTRIBUTE =
            WebSessionSecurity.class.getName() + ".authToken";
    static final int OPAQUE_TOKEN_CHARACTERS = 43;

    private WebSessionSecurity() {
    }

    public static String readSessionToken(HttpServletRequest request) {
        return readSessionToken(request.getCookies());
    }

    static String readSessionToken(Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }
        String found = null;
        for (Cookie cookie : cookies) {
            if (!COOKIE_NAME.equals(cookie.getName())) {
                continue;
            }
            String value = cookie.getValue();
            if (found != null
                    || !isValidOpaqueToken(value)) {
                return null;
            }
            found = value;
        }
        return found;
    }

    public static void setSessionCookie(
            HttpServletResponse response,
            String token,
            long maxAgeSeconds,
            boolean crossSite
    ) {
        response.addHeader(
                HttpHeaders.SET_COOKIE,
                buildSessionCookie(token, maxAgeSeconds, crossSite));
    }

    public static void clearSessionCookie(
            HttpServletResponse response,
            boolean crossSite
    ) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildClearCookie(crossSite));
    }

    static String buildSessionCookie(String token, long maxAgeSeconds, boolean crossSite) {
        if (token == null
                || !isValidOpaqueToken(token)
                || maxAgeSeconds <= 0) {
            throw new IllegalArgumentException("valid session token and lifetime are required");
        }
        return cookieBuilder(token, crossSite)
                .maxAge(Duration.ofSeconds(maxAgeSeconds))
                .build()
                .toString();
    }

    static String buildClearCookie(boolean crossSite) {
        return cookieBuilder("", crossSite)
                .maxAge(Duration.ZERO)
                .build()
                .toString();
    }

    private static ResponseCookie.ResponseCookieBuilder cookieBuilder(
            String value,
            boolean crossSite
    ) {
        return ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite(crossSite ? "None" : "Strict");
    }

    public static boolean requiresCsrf(String method) {
        return !("GET".equalsIgnoreCase(method)
                || "HEAD".equalsIgnoreCase(method)
                || "OPTIONS".equalsIgnoreCase(method));
    }

    public static boolean csrfMatches(String expected, String supplied) {
        if (!isValidOpaqueToken(expected) || !isValidOpaqueToken(supplied)) {
            return false;
        }
        byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        byte[] suppliedBytes = supplied.getBytes(StandardCharsets.UTF_8);
        try {
            return MessageDigest.isEqual(expectedBytes, suppliedBytes);
        } finally {
            java.util.Arrays.fill(expectedBytes, (byte) 0);
            java.util.Arrays.fill(suppliedBytes, (byte) 0);
        }
    }

    public static boolean isValidOpaqueToken(String value) {
        return value != null
                && value.length() == OPAQUE_TOKEN_CHARACTERS
                && value.chars().allMatch(character ->
                character >= 'A' && character <= 'Z'
                        || character >= 'a' && character <= 'z'
                        || character >= '0' && character <= '9'
                        || character == '-'
                        || character == '_');
    }

    public static boolean isRequestOriginAllowed(
            HttpServletRequest request,
            List<String> allowedOrigins
    ) {
        String origin = request.getHeader("Origin");
        if (origin == null || origin.isBlank()) {
            // Non-browser clients still need the session-bound CSRF header.
            return true;
        }
        if (allowedOrigins != null && allowedOrigins.contains(origin)) {
            return true;
        }
        try {
            URI uri = new URI(origin);
            return uri.getHost() != null
                    && uri.getUserInfo() == null
                    && uri.getQuery() == null
                    && uri.getFragment() == null
                    && uri.getPath().isEmpty()
                    && request.getScheme().equalsIgnoreCase(uri.getScheme())
                    && request.getServerName().equalsIgnoreCase(uri.getHost())
                    && effectivePort(request.getScheme(), request.getServerPort())
                    == effectivePort(uri.getScheme(), uri.getPort());
        } catch (URISyntaxException error) {
            return false;
        }
    }

    private static int effectivePort(String scheme, int port) {
        if (port >= 0) {
            return port;
        }
        if ("https".equalsIgnoreCase(scheme)) {
            return 443;
        }
        if ("http".equalsIgnoreCase(scheme)) {
            return 80;
        }
        return -1;
    }
}

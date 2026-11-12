package cn.sky.skylicense.web.dto.response;

public record AuthLoginResponse(
        String csrfToken,
        long expiresInSeconds,
        boolean mfaRequired,
        String challengeToken
) {
    public static AuthLoginResponse authenticated(String csrfToken, long expiresInSeconds) {
        return new AuthLoginResponse(csrfToken, expiresInSeconds, false, null);
    }

    public static AuthLoginResponse challenge(String token, long expiresInSeconds) {
        return new AuthLoginResponse(null, expiresInSeconds, true, token);
    }
}

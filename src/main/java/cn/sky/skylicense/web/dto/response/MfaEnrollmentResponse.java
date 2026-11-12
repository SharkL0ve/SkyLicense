package cn.sky.skylicense.web.dto.response;

public record MfaEnrollmentResponse(
        String manualSecret,
        String otpauthUri,
        long expiresInSeconds
) {
}

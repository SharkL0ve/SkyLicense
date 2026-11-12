package cn.sky.skylicense.web.dto.response;

public record MfaStatusResponse(
        boolean enabled,
        int remainingRecoveryCodes
) {
}

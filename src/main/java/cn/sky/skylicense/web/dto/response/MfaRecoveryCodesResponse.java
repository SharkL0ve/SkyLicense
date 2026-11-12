package cn.sky.skylicense.web.dto.response;

import java.util.List;

public record MfaRecoveryCodesResponse(List<String> recoveryCodes) {
}

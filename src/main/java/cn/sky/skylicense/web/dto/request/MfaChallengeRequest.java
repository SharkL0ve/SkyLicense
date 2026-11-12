package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class MfaChallengeRequest {
    @NotBlank(message = "MFA挑战不能为空")
    @Size(max = 64)
    private String challengeToken;

    @NotBlank(message = "验证码不能为空")
    @Size(max = 128)
    private String factor;
}

package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class MfaManageRequest {
    @NotBlank(message = "当前密码不能为空")
    @Size(max = 128)
    private String password;

    @NotBlank(message = "验证码不能为空")
    @Size(max = 128)
    private String factor;
}

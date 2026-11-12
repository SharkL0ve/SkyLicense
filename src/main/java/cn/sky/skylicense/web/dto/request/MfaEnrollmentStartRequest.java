package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class MfaEnrollmentStartRequest {
    @NotBlank(message = "当前密码不能为空")
    @Size(max = 128)
    private String password;
}

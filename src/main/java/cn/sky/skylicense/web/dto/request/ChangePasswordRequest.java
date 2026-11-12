package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ChangePasswordRequest {

    @NotBlank(message = "旧密码不能为空")
    @Size(max = 128)
    private String oldPassword;

    @NotBlank(message = "新密码不能为空")
    @Size(min = 12, max = 128)
    private String newPassword;
}

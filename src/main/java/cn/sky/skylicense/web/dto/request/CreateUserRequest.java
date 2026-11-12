package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class CreateUserRequest {

    @NotBlank(message = "用户名不能为空")
    @Size(min = 3, max = 64)
    private String username;

    @NotBlank(message = "密码不能为空")
    @Size(min = 12, max = 128)
    private String password;

    @Pattern(regexp = "USER|ADMIN", message = "角色只能是 USER 或 ADMIN")
    private String role = "USER";

    @Min(value = 1, message = "最大程序数至少为1")
    @Max(value = 100000, message = "最大程序数不能超过100000")
    private int maxPrograms = 5;
}

package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/** Nullable fields are applied only when present during an administrator update. */
@Data
public class UpdateUserRequest {
    @Size(min = 3, max = 64, message = "用户名长度必须为3-64位")
    private String username;

    @Size(min = 12, max = 128, message = "密码长度必须为12-128位")
    private String password;

    @Pattern(regexp = "USER|ADMIN", message = "角色只能是 USER 或 ADMIN")
    private String role;

    @Min(value = 1, message = "最大程序数至少为1")
    @Max(value = 100000, message = "最大程序数不能超过100000")
    private Integer maxPrograms;
}

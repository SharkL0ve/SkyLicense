package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class BanRequest {

    @NotBlank(message = "封禁类型不能为空")
    @Size(max = 4, message = "封禁类型不能超过4个字符")
    @Pattern(regexp = "(?i)IP|HWID|QQ|CODE", message = "封禁类型无效")
    private String type; // IP, HWID, QQ, CODE

    @NotBlank(message = "封禁值不能为空")
    @Size(max = 256, message = "封禁值不能超过256个字符")
    private String value;

    @Size(max = 1024, message = "封禁原因不能超过1024个字符")
    private String reason;

    @Positive(message = "程序ID必须大于0")
    private Long programId;

    @Pattern(
            regexp = "^$|\\d{4}-\\d{2}-\\d{2}-\\d{2}:\\d{2}",
            message = "封禁到期时间格式必须为 yyyy-MM-dd-HH:mm")
    private String expirationDate; // 过期时间，null=永久封禁
}

package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/** Fields omitted from an update remain unchanged; blank optional text clears it. */
@Data
public class UpdateLicenseRequest {
    @Size(max = 20, message = "QQ号不能超过20位")
    @Pattern(regexp = "^$|[0-9]{1,20}$", message = "QQ号必须是1-20位数字")
    private String qq;

    @Min(value = 0, message = "可绑定IP数不能为负数")
    @Max(value = 10000, message = "可绑定IP数不能超过10000")
    private Integer bindableIps;

    @Min(value = 0, message = "可绑定机器码数不能为负数")
    @Max(value = 10000, message = "可绑定机器码数不能超过10000")
    private Integer bindableHwids;

    @Size(max = 2048, message = "备注不能超过2048个字符")
    private String notes;

    @Pattern(
            regexp = "^$|\\d{4}-\\d{2}-\\d{2}-\\d{2}:\\d{2}",
            message = "到期时间格式必须为 yyyy-MM-dd-HH:mm")
    private String expirationDate;

    @Min(value = 0, message = "每日验证上限不能为负数")
    @Max(value = 1000000, message = "每日验证上限不能超过1000000")
    private Integer maxDailyAuth;
}

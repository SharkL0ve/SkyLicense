package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

/**
 * 管理员创建授权码请求
 * 支持为多个程序创建授权码，或使用 "all" 表示适用所有程序
 */
@Data
public class AdminCreateLicenseRequest {

    @Size(max = 256, message = "授权码不能超过256个字符")
    @Pattern(
            regexp = "^$|[A-Za-z0-9][A-Za-z0-9._+\\-]{0,255}",
            message = "授权码只能包含字母、数字、点、下划线、加号和连字符")
    private String code; // 为空则自动生成UUID

    /**
     * 目标程序ID列表。
     * 为每个程序分别创建一个授权码（code相同则共享，为空则各自生成）
     */
    @Size(max = 1000, message = "单次最多选择1000个程序")
    private List<@Positive(message = "程序ID必须大于0") Long> programIds;

    @Size(max = 20, message = "QQ号不能超过20位")
    @Pattern(regexp = "^$|[0-9]{1,20}$", message = "QQ号必须是1-20位数字")
    private String qq;

    @Min(value = 0, message = "可绑定IP数不能为负数")
    @Max(value = 10000, message = "可绑定IP数不能超过10000")
    private int bindableIps = 1;

    @Min(value = 0, message = "可绑定机器码数不能为负数")
    @Max(value = 10000, message = "可绑定机器码数不能超过10000")
    private int bindableHwids = 0;

    @Size(max = 2048, message = "备注不能超过2048个字符")
    private String notes;

    @Pattern(
            regexp = "^$|\\d{4}-\\d{2}-\\d{2}-\\d{2}:\\d{2}",
            message = "到期时间格式必须为 yyyy-MM-dd-HH:mm")
    private String expirationDate;

    @Min(value = 0, message = "每日验证上限不能为负数")
    @Max(value = 1000000, message = "每日验证上限不能超过1000000")
    private int maxDailyAuth = 0;

    /**
     * 是否为所有程序创建（忽略 programIds）
     */
    private boolean allPrograms = false;
}

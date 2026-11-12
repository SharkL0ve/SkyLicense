package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/** Nullable fields are applied only when present during a program update. */
@Data
public class UpdateProgramRequest {
    @Size(max = 64, message = "程序名称不能超过64位")
    @Pattern(
            regexp = "[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}",
            message = "程序名称只能包含字母、数字、点、下划线、加号和连字符")
    private String name;

    @Size(max = 2048, message = "程序描述不能超过2048个字符")
    private String description;
}

package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class BatchLicenseRequest {

    @NotEmpty(message = "授权码列表不能为空")
    @Size(max = 1000, message = "单次批量操作不能超过1000个授权码")
    private List<@NotBlank @Size(max = 256) @Pattern(
            regexp = "[A-Za-z0-9][A-Za-z0-9._+\\-]{0,255}") String> codes;

    @Size(max = 1024, message = "封禁原因不能超过1024个字符")
    private String reason; // 用于批量封禁
}

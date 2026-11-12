package cn.sky.skylicense.web.dto.query;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class AuthLogQuery {
    @Size(max = 256)
    @Pattern(regexp = "^$|[A-Za-z0-9][A-Za-z0-9._+\\-]{0,255}$")
    private String code;

    @Size(max = 64)
    @Pattern(regexp = "^$|[0-9A-Fa-f:.]{1,64}$")
    private String ip;

    @Size(max = 256)
    @Pattern(regexp = "^$|[A-Za-z0-9+/=]{1,256}$")
    private String hwid;

    @Size(max = 64)
    @Pattern(regexp = "^$|[A-Z][A-Z0-9_]{0,63}$")
    private String result;      // OK, FAILED, BANNED, etc.

    @Size(max = 16)
    @Pattern(regexp = "^$|\\d{4}-\\d{2}-\\d{2}-\\d{2}:\\d{2}$")
    private String startTime;

    @Size(max = 16)
    @Pattern(regexp = "^$|\\d{4}-\\d{2}-\\d{2}-\\d{2}:\\d{2}$")
    private String endTime;

    @Positive
    private Long programId;
}

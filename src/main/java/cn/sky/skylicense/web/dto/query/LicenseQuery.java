package cn.sky.skylicense.web.dto.query;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LicenseQuery {
    @Size(max = 16)
    @Pattern(regexp = "^$|(?i:active|banned)$")
    private String status;      // "active", "banned", or null for all

    @Size(max = 128)
    private String qq;

    @Size(max = 64)
    @Pattern(regexp = "^$|[0-9A-Fa-f:.]{1,64}$")
    private String ip;

    @Size(max = 256)
    @Pattern(regexp = "^$|[A-Za-z0-9+/=]{1,256}$")
    private String hwid;

    @Size(max = 256)
    private String keyword;     // search in code/qq/notes

    @Size(max = 32)
    @Pattern(regexp = "^$|createTime|lastAuthTime|code|qq|status")
    private String sortBy;      // createTime, lastAuthTime, code

    @Size(max = 4)
    @Pattern(regexp = "^$|(?i:asc|desc)$")
    private String order;       // asc, desc
}

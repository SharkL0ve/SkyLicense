package cn.sky.skylicense.web.dto.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UnbindRequest {
    @Size(max = 64, message = "IP不能超过64个字符")
    private String ip;   // 要解绑的单个IP，为空则不操作IP
    @Size(max = 256, message = "HWID不能超过256个字符")
    private String hwid; // 要解绑的单个HWID，为空则不操作HWID
    private boolean all; // true=清空所有绑定

    @AssertTrue(message = "必须指定IP、HWID或清空全部绑定")
    public boolean isOperationSpecified() {
        return all
                || ip != null && !ip.isBlank()
                || hwid != null && !hwid.isBlank();
    }
}

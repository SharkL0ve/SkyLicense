package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.web.aop.OpLog;
import cn.sky.skylicense.web.dto.query.LicenseQuery;
import cn.sky.skylicense.web.dto.request.BatchLicenseRequest;
import cn.sky.skylicense.web.dto.request.CreateLicenseRequest;
import cn.sky.skylicense.web.dto.request.UnbindRequest;
import cn.sky.skylicense.web.dto.request.UpdateLicenseRequest;
import cn.sky.skylicense.web.dto.response.ApiResponse;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.service.LicenseService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Validated
@RestController
@RequestMapping("/api")
public class LicenseController {
    private static final String LICENSE_CODE_PATTERN =
            "[A-Za-z0-9][A-Za-z0-9._+\\-]{0,255}";

    private final LicenseService licenseService;

    public LicenseController(LicenseService licenseService) {
        this.licenseService = licenseService;
    }

    @GetMapping("/programs/{programId}/licenses")
    public ApiResponse<PageResult<License>> listByProgram(
            @PathVariable long programId,
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize,
            @Valid LicenseQuery query) {
        return ApiResponse.ok(licenseService.listByProgram(programId, page, pageSize, query));
    }

    @OpLog(action = "CREATE_LICENSE", target = "license")
    @PostMapping("/programs/{programId}/licenses")
    public ApiResponse<License> create(
            @PathVariable long programId,
            @Valid @RequestBody CreateLicenseRequest request) {
        License license = licenseService.createLicense(programId, request);
        return ApiResponse.ok("授权码创建成功", license);
    }

    /**
     * 为多个程序创建授权码（用户只能选择自己的程序）
     * 请求体中 programIds 指定目标程序列表
     */
    @OpLog(action = "CREATE_LICENSE_MULTI", target = "license")
    @PostMapping("/licenses/multi")
    public ApiResponse<java.util.List<License>> createMulti(@Valid @RequestBody CreateLicenseRequest request) {
        java.util.List<License> licenses = licenseService.createLicenseMulti(request);
        return ApiResponse.ok("授权码创建成功，共 " + licenses.size() + " 个", licenses);
    }

    @GetMapping("/licenses/{code}")
    public ApiResponse<License> get(
            @PathVariable @Size(min = 1, max = 256)
            @Pattern(regexp = LICENSE_CODE_PATTERN) String code) {
        return ApiResponse.ok(licenseService.getByCode(code));
    }

    @OpLog(action = "UPDATE_LICENSE", target = "license")
    @PutMapping("/licenses/{code}")
    public ApiResponse<License> update(
            @PathVariable @Size(min = 1, max = 256)
            @Pattern(regexp = LICENSE_CODE_PATTERN) String code,
            @Valid @RequestBody UpdateLicenseRequest request) {
        return ApiResponse.ok(licenseService.updateLicense(code, request));
    }

    @OpLog(action = "DELETE_LICENSE", target = "license")
    @DeleteMapping("/licenses/{code}")
    public ApiResponse<Void> delete(
            @PathVariable @Size(min = 1, max = 256)
            @Pattern(regexp = LICENSE_CODE_PATTERN) String code) {
        licenseService.deleteLicense(code);
        return ApiResponse.ok("授权码删除成功", null);
    }

    @OpLog(action = "UNBIND_LICENSE", target = "license")
    @PutMapping("/licenses/{code}/unbind")
    public ApiResponse<License> unbind(
            @PathVariable @Size(min = 1, max = 256)
            @Pattern(regexp = LICENSE_CODE_PATTERN) String code,
            @Valid @RequestBody UnbindRequest request) {
        License license = licenseService.unbind(code, request);
        return ApiResponse.ok("解绑成功", license);
    }

    @OpLog(action = "BAN_LICENSE", target = "license")
    @PutMapping("/licenses/{code}/ban")
    public ApiResponse<Void> ban(
            @PathVariable @Size(min = 1, max = 256)
            @Pattern(regexp = LICENSE_CODE_PATTERN) String code,
            @RequestParam(required = false) @Size(max = 1024) String reason) {
        licenseService.banLicense(code, reason);
        return ApiResponse.ok("封禁成功", null);
    }

    @OpLog(action = "UNBAN_LICENSE", target = "license")
    @PutMapping("/licenses/{code}/unban")
    public ApiResponse<Void> unban(
            @PathVariable @Size(min = 1, max = 256)
            @Pattern(regexp = LICENSE_CODE_PATTERN) String code) {
        licenseService.unbanLicense(code);
        return ApiResponse.ok("解封成功", null);
    }

    @GetMapping("/licenses/{code}/logs")
    public ApiResponse<PageResult<AuthLog>> logs(
            @PathVariable @Size(min = 1, max = 256)
            @Pattern(regexp = LICENSE_CODE_PATTERN) String code,
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        return ApiResponse.ok(licenseService.getAuthLogs(code, page, pageSize));
    }

    /**
     * 查看当前用户所有程序的验证历史（支持筛选）
     * 管理员可查看全部
     */
    @GetMapping("/auth-logs")
    public ApiResponse<PageResult<AuthLog>> allAuthLogs(
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize,
            @Valid cn.sky.skylicense.web.dto.query.AuthLogQuery query) {
        return ApiResponse.ok(licenseService.getAuthLogsByUser(query, page, pageSize));
    }

    // ===== 批量操作 =====

    @OpLog(action = "BATCH_BAN_LICENSE", target = "license")
    @PutMapping("/licenses/batch/ban")
    public ApiResponse<Map<String, Integer>> batchBan(@Valid @RequestBody BatchLicenseRequest request) {
        int count = licenseService.batchBan(request);
        return ApiResponse.ok("批量封禁完成", Map.of("affected", count));
    }

    @OpLog(action = "BATCH_UNBAN_LICENSE", target = "license")
    @PutMapping("/licenses/batch/unban")
    public ApiResponse<Map<String, Integer>> batchUnban(@Valid @RequestBody BatchLicenseRequest request) {
        int count = licenseService.batchUnban(request);
        return ApiResponse.ok("批量解封完成", Map.of("affected", count));
    }

    @OpLog(action = "BATCH_DELETE_LICENSE", target = "license")
    @DeleteMapping("/licenses/batch")
    public ApiResponse<Map<String, Integer>> batchDelete(@Valid @RequestBody BatchLicenseRequest request) {
        int count = licenseService.batchDelete(request);
        return ApiResponse.ok("批量删除完成", Map.of("affected", count));
    }
}

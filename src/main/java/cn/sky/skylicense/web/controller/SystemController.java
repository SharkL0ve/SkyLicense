package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.web.aop.OpLog;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.response.ApiResponse;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.dto.response.OperationIntegrityResponse;
import cn.sky.skylicense.web.dto.response.OperationLogView;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.service.LicenseService;
import cn.sky.skylicense.web.service.OperationLogService;
import cn.sky.skylicense.web.service.ProgramService;
import cn.sky.skylicense.web.service.ResourceUploadService;
import cn.sky.skylicense.web.service.SessionService;
import cn.sky.skylicense.netty.SessionManager;
import cn.sky.skylicense.netty.SocketHandler;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Validated
@RestController
@RequestMapping("/api/admin")
public class SystemController {

    private final ProgramService programService;
    private final LicenseService licenseService;
    private final OperationLogService operationLogService;
    private final ResourceUploadService resourceUploadService;
    private final SessionService sessionService;
    private final WebDataAccessor webDataAccessor;

    public SystemController(ProgramService programService, LicenseService licenseService,
                            OperationLogService operationLogService, ResourceUploadService resourceUploadService,
                            SessionService sessionService, WebDataAccessor webDataAccessor) {
        this.programService = programService;
        this.licenseService = licenseService;
        this.operationLogService = operationLogService;
        this.resourceUploadService = resourceUploadService;
        this.sessionService = sessionService;
        this.webDataAccessor = webDataAccessor;
    }

    @GetMapping("/programs")
    public ApiResponse<PageResult<Program>> allPrograms(
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        requireAdmin();
        return ApiResponse.ok(programService.listPrograms(page, pageSize));
    }

    @GetMapping("/licenses")
    public ApiResponse<PageResult<License>> allLicenses(
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        requireAdmin();
        return ApiResponse.ok(licenseService.listAll(page, pageSize));
    }

    /**
     * 管理员创建授权码（支持指定单个/多个程序，或所有程序）
     *
     * 示例1 - 为单个程序创建: { "programIds": [1], "qq": "123", "bindableIps": 2 }
     * 示例2 - 为多个程序创建: { "programIds": [1, 2, 3], "qq": "123" }
     * 示例3 - 为所有程序创建: { "allPrograms": true, "qq": "123" }
     */
    @OpLog(action = "ADMIN_CREATE_LICENSE", target = "license")
    @PostMapping("/licenses")
    public ApiResponse<java.util.List<License>> createLicense(
            @Valid @RequestBody cn.sky.skylicense.web.dto.request.AdminCreateLicenseRequest request) {
        requireAdmin();
        java.util.List<License> licenses = licenseService.adminCreateLicense(request);
        return ApiResponse.ok("授权码创建成功，共 " + licenses.size() + " 个", licenses);
    }

    @GetMapping("/operations")
    public ApiResponse<PageResult<OperationLogView>> allOperations(
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        requireAdmin();
        return ApiResponse.ok(operationLogService.listAll(page, pageSize));
    }

    @GetMapping("/operations/integrity")
    public ApiResponse<OperationIntegrityResponse> operationIntegrity() {
        requireAdmin();
        return ApiResponse.ok(operationLogService.integrityStatus());
    }

    /**
     * 管理员查看所有验证历史（包含所有失败类型）
     * 支持按 programId/code/ip/hwid/result/时间范围 筛选
     */
    @GetMapping("/auth-logs")
    public ApiResponse<PageResult<cn.sky.skylicense.web.entity.AuthLog>> allAuthLogs(
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize,
            @Valid cn.sky.skylicense.web.dto.query.AuthLogQuery query) {
        requireAdmin();
        return ApiResponse.ok(licenseService.getAuthLogsByUser(query, page, pageSize));
    }

    @OpLog(action = "RELOAD_RESOURCES", target = "system")
    @PostMapping("/reload")
    public ApiResponse<Void> reload() {
        requireAdmin();
        resourceUploadService.reloadResources();
        return ApiResponse.ok("资源重载成功", null);
    }

    @GetMapping("/stats")
    public ApiResponse<?> stats() {
        requireAdmin();
        try {
            long userCount = webDataAccessor.getUserDao().countOf();
            long programCount = webDataAccessor.getProgramDao().countOf();
            long licenseCount = webDataAccessor.getLicenseDao().countOf();
            long banCount = webDataAccessor.getBanRecordDao().countOf();
            long activeLicenses = webDataAccessor.getLicenseDao().queryBuilder()
                    .where().eq("status", 1).countOf();
            long bannedLicenses = webDataAccessor.getLicenseDao().queryBuilder()
                    .where().eq("status", 0).countOf();
            long authLogCount = webDataAccessor.getAuthLogDao().countOf();
            long versionCount = webDataAccessor.getProgramVersionDao().countOf();

            SocketHandler.NativeRateLimitStats rateLimits = SocketHandler.rateLimitStats();
            java.util.Map<String, Object> stats = new java.util.LinkedHashMap<>();
            stats.put("userCount", userCount);
            stats.put("programCount", programCount);
            stats.put("licenseCount", licenseCount);
            stats.put("activeLicenses", activeLicenses);
            stats.put("bannedLicenses", bannedLicenses);
            stats.put("banRecordCount", banCount);
            stats.put("authLogCount", authLogCount);
            stats.put("versionCount", versionCount);
            stats.put("activeWebSessionCount", sessionService.activeCount());
            stats.put("activeClientSessionCount", SessionManager.getActiveSessionCount());
            stats.put("authRateLimitTrackedAddresses", rateLimits.authTrackedAddresses());
            stats.put("authRateLimitRejectedCount",
                    rateLimits.authThrottledRejections() + rateLimits.authCapacityRejections());
            stats.put("authRateLimitCapacityRejectedCount", rateLimits.authCapacityRejections());
            stats.put("heartbeatRateLimitTrackedAddresses", rateLimits.heartbeatTrackedAddresses());
            stats.put("heartbeatRateLimitRejectedCount",
                    rateLimits.heartbeatThrottledRejections()
                            + rateLimits.heartbeatCapacityRejections());
            stats.put("heartbeatRateLimitCapacityRejectedCount",
                    rateLimits.heartbeatCapacityRejections());
            return ApiResponse.ok(stats);
        } catch (Exception e) {
            throw new BizException(500, "统计查询失败");
        }
    }

    private void requireAdmin() {
        UserContext ctx = UserContext.get();
        if (ctx == null || !ctx.isAdmin()) {
            throw BizException.forbidden("需要管理员权限");
        }
    }
}

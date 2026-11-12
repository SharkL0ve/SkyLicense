package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.web.aop.OpLog;
import cn.sky.skylicense.web.dto.query.AuthLogQuery;
import cn.sky.skylicense.web.dto.request.CreateProgramRequest;
import cn.sky.skylicense.web.dto.request.UpdateProgramRequest;
import cn.sky.skylicense.web.dto.response.ApiResponse;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.ProgramVersion;
import cn.sky.skylicense.web.service.LicenseService;
import cn.sky.skylicense.web.service.ProgramService;
import cn.sky.skylicense.web.service.ResourceUploadService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Validated
@RestController
@RequestMapping("/api/programs")
public class ProgramController {

    private final ProgramService programService;
    private final ResourceUploadService resourceUploadService;
    private final LicenseService licenseService;

    public ProgramController(ProgramService programService, ResourceUploadService resourceUploadService,
                             LicenseService licenseService) {
        this.programService = programService;
        this.resourceUploadService = resourceUploadService;
        this.licenseService = licenseService;
    }

    @GetMapping
    public ApiResponse<PageResult<Program>> list(
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        return ApiResponse.ok(programService.listPrograms(page, pageSize));
    }

    @OpLog(action = "CREATE_PROGRAM", target = "program")
    @PostMapping
    public ApiResponse<Program> create(@Valid @RequestBody CreateProgramRequest request) {
        Program program = programService.createProgram(request);
        return ApiResponse.ok("程序创建成功", program);
    }

    @GetMapping("/{id}")
    public ApiResponse<Program> get(@PathVariable long id) {
        return ApiResponse.ok(programService.getProgram(id));
    }

    @OpLog(action = "UPDATE_PROGRAM", target = "program")
    @PutMapping("/{id}")
    public ApiResponse<Program> update(
            @PathVariable long id,
            @Valid @RequestBody UpdateProgramRequest request) {
        return ApiResponse.ok(programService.updateProgram(id, request));
    }

    @OpLog(action = "DELETE_PROGRAM", target = "program")
    @DeleteMapping("/{id}")
    public ApiResponse<Void> delete(@PathVariable long id) {
        programService.deleteProgram(id);
        return ApiResponse.ok("程序删除成功", null);
    }

    // ===== 版本管理 =====

    @GetMapping("/{id}/versions")
    public ApiResponse<List<ProgramVersion>> listVersions(@PathVariable long id) {
        return ApiResponse.ok(resourceUploadService.listVersions(id));
    }

    @OpLog(action = "UPLOAD_VERSION", target = "program_version")
    @PostMapping("/{id}/versions")
    public ApiResponse<ProgramVersion> uploadVersion(
            @PathVariable long id,
            @RequestParam String version,
            @RequestParam("file") MultipartFile file) {
        ProgramVersion pv = resourceUploadService.uploadVersion(id, version, file);
        return ApiResponse.ok("版本上传成功", pv);
    }

    @DeleteMapping("/{id}/versions/{vid}")
    public ApiResponse<Void> deleteVersion(@PathVariable long id, @PathVariable long vid) {
        resourceUploadService.deleteVersion(id, vid);
        return ApiResponse.ok("版本删除成功", null);
    }

    @OpLog(action = "TOGGLE_PROGRAM_STATUS", target = "program")
    @PutMapping("/{id}/status")
    public ApiResponse<Void> toggleStatus(
            @PathVariable long id,
            @RequestParam @Min(0) @Max(1) int status) {
        programService.toggleStatus(id, status);
        return ApiResponse.ok("状态更新成功", null);
    }

    /**
     * 查看指定程序的所有验证历史（包含成功和失败记录）
     * 支持按 result/ip/hwid/code/时间范围 筛选
     */
    @GetMapping("/{id}/auth-logs")
    public ApiResponse<PageResult<AuthLog>> authLogs(
            @PathVariable long id,
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize,
            @Valid AuthLogQuery query) {
        return ApiResponse.ok(licenseService.getAuthLogsByProgram(id, query, page, pageSize));
    }
}

package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.web.aop.OpLog;
import cn.sky.skylicense.web.dto.request.CreateUserRequest;
import cn.sky.skylicense.web.dto.request.UpdateUserRequest;
import cn.sky.skylicense.web.dto.request.AdminMfaResetRequest;
import cn.sky.skylicense.web.dto.response.ApiResponse;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.dto.response.OperationLogView;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.service.OperationLogService;
import cn.sky.skylicense.web.service.UserService;
import cn.sky.skylicense.web.service.MfaService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Validated
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final OperationLogService operationLogService;
    private final MfaService mfaService;

    public UserController(
            UserService userService,
            OperationLogService operationLogService,
            MfaService mfaService
    ) {
        this.userService = userService;
        this.operationLogService = operationLogService;
        this.mfaService = mfaService;
    }

    @GetMapping
    public ApiResponse<PageResult<WebUser>> list(
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        requireAdmin();
        return ApiResponse.ok(userService.listUsers(page, pageSize));
    }

    @OpLog(action = "CREATE_USER", target = "user")
    @PostMapping
    public ApiResponse<WebUser> create(@Valid @RequestBody CreateUserRequest request) {
        requireAdmin();
        WebUser user = userService.createUser(request);
        return ApiResponse.ok("用户创建成功", user);
    }

    @GetMapping("/{id}")
    public ApiResponse<WebUser> get(@PathVariable long id) {
        requireAdmin();
        return ApiResponse.ok(userService.getUser(id));
    }

    @OpLog(action = "UPDATE_USER", target = "user")
    @PutMapping("/{id}")
    public ApiResponse<WebUser> update(
            @PathVariable long id,
            @Valid @RequestBody UpdateUserRequest request) {
        requireAdmin();
        return ApiResponse.ok(userService.updateUser(id, request));
    }

    @OpLog(action = "DELETE_USER", target = "user")
    @DeleteMapping("/{id}")
    public ApiResponse<Void> delete(@PathVariable long id) {
        requireAdmin();
        userService.deleteUser(id);
        return ApiResponse.ok("用户删除成功", null);
    }

    @OpLog(action = "TOGGLE_USER_STATUS", target = "user")
    @PutMapping("/{id}/status")
    public ApiResponse<Void> toggleStatus(
            @PathVariable long id,
            @RequestParam @Min(0) @Max(1) int status) {
        requireAdmin();
        userService.toggleStatus(id, status);
        return ApiResponse.ok("状态更新成功", null);
    }

    @OpLog(action = "ADMIN_RESET_MFA", target = "user")
    @DeleteMapping("/{id}/mfa")
    public ApiResponse<Void> resetMfa(
            @PathVariable long id,
            @Valid @RequestBody AdminMfaResetRequest request
    ) {
        requireAdmin();
        mfaService.resetByAdministrator(id, request.getPassword(), request.getFactor());
        return ApiResponse.ok("用户 MFA 已重置", null);
    }

    @GetMapping("/{id}/operations")
    public ApiResponse<PageResult<OperationLogView>> operations(
            @PathVariable long id,
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        requireAdmin();
        return ApiResponse.ok(operationLogService.listByUser(id, page, pageSize));
    }

    private void requireAdmin() {
        UserContext ctx = UserContext.get();
        if (ctx == null || !ctx.isAdmin()) {
            throw BizException.forbidden("需要管理员权限");
        }
    }
}

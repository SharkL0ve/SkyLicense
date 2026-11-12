package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.web.dto.request.ChangePasswordRequest;
import cn.sky.skylicense.web.dto.request.LoginRequest;
import cn.sky.skylicense.web.dto.request.MfaChallengeRequest;
import cn.sky.skylicense.web.dto.request.MfaEnrollmentStartRequest;
import cn.sky.skylicense.web.dto.request.MfaFactorRequest;
import cn.sky.skylicense.web.dto.request.MfaManageRequest;
import cn.sky.skylicense.web.dto.response.ApiResponse;
import cn.sky.skylicense.web.dto.response.AuthLoginResponse;
import cn.sky.skylicense.web.dto.response.AuthSessionResponse;
import cn.sky.skylicense.web.dto.response.MfaEnrollmentResponse;
import cn.sky.skylicense.web.dto.response.MfaRecoveryCodesResponse;
import cn.sky.skylicense.web.dto.response.MfaStatusResponse;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.aop.OpLog;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.security.WebSessionSecurity;
import cn.sky.skylicense.web.service.AuthService;
import cn.sky.skylicense.web.service.MfaService;
import cn.sky.skylicense.web.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final MfaService mfaService;
    private final boolean crossSiteCookie;

    public AuthController(AuthService authService, MfaService mfaService) {
        this.authService = authService;
        this.mfaService = mfaService;
        crossSiteCookie = !SkyLicense.configuration()
                .getStorage()
                .getAllowedWebOrigins()
                .isEmpty();
    }

    @OpLog(action = "LOGIN", target = "auth", allowAnonymous = true)
    @PostMapping("/login")
    public ApiResponse<AuthLoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        AuthService.LoginOutcome outcome =
                authService.authenticate(request, servletRequest.getRemoteAddr());
        if (outcome.mfaRequired()) {
            MfaService.LoginChallenge challenge = outcome.challenge();
            return ApiResponse.ok(AuthLoginResponse.challenge(
                    challenge.token(), challenge.expiresInSeconds()));
        }
        SessionService.SessionToken session = outcome.session();
        WebSessionSecurity.setSessionCookie(
                servletResponse,
                session.token(),
                session.expiresInSeconds(),
                crossSiteCookie);
        return ApiResponse.ok(AuthLoginResponse.authenticated(
                session.csrfToken(), session.expiresInSeconds()));
    }

    @OpLog(action = "MFA_LOGIN_VERIFY", target = "auth", allowAnonymous = true)
    @PostMapping("/mfa/verify")
    public ApiResponse<AuthLoginResponse> verifyMfa(
            @Valid @RequestBody MfaChallengeRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        SessionService.SessionToken session = authService.verifyMfa(
                request.getChallengeToken(),
                request.getFactor(),
                servletRequest.getRemoteAddr());
        WebSessionSecurity.setSessionCookie(
                servletResponse,
                session.token(),
                session.expiresInSeconds(),
                crossSiteCookie);
        return ApiResponse.ok(AuthLoginResponse.authenticated(
                session.csrfToken(), session.expiresInSeconds()));
    }

    @OpLog(action = "LOGOUT", target = "auth")
    @PostMapping("/logout")
    public ApiResponse<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        WebSessionSecurity.clearSessionCookie(response, crossSiteCookie);
        Object authenticatedToken = request.getAttribute(
                WebSessionSecurity.AUTH_TOKEN_ATTRIBUTE);
        if (authenticatedToken instanceof String token) {
            authService.logout(token);
        }
        return ApiResponse.ok("已登出", null);
    }

    @GetMapping("/me")
    public ApiResponse<WebUser> me() {
        WebUser user = authService.getCurrentUser();
        return ApiResponse.ok(user);
    }

    @GetMapping("/session")
    public ApiResponse<AuthSessionResponse> session() {
        UserContext context = UserContext.get();
        if (context == null) {
            throw BizException.unauthorized("未登录");
        }
        return ApiResponse.ok(new AuthSessionResponse(
                authService.getCurrentUser(), context.getCsrfToken()));
    }

    @GetMapping("/mfa/status")
    public ApiResponse<MfaStatusResponse> mfaStatus() {
        return ApiResponse.ok(mfaService.status());
    }

    @OpLog(action = "MFA_ENROLL_START", target = "auth")
    @PostMapping("/mfa/enrollment")
    public ApiResponse<MfaEnrollmentResponse> startMfaEnrollment(
            @Valid @RequestBody MfaEnrollmentStartRequest request
    ) {
        return ApiResponse.ok(mfaService.startEnrollment(request.getPassword()));
    }

    @OpLog(action = "MFA_ENROLL_CONFIRM", target = "auth")
    @PostMapping("/mfa/enrollment/confirm")
    public ApiResponse<MfaRecoveryCodesResponse> confirmMfaEnrollment(
            @Valid @RequestBody MfaFactorRequest request,
            HttpServletResponse response
    ) {
        MfaRecoveryCodesResponse result = mfaService.confirmEnrollment(request.getFactor());
        WebSessionSecurity.clearSessionCookie(response, crossSiteCookie);
        return ApiResponse.ok("MFA 已启用，请保存恢复码后重新登录", result);
    }

    @OpLog(action = "MFA_RECOVERY_REGENERATE", target = "auth")
    @PostMapping("/mfa/recovery-codes")
    public ApiResponse<MfaRecoveryCodesResponse> regenerateMfaRecoveryCodes(
            @Valid @RequestBody MfaManageRequest request,
            HttpServletResponse response
    ) {
        MfaRecoveryCodesResponse result = mfaService.regenerateRecoveryCodes(
                request.getPassword(), request.getFactor());
        WebSessionSecurity.clearSessionCookie(response, crossSiteCookie);
        return ApiResponse.ok("恢复码已更新，请保存后重新登录", result);
    }

    @OpLog(action = "MFA_DISABLE", target = "auth")
    @DeleteMapping("/mfa")
    public ApiResponse<Void> disableMfa(
            @Valid @RequestBody MfaManageRequest request,
            HttpServletResponse response
    ) {
        mfaService.disable(request.getPassword(), request.getFactor());
        WebSessionSecurity.clearSessionCookie(response, crossSiteCookie);
        return ApiResponse.ok("MFA 已禁用，请重新登录", null);
    }

    @OpLog(action = "CHANGE_PASSWORD", target = "auth")
    @PutMapping("/password")
    public ApiResponse<Void> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletResponse response
    ) {
        authService.changePassword(request);
        WebSessionSecurity.clearSessionCookie(response, crossSiteCookie);
        return ApiResponse.ok("密码修改成功", null);
    }
}

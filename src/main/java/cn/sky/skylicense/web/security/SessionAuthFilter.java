package cn.sky.skylicense.web.security;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.web.dto.response.ApiResponse;
import cn.sky.skylicense.web.service.OperationLogService;
import cn.sky.skylicense.web.service.SessionService;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

/** Resolves opaque browser credentials exclusively through the persistent session store. */
@Component
public final class SessionAuthFilter implements Filter {
    static final String ADMIN_MFA_REQUIRED_MESSAGE =
            "管理员必须先启用 MFA 才能访问此接口";

    private final Function<String, UserContext> sessionResolver;
    private final Supplier<List<String>> allowedOrigins;
    private final SecurityAuditSink securityAuditSink;
    private final Gson gson = new GsonBuilder().serializeNulls().create();

    @Autowired
    public SessionAuthFilter(
            SessionService sessionService,
            OperationLogService operationLogService
    ) {
        this(
                sessionService::resolveContext,
                configuredAllowedOrigins(),
                operationLogService::logSecurityRejection);
    }

    SessionAuthFilter(
            Function<String, UserContext> sessionResolver,
            Supplier<List<String>> allowedOrigins
    ) {
        this(sessionResolver, allowedOrigins, (actor, reason, method, ip) -> { });
    }

    SessionAuthFilter(
            Function<String, UserContext> sessionResolver,
            Supplier<List<String>> allowedOrigins,
            SecurityAuditSink securityAuditSink
    ) {
        this.sessionResolver = sessionResolver;
        this.allowedOrigins = allowedOrigins;
        this.securityAuditSink = securityAuditSink;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();
        if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        if ("/api/auth/login".equals(path) || "/api/auth/mfa/verify".equals(path)) {
            if (!WebSessionSecurity.isRequestOriginAllowed(
                    httpRequest,
                    allowedOrigins.get())) {
                auditRejection(httpRequest, null, "LOGIN_ORIGIN_REJECTED");
                sendError(httpResponse, 403, "Login request origin is not trusted");
                return;
            }
            chain.doFilter(request, response);
            return;
        }

        String token = WebSessionSecurity.readSessionToken(httpRequest);
        if (token == null) {
            sendError(httpResponse, 401, "未提供有效会话");
            return;
        }

        UserContext context = sessionResolver.apply(token);
        if (context == null) {
            sendError(httpResponse, 401, "会话已撤销或已过期，请重新登录");
            return;
        }

        if (WebSessionSecurity.requiresCsrf(httpRequest.getMethod())) {
            if (!WebSessionSecurity.isRequestOriginAllowed(
                    httpRequest,
                    allowedOrigins.get())) {
                auditRejection(httpRequest, context, "ORIGIN_REJECTED");
                sendError(httpResponse, 403, "请求来源不受信任");
                return;
            }
            if (!WebSessionSecurity.csrfMatches(
                    context.getCsrfToken(),
                    httpRequest.getHeader(WebSessionSecurity.CSRF_HEADER))) {
                auditRejection(httpRequest, context, "CSRF_REJECTED");
                sendError(httpResponse, 403, "CSRF 校验失败");
                return;
            }
        }

        if (httpRequest.getAttribute(WebSessionSecurity.AUTH_TOKEN_ATTRIBUTE) != null) {
            auditRejection(httpRequest, context, "DUPLICATE_AUTH_STATE");
            sendError(httpResponse, 400, "重复认证状态");
            return;
        }

        if (context.isAdmin()
                && !context.isMfaEnabled()
                && !isAdministratorMfaBootstrapEndpoint(
                        httpRequest.getMethod(), path)) {
            auditRejection(httpRequest, context, "ADMIN_MFA_REQUIRED");
            sendError(httpResponse, 403, ADMIN_MFA_REQUIRED_MESSAGE);
            return;
        }

        httpRequest.setAttribute(WebSessionSecurity.AUTH_TOKEN_ATTRIBUTE, token);
        UserContext.set(context);
        try {
            chain.doFilter(request, response);
        } finally {
            UserContext.clear();
        }
    }

    private static boolean isAdministratorMfaBootstrapEndpoint(
            String method,
            String path
    ) {
        return switch (method == null ? "" : method.toUpperCase(java.util.Locale.ROOT)) {
            case "GET" -> "/api/auth/session".equals(path)
                    || "/api/auth/me".equals(path)
                    || "/api/auth/mfa/status".equals(path);
            case "POST" -> "/api/auth/logout".equals(path)
                    || "/api/auth/mfa/enrollment".equals(path)
                    || "/api/auth/mfa/enrollment/confirm".equals(path);
            case "PUT" -> "/api/auth/password".equals(path);
            default -> false;
        };
    }

    private static Supplier<List<String>> configuredAllowedOrigins() {
        List<String> origins = List.copyOf(
                SkyLicense.configuration().getStorage().getAllowedWebOrigins());
        return () -> origins;
    }

    private void sendError(HttpServletResponse response, int status, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(gson.toJson(ApiResponse.error(status, message)));
    }

    private void auditRejection(
            HttpServletRequest request,
            UserContext actor,
            String reason
    ) {
        try {
            String address = request.getRemoteAddr();
            securityAuditSink.record(
                    actor,
                    reason,
                    request.getMethod(),
                    address == null ? "unknown" : address);
        } catch (Exception error) {
            SkyLicense.LOG.warn("Unable to persist Web security rejection reason={}", reason);
        }
    }

    @FunctionalInterface
    interface SecurityAuditSink {
        void record(UserContext actor, String reason, String method, String ip);
    }
}

package cn.sky.skylicense.web.aop;

import cn.sky.skylicense.web.service.OperationLogService;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;

import java.util.LinkedHashMap;
import java.util.Map;

@Aspect
@Component
public class OpLogAspect {
    private static final Logger LOG = LogManager.getLogger(OpLogAspect.class);

    private final OperationLogService operationLogService;
    private final OperationLogSanitizer sanitizer;

    public OpLogAspect(
            OperationLogService operationLogService,
            OperationLogSanitizer sanitizer
    ) {
        this.operationLogService = operationLogService;
        this.sanitizer = sanitizer;
    }

    @Around("@annotation(opLog)")
    public Object around(ProceedingJoinPoint joinPoint, OpLog opLog) throws Throwable {
        String target = opLog.target().isEmpty() ? getRequestPath() : opLog.target();
        long auditId = persistAudit(
                joinPoint,
                opLog,
                target,
                buildDetail(joinPoint, "ATTEMPT", null));
        if (auditId == 0L) {
            throw new BizException(503, "审计服务暂不可用，请稍后重试");
        }
        try {
            Object result = joinPoint.proceed();
            completeAudit(auditId, joinPoint, "SUCCESS", null);
            return result;
        } catch (Throwable failure) {
            completeAudit(auditId, joinPoint, "REJECTED", failure);
            throw failure;
        }
    }

    private long persistAudit(
            ProceedingJoinPoint joinPoint,
            OpLog opLog,
            String target,
            String detail
    ) {
        try {
            String ip = getClientIp();
            if (UserContext.get() == null && opLog.allowAnonymous()) {
                return operationLogService.logAnonymous(
                        opLog.action(), target, detail, ip, true);
            } else {
                return operationLogService.log(opLog.action(), target, detail, ip);
            }
        } catch (Exception error) {
            operationLogService.markUnhealthy();
            LOG.error(
                    "Unable to persist operation audit attempt action={} target={}",
                    opLog.action(),
                    target,
                    error);
            return 0L;
        }
    }

    private void completeAudit(
            long auditId,
            ProceedingJoinPoint joinPoint,
            String outcome,
            Throwable failure
    ) {
        try {
            operationLogService.complete(
                    auditId,
                    outcome,
                    buildDetail(joinPoint, outcome, failure));
        } catch (Exception error) {
            operationLogService.markUnhealthy();
            LOG.error(
                    "Unable to complete operation audit event id={} outcome={}",
                    auditId,
                    outcome,
                    error);
        }
    }

    private String buildDetail(
            ProceedingJoinPoint joinPoint,
            String outcome,
            Throwable failure
    ) {
        MethodSignature sig = (MethodSignature) joinPoint.getSignature();
        String[] paramNames = sig.getParameterNames();
        Object[] args = joinPoint.getArgs();
        if (paramNames == null || paramNames.length != args.length) {
            paramNames = new String[args.length];
            for (int index = 0; index < args.length; index++) {
                paramNames[index] = "arg" + index;
            }
        }

        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("outcome", outcome);
        if (failure instanceof BizException businessFailure) {
            detail.put("errorCode", businessFailure.getCode());
        } else if (failure != null) {
            detail.put("errorType", failure.getClass().getSimpleName());
        }
        for (int i = 0; i < paramNames.length; i++) {
            if (args[i] instanceof MultipartFile) {
                detail.put(paramNames[i], ((MultipartFile) args[i]).getOriginalFilename());
            } else if (args[i] instanceof ServletRequest || args[i] instanceof ServletResponse) {
                continue; // 跳过 servlet transport objects
            } else {
                detail.put(paramNames[i], args[i]);
            }
        }
        return sanitizer.serialize(detail);
    }

    private String getRequestPath() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) return "";
            return attrs.getRequest().getRequestURI();
        } catch (Exception e) {
            return "";
        }
    }

    private String getClientIp() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) return "unknown";
            HttpServletRequest request = attrs.getRequest();
            // Forwarded headers are attacker-controlled unless a trusted proxy is configured.
            return request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();
        } catch (Exception e) {
            return "unknown";
        }
    }
}

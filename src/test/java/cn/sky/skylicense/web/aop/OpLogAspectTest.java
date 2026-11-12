package cn.sky.skylicense.web.aop;

import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.request.LoginRequest;
import cn.sky.skylicense.web.entity.OperationLog;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.service.OperationLogService;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpLogAspectTest {
    @TempDir
    Path temporaryDirectory;

    @AfterEach
    void clearContext() {
        UserContext.clear();
    }

    @Test
    void rejectedMutationsAreAuditedWithoutExceptionMessagesOrRawIdentifiers() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("rejected-audit.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 9);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            OpLogAspect aspect = new OpLogAspect(service, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            OpLog annotation = Endpoint.class
                    .getDeclaredMethod("mutate", String.class)
                    .getAnnotation(OpLog.class);

            BizException failure = assertThrows(
                    BizException.class,
                    () -> aspect.around(joinPoint("SECRET-CODE"), annotation));
            assertEquals(403, failure.getCode());

            OperationLog stored = accessor.getOperationLogDao().queryForAll().get(0);
            assertEquals("MUTATE", stored.getAction());
            assertTrue(stored.getDetail().contains("\"outcome\":\"REJECTED\""));
            assertTrue(stored.getDetail().contains("\"errorCode\":403"));
            assertTrue(stored.getDetail().contains("ref:v1:"));
            assertFalse(stored.getDetail().contains("SECRET-CODE"));
            assertFalse(stored.getDetail().contains("denied for SECRET-CODE"));
        } finally {
            accessor.close();
        }
    }

    @Test
    void successfulMutationsAreMarkedSuccessfulAfterTheHandlerReturns() throws Throwable {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("successful-audit.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 13);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            OpLogAspect aspect = new OpLogAspect(service, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            OpLog annotation = Endpoint.class
                    .getDeclaredMethod("mutate", String.class)
                    .getAnnotation(OpLog.class);

            assertEquals("completed", aspect.around(
                    executingJoinPoint(new AtomicBoolean()), annotation));

            OperationLog stored = accessor.getOperationLogDao().queryForAll().get(0);
            assertTrue(stored.getDetail().contains("\"outcome\":\"SUCCESS\""));
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    @Test
    void anonymousLoginFailuresAreAuditedWithoutCredentialsOrAccountNames() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("anonymous-login-audit.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 6);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OpLogAspect aspect = new OpLogAspect(
                    new OperationLogService(accessor, sanitizer), sanitizer);
            LoginRequest request = new LoginRequest();
            request.setUsername("target-admin");
            request.setPassword("NeverStoreThisPassword1!");
            OpLog annotation = Endpoint.class
                    .getDeclaredMethod("login", LoginRequest.class)
                    .getAnnotation(OpLog.class);

            BizException failure = assertThrows(
                    BizException.class,
                    () -> aspect.around(loginJoinPoint(request), annotation));
            assertEquals(401, failure.getCode());

            OperationLog stored = accessor.getOperationLogDao().queryForAll().get(0);
            assertEquals(0L, stored.getUserId());
            assertEquals("anonymous", stored.getUsername());
            assertEquals("LOGIN", stored.getAction());
            assertTrue(stored.getDetail().contains("\"outcome\":\"REJECTED\""));
            assertTrue(stored.getDetail().contains("ref:v1:"));
            assertFalse(stored.getDetail().contains("target-admin"));
            assertFalse(stored.getDetail().contains("NeverStoreThisPassword1!"));
        } finally {
            accessor.close();
        }
    }

    @Test
    void anonymousLoginAuditIsRateLimitedWithoutBlockingTheLoginHandler() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("anonymous-login-rate-limit.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 11);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            OpLogAspect aspect = new OpLogAspect(service, sanitizer);
            LoginRequest request = new LoginRequest();
            request.setUsername("target-admin");
            request.setPassword("NeverStoreThisPassword1!");
            OpLog annotation = Endpoint.class
                    .getDeclaredMethod("login", LoginRequest.class)
                    .getAnnotation(OpLog.class);

            assertThrows(BizException.class,
                    () -> aspect.around(loginJoinPoint(request), annotation));
            assertThrows(BizException.class,
                    () -> aspect.around(loginJoinPoint(request), annotation));

            assertEquals(1, accessor.getOperationLogDao().countOf());
        } finally {
            accessor.close();
        }
    }

    @Test
    void auditWriteFailureStopsTheProtectedOperationBeforeItRuns() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("audit-write-failure.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 12);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            OpLogAspect aspect = new OpLogAspect(service, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            OpLog annotation = Endpoint.class
                    .getDeclaredMethod("mutate", String.class)
                    .getAnnotation(OpLog.class);
            AtomicBoolean executed = new AtomicBoolean();
            accessor.close();

            BizException failure = assertThrows(
                    BizException.class,
                    () -> aspect.around(executingJoinPoint(executed), annotation));
            assertEquals(503, failure.getCode());
            assertFalse(executed.get());
            assertFalse(service.isHealthy());
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    private static ProceedingJoinPoint joinPoint(String code) throws Exception {
        Method method = Endpoint.class.getDeclaredMethod("mutate", String.class);
        MethodSignature signature = (MethodSignature) Proxy.newProxyInstance(
                MethodSignature.class.getClassLoader(),
                new Class<?>[]{MethodSignature.class},
                (proxy, invoked, arguments) -> switch (invoked.getName()) {
                    case "getParameterNames" -> new String[]{"code"};
                    case "getMethod" -> method;
                    default -> defaultValue(invoked.getReturnType());
                });
        return (ProceedingJoinPoint) Proxy.newProxyInstance(
                ProceedingJoinPoint.class.getClassLoader(),
                new Class<?>[]{ProceedingJoinPoint.class},
                (proxy, invoked, arguments) -> switch (invoked.getName()) {
                    case "proceed" -> throw BizException.forbidden("denied for " + code);
                    case "getSignature" -> signature;
                    case "getArgs" -> new Object[]{code};
                    default -> defaultValue(invoked.getReturnType());
                });
    }

    private static ProceedingJoinPoint loginJoinPoint(LoginRequest request) throws Exception {
        Method method = Endpoint.class.getDeclaredMethod("login", LoginRequest.class);
        MethodSignature signature = (MethodSignature) Proxy.newProxyInstance(
                MethodSignature.class.getClassLoader(),
                new Class<?>[]{MethodSignature.class},
                (proxy, invoked, arguments) -> switch (invoked.getName()) {
                    case "getParameterNames" -> new String[]{"request"};
                    case "getMethod" -> method;
                    default -> defaultValue(invoked.getReturnType());
                });
        return (ProceedingJoinPoint) Proxy.newProxyInstance(
                ProceedingJoinPoint.class.getClassLoader(),
                new Class<?>[]{ProceedingJoinPoint.class},
                (proxy, invoked, arguments) -> switch (invoked.getName()) {
                    case "proceed" -> throw new BizException(401, "invalid credentials");
                    case "getSignature" -> signature;
                    case "getArgs" -> new Object[]{request};
                    default -> defaultValue(invoked.getReturnType());
                });
    }

    private static ProceedingJoinPoint executingJoinPoint(AtomicBoolean executed)
            throws Exception {
        Method method = Endpoint.class.getDeclaredMethod("mutate", String.class);
        MethodSignature signature = (MethodSignature) Proxy.newProxyInstance(
                MethodSignature.class.getClassLoader(),
                new Class<?>[]{MethodSignature.class},
                (proxy, invoked, arguments) -> switch (invoked.getName()) {
                    case "getParameterNames" -> new String[]{"code"};
                    case "getMethod" -> method;
                    default -> defaultValue(invoked.getReturnType());
                });
        return (ProceedingJoinPoint) Proxy.newProxyInstance(
                ProceedingJoinPoint.class.getClassLoader(),
                new Class<?>[]{ProceedingJoinPoint.class},
                (proxy, invoked, arguments) -> switch (invoked.getName()) {
                    case "proceed" -> {
                        executed.set(true);
                        yield "completed";
                    }
                    case "getSignature" -> signature;
                    case "getArgs" -> new Object[]{"safe-code"};
                    default -> defaultValue(invoked.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == char.class) {
            return '\0';
        }
        return 0;
    }

    private static final class Endpoint {
        @OpLog(action = "MUTATE", target = "license")
        private void mutate(String code) {
        }

        @OpLog(action = "LOGIN", target = "auth", allowAnonymous = true)
        private void login(LoginRequest request) {
        }
    }
}

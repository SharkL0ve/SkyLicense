package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.exception.GlobalExceptionHandler;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.service.OperationLogService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

class SystemControllerAuditTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void administratorCanVerifyAndListAuditEventsWithoutReceivingMacMaterial()
            throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("system-audit.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 57);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            SystemController controller = new SystemController(
                    null, null, service, null, null, accessor);
            MockMvc mvc = MockMvcBuilders.standaloneSetup(controller)
                    .setControllerAdvice(new GlobalExceptionHandler())
                    .build();

            UserContext.set(new UserContext(7L, "admin", "ADMIN", "csrf"));
            long auditId = service.log("TEST", "audit", "{}", "203.0.113.9");
            service.complete(auditId, "SUCCESS", "{\"outcome\":\"SUCCESS\"}");

            MvcResult integrity = mvc.perform(get("/api/admin/operations/integrity"))
                    .andReturn();
            assertEquals(200, integrity.getResponse().getStatus());
            String integrityBody = integrity.getResponse().getContentAsString();
            assertTrue(integrityBody.contains("\"verified\":true"));
            assertTrue(integrityBody.contains("\"status\":\"VERIFIED\""));
            assertNoMacMaterial(integrityBody);

            MvcResult operations = mvc.perform(get("/api/admin/operations"))
                    .andReturn();
            assertEquals(200, operations.getResponse().getStatus());
            String operationsBody = operations.getResponse().getContentAsString();
            assertTrue(operationsBody.contains("\"eventId\""));
            assertTrue(operationsBody.contains("\"outcome\":\"SUCCESS\""));
            assertNoMacMaterial(operationsBody);

            UserContext.set(new UserContext(8L, "operator", "USER", "csrf"));
            MvcResult forbidden = mvc.perform(get("/api/admin/operations/integrity"))
                    .andReturn();
            assertEquals(403, forbidden.getResponse().getStatus());
        } finally {
            UserContext.clear();
            Arrays.fill(key, (byte) 0);
            accessor.close();
        }
    }

    private static void assertNoMacMaterial(String body) {
        assertFalse(body.contains("chainPreviousMac"));
        assertFalse(body.contains("chainMac"));
        assertFalse(body.contains("integrityMac"));
        assertFalse(body.contains("headMac"));
        assertFalse(body.contains("stateMac"));
    }
}

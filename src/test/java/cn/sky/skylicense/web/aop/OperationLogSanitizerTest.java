package cn.sky.skylicense.web.aop;

import org.junit.jupiter.api.Test;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.List;
import java.util.Map;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OperationLogSanitizerTest {
    @Test
    void secretsAndIdentifiersAreNeverSerializedAsPlaintext() {
        String password = "bad\\\"password";
        String code = "LICENSE-123";
        String hwid = "HWID-ABC";
        String ip = "203.0.113.10";
        String username = "target-admin";

        String detail;
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key((byte) 1))) {
            detail = sanitizer.serialize(Map.of(
                    "password", password,
                    "code", code,
                    "codes", List.of(code),
                    "hwid", hwid,
                    "ip", ip,
                    "username", username,
                    "nested", Map.of("newPassword", password)));
        }

        assertFalse(detail.contains(password));
        assertFalse(detail.contains(code));
        assertFalse(detail.contains(hwid));
        assertFalse(detail.contains(ip));
        assertFalse(detail.contains(username));
        assertTrue(detail.contains("***"));
        assertTrue(detail.contains("ref:"));
    }

    @Test
    void referencesAreKeyedStableAndVersionedForAuditCorrelation() {
        OperationLogSanitizer first = OperationLogSanitizer.forKey(key((byte) 1));
        OperationLogSanitizer second = OperationLogSanitizer.forKey(key((byte) 2));
        try {
            String reference = first.reference("license");
            assertEquals(reference, first.reference("license"));
            assertNotEquals(reference, first.reference("other"));
            assertNotEquals(reference, second.reference("license"));
            assertTrue(reference.matches("ref:v1:[0-9a-f]{64}"));
        } finally {
            first.close();
            second.close();
        }
        assertThrows(IllegalStateException.class, () -> first.reference("license"));
    }

    @Test
    void rejectsKeysWithInsufficientEntropyCapacity() {
        assertThrows(
                IllegalArgumentException.class,
                () -> OperationLogSanitizer.forKey(new byte[31]));
    }

    @Test
    void oversizedDetailsRemainBoundedAndValidJson() {
        String oversized = "payload-".repeat(1_000);
        String detail;
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key((byte) 3))) {
            detail = sanitizer.serialize(Map.of("description", oversized));
        }

        JsonObject parsed = JsonParser.parseString(detail).getAsJsonObject();
        assertTrue(parsed.get("truncated").getAsBoolean());
        assertTrue(parsed.get("originalLength").getAsInt() > 2_000);
        assertTrue(parsed.get("detailDigest").getAsString()
                .matches("ref:v1:[0-9a-f]{64}"));
        assertFalse(detail.contains(oversized));
        assertTrue(detail.length() < 2_000);
    }

    private static byte[] key(byte value) {
        byte[] key = new byte[32];
        Arrays.fill(key, value);
        return key;
    }
}

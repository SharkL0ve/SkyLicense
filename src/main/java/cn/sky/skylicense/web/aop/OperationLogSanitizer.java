package cn.sky.skylicense.web.aop;

import cn.sky.skylicense.security.SecretSource;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Serializes audit arguments without retaining credentials or reusable identifiers. */
public final class OperationLogSanitizer implements AutoCloseable {
    public static final String HMAC_KEY_ENV = "SKYLICENSE_OPERATION_LOG_HMAC_KEY";
    private static final byte[] DOMAIN =
            "SkyLicense operation audit reference v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final Set<String> SECRET_FIELDS = Set.of(
            "password", "oldpassword", "newpassword", "secret", "token", "csrftoken",
            "authorization", "cookie", "challengetoken", "factor", "totpcode",
            "recoverycode", "recoverycodes", "manualsecret", "otpauthuri");
    private static final Set<String> IDENTIFIER_FIELDS = Set.of(
            "code", "codes", "hwid", "ip", "qq", "value", "username");
    private static final Gson GSON = new Gson();
    private static final int MAX_DETAIL_BYTES = 2_000;
    private static final int HMAC_KEY_BYTES = 32;
    private static final String REFERENCE_PREFIX = "ref:v1:";

    private final byte[] hmacKey;
    private boolean closed;

    private OperationLogSanitizer(byte[] key) {
        if (key == null || key.length < HMAC_KEY_BYTES) {
            throw new IllegalArgumentException("operation audit HMAC key must contain at least 32 bytes");
        }
        this.hmacKey = key.clone();
    }

    /** Creates the production sanitizer from the isolated environment secret. */
    public static OperationLogSanitizer fromEnvironment() {
        String encoded = SecretSource.readRequired(HMAC_KEY_ENV, HMAC_KEY_BYTES * 2);
        byte[] key = decodeEnvironmentKey(encoded);
        try {
            return new OperationLogSanitizer(key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /** Test and dependency-injection factory; production code should use {@link #fromEnvironment()}. */
    public static OperationLogSanitizer forKey(byte[] key) {
        return new OperationLogSanitizer(key);
    }

    /** Validates the production environment without retaining a second key copy. */
    public static void validateEnvironment() {
        byte[] key = decodeEnvironmentKey(
                SecretSource.readRequired(HMAC_KEY_ENV, HMAC_KEY_BYTES * 2));
        Arrays.fill(key, (byte) 0);
    }

    public synchronized String serialize(Map<String, Object> detail) {
        ensureOpen();
        JsonElement tree = GSON.toJsonTree(detail);
        redact(tree, "");
        String json = GSON.toJson(tree);
        int originalLength = json.getBytes(StandardCharsets.UTF_8).length;
        if (originalLength > MAX_DETAIL_BYTES) {
            JsonObject truncated = new JsonObject();
            truncated.addProperty("truncated", true);
            truncated.addProperty("detailDigest", reference(json));
            truncated.addProperty("originalLength", originalLength);
            return GSON.toJson(truncated);
        }
        return json;
    }

    public synchronized String reference(String value) {
        ensureOpen();
        if (value == null || value.isEmpty()) {
            return value;
        }
        return REFERENCE_PREFIX + hmac(value);
    }

    /**
     * Computes a domain-separated MAC for audit records and checkpoints. The
     * operation-log service supplies a length-prefixed canonical payload; this
     * method deliberately shares the installation key with references while
     * keeping the cryptographic domains independent.
     */
    public synchronized String auditMac(String domain, byte[] payload) {
        ensureOpen();
        if (domain == null || domain.isEmpty() || payload == null) {
            throw new IllegalArgumentException("audit MAC domain and payload are required");
        }
        byte[] domainBytes = domain.getBytes(StandardCharsets.US_ASCII);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            mac.update(domainBytes);
            mac.update((byte) 0);
            byte[] digest = mac.doFinal(payload);
            try {
                return toLowerHex(digest);
            } finally {
                Arrays.fill(digest, (byte) 0);
            }
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", error);
        } finally {
            Arrays.fill(domainBytes, (byte) 0);
        }
    }

    public synchronized boolean matchesAuditMac(
            String domain,
            byte[] payload,
            String expected
    ) {
        if (expected == null || expected.length() != 64) {
            return false;
        }
        String actual = auditMac(domain, payload);
        return MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.US_ASCII),
                expected.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            Arrays.fill(hmacKey, (byte) 0);
            closed = true;
        }
    }

    private void redact(JsonElement element, String fieldName) {
        if (element == null || element.isJsonNull()) {
            return;
        }
        String normalized = fieldName == null ? "" : fieldName.toLowerCase(Locale.ROOT);
        if (element.isJsonObject()) {
            JsonObject object = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
                String name = entry.getKey();
                String lowerName = name.toLowerCase(Locale.ROOT);
                if (SECRET_FIELDS.contains(lowerName)) {
                    entry.setValue(new JsonPrimitive("***"));
                } else if (IDENTIFIER_FIELDS.contains(lowerName)) {
                    entry.setValue(redactIdentifier(entry.getValue()));
                } else {
                    redact(entry.getValue(), name);
                }
            }
        } else if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            for (JsonElement child : array) {
                redact(child, normalized);
            }
        }
    }

    private JsonElement redactIdentifier(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return element;
        }
        if (element.isJsonArray()) {
            JsonArray result = new JsonArray();
            for (JsonElement child : element.getAsJsonArray()) {
                result.add(redactIdentifier(child));
            }
            return result;
        }
        if (element.isJsonPrimitive()) {
            JsonPrimitive primitive = element.getAsJsonPrimitive();
            if (primitive.isString()) {
                return new JsonPrimitive(reference(primitive.getAsString()));
            }
        }
        return new JsonPrimitive(reference(GSON.toJson(element)));
    }

    private String hmac(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            mac.update(DOMAIN);
            byte[] digest = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            try {
                return toLowerHex(digest);
            } finally {
                Arrays.fill(digest, (byte) 0);
            }
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", error);
        }
    }

    private static String toLowerHex(byte[] value) {
        StringBuilder hex = new StringBuilder(value.length * 2);
        for (byte item : value) {
            hex.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            hex.append(Character.forDigit(item & 0x0f, 16));
        }
        return hex.toString();
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("operation log sanitizer is closed");
        }
    }

    private static byte[] decodeEnvironmentKey(String encoded) {
        if (encoded == null || encoded.length() != HMAC_KEY_BYTES * 2
                || !encoded.chars().allMatch(character ->
                character <= 0x7f && Character.digit(character, 16) >= 0)) {
            throw new IllegalStateException(
                    HMAC_KEY_ENV + " must be exactly 64 hexadecimal characters");
        }
        byte[] key = new byte[HMAC_KEY_BYTES];
        for (int index = 0; index < key.length; index++) {
            int high = Character.digit(encoded.charAt(index * 2), 16);
            int low = Character.digit(encoded.charAt(index * 2 + 1), 16);
            key[index] = (byte) ((high << 4) | low);
        }
        if (Arrays.equals(key, new byte[HMAC_KEY_BYTES])) {
            Arrays.fill(key, (byte) 0);
            throw new IllegalStateException(HMAC_KEY_ENV + " must not be all zero");
        }
        return key;
    }
}

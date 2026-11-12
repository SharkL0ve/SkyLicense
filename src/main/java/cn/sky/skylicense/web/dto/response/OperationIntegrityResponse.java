package cn.sky.skylicense.web.dto.response;

/** Minimal administrator-facing result for a full retained audit-chain check. */
public record OperationIntegrityResponse(
        boolean verified,
        long rowCount,
        long anchorId,
        long headId,
        long checkedAtMillis,
        String status
) {
    public static OperationIntegrityResponse failed(long checkedAtMillis) {
        return new OperationIntegrityResponse(
                false, 0L, 0L, 0L, checkedAtMillis, "AUDIT_INTEGRITY_FAILED");
    }
}

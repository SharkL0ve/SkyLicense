package cn.sky.skylicense.web.dto.response;

import cn.sky.skylicense.web.entity.OperationLog;

/** Public audit-event projection that deliberately omits internal MAC material. */
public record OperationLogView(
        long id,
        String eventId,
        long userId,
        String username,
        String action,
        String target,
        String detail,
        String ip,
        String timestamp,
        String outcome,
        long occurredAtMillis,
        Long completedAtMillis
) {
    public static OperationLogView from(OperationLog log) {
        return new OperationLogView(
                log.getId(),
                log.getEventId(),
                log.getUserId(),
                log.getUsername(),
                log.getAction(),
                log.getTarget(),
                log.getDetail(),
                log.getIp(),
                log.getTimestamp(),
                log.getOutcome(),
                log.getOccurredAtMillis(),
                log.getCompletedAtMillis());
    }
}

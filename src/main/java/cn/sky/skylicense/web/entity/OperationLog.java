package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@DatabaseTable(tableName = "operation_log")
@NoArgsConstructor
@AllArgsConstructor
public class OperationLog {

    @DatabaseField(generatedId = true)
    private long id;

    @DatabaseField(columnName = "user_id", index = true)
    private long userId;

    @DatabaseField(columnName = "username")
    private String username;

    @DatabaseField(columnName = "action")
    private String action;

    @DatabaseField(columnName = "target")
    private String target;

    @DatabaseField(columnName = "detail", width = 4096)
    private String detail;

    @DatabaseField(columnName = "ip")
    private String ip;

    @DatabaseField(columnName = "timestamp", index = true)
    private String timestamp;

    /** Stable correlation id for the whole audit event. */
    @DatabaseField(columnName = "event_id", index = true)
    private String eventId;

    /** ATTEMPT, SUCCESS, REJECTED, or LEGACY for migrated historical rows. */
    @DatabaseField(columnName = "outcome", index = true)
    private String outcome;

    /** Authoritative event start time in UTC epoch milliseconds. */
    @DatabaseField(columnName = "occurred_at_ms")
    private long occurredAtMillis;

    /** Completion time in UTC epoch milliseconds; null while ATTEMPT is open. */
    @DatabaseField(columnName = "completed_at_ms")
    private Long completedAtMillis;

    /** Chain predecessor MAC. It is immutable after insertion. */
    @DatabaseField(columnName = "chain_previous_mac", width = 64)
    private String chainPreviousMac;

    /** MAC over immutable chain fields. */
    @DatabaseField(columnName = "chain_mac", width = 64)
    private String chainMac;

    /** MAC over the complete current row, including mutable completion fields. */
    @DatabaseField(columnName = "integrity_mac", width = 64)
    private String integrityMac;
}

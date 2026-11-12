package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Authenticated checkpoint for the append-only operation-log chain. */
@Builder
@Data
@DatabaseTable(tableName = "operation_log_state")
@NoArgsConstructor
@AllArgsConstructor
public class OperationLogState {

    @DatabaseField(columnName = "singleton_id", id = true)
    private int singletonId;

    /** Last pruned row id, or zero for the genesis checkpoint. */
    @DatabaseField(columnName = "anchor_id")
    private long anchorId;

    /** Chain MAC of the anchor row, or the genesis MAC. */
    @DatabaseField(columnName = "anchor_mac", canBeNull = false, width = 64)
    private String anchorMac;

    /** Current last retained row id. */
    @DatabaseField(columnName = "head_id")
    private long headId;

    /** Chain MAC of the current last retained row. */
    @DatabaseField(columnName = "head_mac", canBeNull = false, width = 64)
    private String headMac;

    /** Number of retained operation-log rows. */
    @DatabaseField(columnName = "row_count")
    private long rowCount;

    /** MAC over every checkpoint field above. */
    @DatabaseField(columnName = "state_mac", canBeNull = false, width = 64)
    private String stateMac;

    @DatabaseField(columnName = "updated_at_ms")
    private long updatedAtMillis;
}

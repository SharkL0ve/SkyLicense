package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@DatabaseTable(tableName = "ban_record")
@NoArgsConstructor
@AllArgsConstructor
public class BanRecord {

    @DatabaseField(generatedId = true)
    private long id;

    @DatabaseField(columnName = "type", canBeNull = false, index = true)
    private String type; // IP, HWID, QQ, CODE

    @DatabaseField(columnName = "value", canBeNull = false)
    private String value;

    @DatabaseField(columnName = "reason")
    private String reason;

    @DatabaseField(columnName = "operator_id")
    private long operatorId;

    @DatabaseField(columnName = "program_id")
    private long programId;

    @DatabaseField(columnName = "create_time")
    private String createTime;

    @DatabaseField(columnName = "expiration_date")
    private String expirationDate; // null=永久封禁

    @DatabaseField(columnName = "status")
    private int status; // 1=生效, 0=暂停
}

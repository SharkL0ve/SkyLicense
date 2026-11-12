package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@DatabaseTable(tableName = "auth_log")
@NoArgsConstructor
@AllArgsConstructor
public class AuthLog {

    @DatabaseField(generatedId = true)
    private long id;

    @DatabaseField(columnName = "license_id", index = true)
    private long licenseId;

    @DatabaseField(columnName = "code", index = true)
    private String code;

    @DatabaseField(columnName = "ip")
    private String ip;

    @DatabaseField(columnName = "hwid")
    private String hwid;

    @DatabaseField(columnName = "result")
    private String result;

    @DatabaseField(columnName = "timestamp", index = true)
    private String timestamp;

    @DatabaseField(columnName = "program_id", index = true)
    private long programId;

    @DatabaseField(columnName = "user_id", index = true)
    private long userId;
}

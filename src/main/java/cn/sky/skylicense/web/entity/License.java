package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Builder
@Data
@DatabaseTable(tableName = "license")
@NoArgsConstructor
@AllArgsConstructor
public class License {

    @DatabaseField(generatedId = true)
    private long id;

    @DatabaseField(columnName = "code", unique = true, canBeNull = false, index = true)
    private String code;

    @DatabaseField(columnName = "program_id", canBeNull = false, index = true)
    private long programId;

    @DatabaseField(columnName = "user_id", canBeNull = false, index = true)
    private long userId;

    @DatabaseField(columnName = "qq")
    private String qq;

    @DatabaseField(columnName = "bindable_ips")
    private int bindableIps;

    @DatabaseField(columnName = "bindable_hwids")
    private int bindableHwids;

    @DatabaseField(columnName = "status")
    private int status; // 1=正常, 0=封禁

    @DatabaseField(columnName = "ips", width = 4096)
    private String ips;

    @DatabaseField(columnName = "hwids", width = 4096)
    private String hwids;

    @DatabaseField(columnName = "create_time")
    private String createTime;

    @DatabaseField(columnName = "last_auth_time")
    private String lastAuthTime;

    @DatabaseField(columnName = "ban_reason")
    private String banReason;

    @DatabaseField(columnName = "notes")
    private String notes;

    @DatabaseField(columnName = "expiration_date")
    private String expirationDate;

    @DatabaseField(columnName = "max_daily_auth")
    private int maxDailyAuth; // 0=无限制

    @DatabaseField(columnName = "last_modified_time")
    private String lastModifiedTime;

    public List<String> parseIps() {
        List<String> list = new ArrayList<>();
        if (ips != null && !ips.isEmpty()) {
            for (String item : ips.split(",")) {
                list.add(item.trim());
            }
        }
        return list;
    }

    public List<String> parseHwids() {
        List<String> list = new ArrayList<>();
        if (hwids != null && !hwids.isEmpty()) {
            for (String item : hwids.split(",")) {
                list.add(item.trim());
            }
        }
        return list;
    }

    public static String joinList(List<String> values) {
        return String.join(",", values);
    }
}

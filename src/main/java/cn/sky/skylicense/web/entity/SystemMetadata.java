package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@DatabaseTable(tableName = "system_metadata")
@NoArgsConstructor
@AllArgsConstructor
public class SystemMetadata {
    @DatabaseField(id = true, columnName = "meta_key", width = 128)
    private String key;

    @DatabaseField(columnName = "meta_value", width = 8192, canBeNull = false)
    private String value;
}

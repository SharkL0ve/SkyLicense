package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@DatabaseTable(tableName = "program")
@NoArgsConstructor
@AllArgsConstructor
public class Program {

    @DatabaseField(generatedId = true)
    private long id;

    @DatabaseField(columnName = "user_id", canBeNull = false, index = true)
    private long userId;

    @DatabaseField(columnName = "name", canBeNull = false)
    private String name;

    @DatabaseField(columnName = "description")
    private String description;

    @DatabaseField(columnName = "status")
    private int status; // 1=正常, 0=禁用

    @DatabaseField(columnName = "create_time")
    private String createTime;
}

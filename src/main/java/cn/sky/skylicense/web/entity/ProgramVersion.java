package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@DatabaseTable(tableName = "program_version")
@NoArgsConstructor
@AllArgsConstructor
public class ProgramVersion {

    @DatabaseField(generatedId = true)
    private long id;

    @DatabaseField(columnName = "program_id", canBeNull = false, index = true)
    private long programId;

    @DatabaseField(columnName = "version", canBeNull = false)
    private String version;

    @DatabaseField(columnName = "file_name")
    private String fileName;

    @DatabaseField(columnName = "file_path")
    private String filePath;

    @DatabaseField(columnName = "entry_class")
    private String entryClass;

    @DatabaseField(columnName = "entry_point")
    private String entryPoint;

    @DatabaseField(columnName = "upload_time")
    private String uploadTime;

    @DatabaseField(columnName = "release_notes", width = 4096)
    private String releaseNotes;
}

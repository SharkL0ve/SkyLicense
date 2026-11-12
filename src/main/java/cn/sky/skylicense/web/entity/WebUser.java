package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@DatabaseTable(tableName = "web_user")
@NoArgsConstructor
@AllArgsConstructor
public class WebUser {

    @DatabaseField(generatedId = true)
    private long id;

    @DatabaseField(columnName = "username", unique = true, canBeNull = false)
    private String username;

    @DatabaseField(columnName = "password", canBeNull = false)
    private String password;

    @DatabaseField(columnName = "role", canBeNull = false)
    private String role; // USER, ADMIN

    @DatabaseField(columnName = "max_programs")
    private int maxPrograms;

    @DatabaseField(columnName = "status")
    private int status; // 1=正常, 0=禁用

    @DatabaseField(columnName = "create_time")
    private String createTime;

    @DatabaseField(columnName = "last_login_time")
    private String lastLoginTime;

    @DatabaseField(columnName = "email")
    private String email;

    @DatabaseField(columnName = "mfa_enabled", canBeNull = false, defaultValue = "0")
    private int mfaEnabled;

    @JsonIgnore
    @DatabaseField(columnName = "mfa_secret", width = 4096)
    private String mfaSecret;

    @JsonIgnore
    @DatabaseField(columnName = "mfa_pending_secret", width = 4096)
    private String mfaPendingSecret;

    @JsonIgnore
    @DatabaseField(columnName = "mfa_pending_created_at")
    private Long mfaPendingCreatedAt;

    @JsonIgnore
    @DatabaseField(columnName = "mfa_recovery_hashes", width = 4096)
    private String mfaRecoveryHashes;

    @JsonIgnore
    @DatabaseField(columnName = "mfa_last_time_step", canBeNull = false, defaultValue = "0")
    private long mfaLastTimeStep;

    @DatabaseField(columnName = "mfa_updated_at")
    private Long mfaUpdatedAt;
}

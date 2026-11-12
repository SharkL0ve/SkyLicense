package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Persistent login-failure state keyed by a domain-separated HMAC reference. */
@Builder
@Data
@DatabaseTable(tableName = "web_login_attempt")
@NoArgsConstructor
@AllArgsConstructor
public class WebLoginAttempt {
    @DatabaseField(id = true, columnName = "attempt_key", width = 64)
    private String attemptKey;

    @DatabaseField(columnName = "scope", canBeNull = false, width = 16)
    private String scope;

    @DatabaseField(columnName = "failure_count", canBeNull = false)
    private int failureCount;

    @DatabaseField(columnName = "window_started_at", canBeNull = false)
    private long windowStartedAt;

    @DatabaseField(columnName = "locked_until", canBeNull = false)
    private long lockedUntil;

    @DatabaseField(columnName = "updated_at", canBeNull = false, index = true)
    private long updatedAt;
}

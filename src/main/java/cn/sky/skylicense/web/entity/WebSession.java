package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Persistent allow-list entry for an HttpOnly browser session. */
@Builder
@Data
@DatabaseTable(tableName = "web_session")
@NoArgsConstructor
@AllArgsConstructor
public class WebSession {
    @DatabaseField(id = true, columnName = "token_digest", width = 43)
    private String tokenDigest;

    @DatabaseField(columnName = "user_id", canBeNull = false, index = true)
    private long userId;

    @DatabaseField(columnName = "csrf_token", canBeNull = false, width = 43)
    private String csrfToken;

    @DatabaseField(columnName = "expires_at", canBeNull = false, index = true)
    private long expiresAt;

    @DatabaseField(columnName = "created_at", canBeNull = false)
    private long createdAt;
}

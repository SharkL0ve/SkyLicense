package cn.sky.skylicense.web.entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Short-lived, digest-only login challenge issued after password verification. */
@Builder
@Data
@DatabaseTable(tableName = "web_mfa_challenge")
@NoArgsConstructor
@AllArgsConstructor
public class WebMfaChallenge {
    @DatabaseField(id = true, columnName = "token_digest", width = 43)
    private String tokenDigest;

    @DatabaseField(columnName = "user_id", canBeNull = false, index = true)
    private long userId;

    @DatabaseField(columnName = "account_reference", canBeNull = false, width = 64)
    private String accountReference;

    @DatabaseField(columnName = "address_reference", canBeNull = false, width = 64)
    private String addressReference;

    @DatabaseField(columnName = "expires_at", canBeNull = false, index = true)
    private long expiresAt;

    @DatabaseField(columnName = "remaining_attempts", canBeNull = false)
    private int remainingAttempts;

    @DatabaseField(columnName = "created_at", canBeNull = false)
    private long createdAt;
}

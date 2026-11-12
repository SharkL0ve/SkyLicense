package cn.sky.skylicense.web.security;

import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.stmt.SelectArg;

import java.sql.SQLException;
import java.util.Locale;
import java.util.regex.Pattern;

/** Canonical username handling shared by account management and login. */
public final class UsernamePolicy {
    private static final Pattern NEW_USERNAME_PATTERN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._\\-]{2,63}");

    private UsernamePolicy() {
    }

    public static String normalizeForMutation(String value) {
        String normalized = normalizeForLogin(value);
        if (normalized == null || !NEW_USERNAME_PATTERN.matcher(normalized).matches()) {
            throw new BizException(
                    "用户名必须为3-64位，并且只能包含字母、数字、点、下划线和连字符");
        }
        return normalized;
    }

    /** Keeps legacy names readable while rejecting blank, oversized, or control-bearing input. */
    public static String normalizeForLogin(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.isEmpty() || normalized.length() > 64) {
            return null;
        }
        for (int index = 0; index < normalized.length(); index++) {
            if (Character.isISOControl(normalized.charAt(index))) {
                return null;
            }
        }
        return normalized;
    }

    public static String accountKey(String normalizedUsername) {
        return normalizedUsername == null
                ? "<invalid>"
                : normalizedUsername.toLowerCase(Locale.ROOT);
    }

    public static WebUser findCaseInsensitive(
            Dao<WebUser, Long> dao,
            String normalizedUsername
    ) throws SQLException {
        if (normalizedUsername == null) {
            return null;
        }
        return dao.queryBuilder().where().raw(
                "username = ? COLLATE NOCASE",
                new SelectArg(SqlType.STRING, normalizedUsername)).queryForFirst();
    }
}

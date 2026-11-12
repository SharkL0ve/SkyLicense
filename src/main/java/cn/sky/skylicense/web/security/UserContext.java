package cn.sky.skylicense.web.security;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserContext {

    private static final ThreadLocal<UserContext> CONTEXT = new ThreadLocal<>();

    private long userId;
    private String username;
    private String role;
    private String csrfToken;
    private boolean mfaEnabled;

    public UserContext(long userId, String username, String role, String csrfToken) {
        this(userId, username, role, csrfToken, false);
    }

    public static void set(UserContext context) {
        CONTEXT.set(context);
    }

    public static UserContext get() {
        return CONTEXT.get();
    }

    public static void clear() {
        CONTEXT.remove();
    }

    public boolean isAdmin() {
        return "ADMIN".equals(role);
    }
}

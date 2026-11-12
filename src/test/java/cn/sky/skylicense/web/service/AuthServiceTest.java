package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.PasswordUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.request.LoginRequest;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.WebSessionSecurity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServiceTest {
    private static final String PASSWORD = "Strong#Password123";

    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private WebUser user;

    @BeforeEach
    void setUp() throws Exception {
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("auth.db").toString());
        user = WebUser.builder()
                .username("admin")
                .password(PasswordUtil.hashPassword(PASSWORD))
                .role("ADMIN")
                .maxPrograms(10)
                .status(1)
                .createTime("2026-01-01-00:00")
                .build();
        accessor.getUserDao().create(user);
    }

    @AfterEach
    void tearDown() {
        if (accessor != null) {
            accessor.close();
        }
    }

    @Test
    void loginPersistsOpaqueSessionAndLogoutRevokesIt() throws Exception {
        SessionService sessions = new SessionService(accessor);
        AuthService service = new AuthService(accessor, sessions);

        SessionService.SessionToken session = service.login(request(), "127.0.0.1");

        assertTrue(WebSessionSecurity.isValidOpaqueToken(session.token()));
        assertTrue(WebSessionSecurity.isValidOpaqueToken(session.csrfToken()));
        assertTrue(sessions.isActive(session.token()));
        assertNotNull(accessor.getUserDao().queryForId(user.getId()).getLastLoginTime());

        service.logout(session.token());
        assertFalse(sessions.isActive(session.token()));
    }

    @Test
    void loginTrimsUsernameAndMatchesItCaseInsensitively() throws Exception {
        SessionService sessions = new SessionService(accessor);
        AuthService service = new AuthService(accessor, sessions);
        LoginRequest request = request();
        request.setUsername("  AdMiN  ");

        SessionService.SessionToken session = service.login(request, "127.0.0.1");

        assertTrue(sessions.isActive(session.token()));
    }

    @Test
    void sessionCapacityFailureRollsBackLastLoginUpdate() throws Exception {
        SessionService sessions = new SessionService(accessor, 1, 1);
        WebUser capacityOwner = WebUser.builder()
                .username("capacity-owner")
                .password(PasswordUtil.hashPassword(PASSWORD))
                .role("USER")
                .maxPrograms(1)
                .status(1)
                .createTime("2026-01-01-00:00")
                .build();
        accessor.getUserDao().create(capacityOwner);
        sessions.persistSession(capacityOwner.getId(), new SessionService.SessionToken(
                "T".repeat(43), "C".repeat(43), 3_600));
        AuthService service = new AuthService(accessor, sessions);

        assertThrows(BizException.class, () -> service.login(request(), "127.0.0.1"));

        assertNull(accessor.getUserDao().queryForId(user.getId()).getLastLoginTime());
        assertTrue(sessions.isActive("T".repeat(43)));
    }

    private static LoginRequest request() {
        LoginRequest request = new LoginRequest();
        request.setUsername("admin");
        request.setPassword(PASSWORD);
        return request;
    }
}

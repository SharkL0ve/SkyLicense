package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.request.CreateUserRequest;
import cn.sky.skylicense.web.dto.request.UpdateUserRequest;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UserServiceTest {
    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private UserService service;
    private WebUser user;

    @BeforeEach
    void setUp() throws Exception {
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("users.db").toString());
        service = new UserService(accessor, new DataCascadeService(accessor),
                new SessionService(accessor));
        user = WebUser.builder()
                .username("original")
                .password("stored-password-hash")
                .role("ADMIN")
                .maxPrograms(37)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
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
    void partialUpdatePreservesOmittedRoleAndProgramLimit() throws Exception {
        UpdateUserRequest request = new UpdateUserRequest();
        request.setUsername("renamed");

        WebUser updated = service.updateUser(user.getId(), request);

        assertEquals("renamed", updated.getUsername());
        assertEquals("ADMIN", updated.getRole());
        assertEquals(37, updated.getMaxPrograms());
    }

    @Test
    void createTrimsSafeUsernameAndRejectsCaseInsensitiveDuplicates() throws Exception {
        CreateUserRequest request = createRequest("  Alice.User  ");

        WebUser created = service.createUser(request);

        assertEquals("Alice.User", created.getUsername());
        assertThrows(BizException.class, () -> service.createUser(createRequest("alice.user")));
        assertThrows(BizException.class, () -> service.createUser(createRequest("unsafe user")));
        assertEquals(2, accessor.getUserDao().countOf());
    }

    @Test
    void updateRejectsCaseInsensitiveConflictAndNormalizesCaseOnlyRename() throws Exception {
        WebUser other = service.createUser(createRequest("Another.User"));
        UpdateUserRequest conflict = new UpdateUserRequest();
        conflict.setUsername(" another.user ");

        assertThrows(BizException.class, () -> service.updateUser(user.getId(), conflict));

        UpdateUserRequest caseOnly = new UpdateUserRequest();
        caseOnly.setUsername(" ORIGINAL ");
        WebUser updated = service.updateUser(user.getId(), caseOnly);
        assertEquals("ORIGINAL", updated.getUsername());
        assertEquals("Another.User", accessor.getUserDao().queryForId(other.getId()).getUsername());
    }

    @Test
    void userStatusAcceptsOnlyBinaryValues() throws Exception {
        assertThrows(
                cn.sky.skylicense.web.exception.BizException.class,
                () -> service.toggleStatus(user.getId(), -1));
        assertEquals(1, accessor.getUserDao().queryForId(user.getId()).getStatus());
    }

    @Test
    void lastActiveAdministratorCannotBeDemotedOrDisabled() throws Exception {
        UpdateUserRequest demote = new UpdateUserRequest();
        demote.setRole("USER");

        assertThrows(
                cn.sky.skylicense.web.exception.BizException.class,
                () -> service.updateUser(user.getId(), demote));
        assertThrows(
                cn.sky.skylicense.web.exception.BizException.class,
                () -> service.toggleStatus(user.getId(), 0));

        WebUser unchanged = accessor.getUserDao().queryForId(user.getId());
        assertEquals("ADMIN", unchanged.getRole());
        assertEquals(1, unchanged.getStatus());
    }

    private static CreateUserRequest createRequest(String username) {
        CreateUserRequest request = new CreateUserRequest();
        request.setUsername(username);
        request.setPassword("Strong#Password123");
        request.setRole("USER");
        request.setMaxPrograms(5);
        return request;
    }
}

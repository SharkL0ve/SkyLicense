package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.PasswordUtil;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.dto.request.CreateUserRequest;
import cn.sky.skylicense.web.dto.request.UpdateUserRequest;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.security.UsernamePolicy;
import com.j256.ormlite.dao.Dao;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
public class UserService {

    private final WebDataAccessor accessor;
    private final DataCascadeService dataCascadeService;
    private final SessionService sessionService;

    public UserService(
            WebDataAccessor accessor,
            DataCascadeService dataCascadeService,
            SessionService sessionService
    ) {
        this.accessor = accessor;
        this.dataCascadeService = dataCascadeService;
        this.sessionService = sessionService;
    }

    @SneakyThrows
    public synchronized WebUser createUser(CreateUserRequest request) {
        Dao<WebUser, Long> dao = accessor.getUserDao();
        requireStrongPassword(request.getPassword());
        requireRole(request.getRole());
        String username = UsernamePolicy.normalizeForMutation(request.getUsername());

        WebUser existing = UsernamePolicy.findCaseInsensitive(dao, username);
        if (existing != null) {
            throw new BizException("用户名已存在");
        }

        WebUser user = WebUser.builder()
                .username(username)
                .password(PasswordUtil.hashPassword(request.getPassword()))
                .role(request.getRole())
                .maxPrograms(request.getMaxPrograms())
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();

        dao.create(user);
        user.setPassword(null);
        return user;
    }

    @SneakyThrows
    public PageResult<WebUser> listUsers(int page, int pageSize) {
        Dao<WebUser, Long> dao = accessor.getUserDao();
        long total = dao.countOf();
        List<WebUser> users = dao.queryBuilder()
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .orderBy("id", true)
                .query();
        users.forEach(u -> u.setPassword(null));
        return PageResult.of(users, total, page, pageSize);
    }

    @SneakyThrows
    public WebUser getUser(long id) {
        WebUser user = accessor.getUserDao().queryForId(id);
        if (user == null) {
            throw BizException.notFound("用户不存在");
        }
        user.setPassword(null);
        return user;
    }

    @SneakyThrows
    public synchronized WebUser updateUser(long id, UpdateUserRequest request) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            return updateUserLocked(id, request);
        }
    }

    @SneakyThrows
    private WebUser updateUserLocked(long id, UpdateUserRequest request) {
        Dao<WebUser, Long> dao = accessor.getUserDao();
        WebUser user = dao.queryForId(id);
        if (user == null) {
            throw BizException.notFound("用户不存在");
        }

        boolean identityChanged = false;
        boolean wasActiveAdmin = "ADMIN".equals(user.getRole()) && user.getStatus() == 1;
        if (request.getUsername() != null) {
            String username = UsernamePolicy.normalizeForMutation(request.getUsername());
            if (!Objects.equals(user.getUsername(), username)) {
                WebUser conflict = UsernamePolicy.findCaseInsensitive(dao, username);
                if (conflict != null && conflict.getId() != id) {
                    throw new BizException("用户名已存在");
                }
                user.setUsername(username);
                identityChanged = true;
            }
        }
        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            requireStrongPassword(request.getPassword());
            user.setPassword(PasswordUtil.hashPassword(request.getPassword()));
            identityChanged = true;
        }
        if (request.getRole() != null) {
            requireRole(request.getRole());
            if (!Objects.equals(user.getRole(), request.getRole())) {
                user.setRole(request.getRole());
                identityChanged = true;
            }
        }
        if (request.getMaxPrograms() != null) {
            user.setMaxPrograms(request.getMaxPrograms());
        }

        if (identityChanged) {
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                if (wasActiveAdmin && !"ADMIN".equals(user.getRole())) {
                    requireAnotherActiveAdmin(id);
                }
                dao.update(user);
                sessionService.revokeUser(id);
                return null;
            });
        } else {
            dao.update(user);
        }
        user.setPassword(null);
        return user;
    }

    @SneakyThrows
    public synchronized void deleteUser(long id) {
        UserContext ctx = UserContext.get();
        if (ctx.getUserId() == id) {
            throw new BizException("不能删除自己");
        }
        Dao<WebUser, Long> dao = accessor.getUserDao();
        WebUser user = dao.queryForId(id);
        if (user == null) {
            throw BizException.notFound("用户不存在");
        }
        if ("ADMIN".equals(user.getRole()) && user.getStatus() == 1) {
            requireAnotherActiveAdmin(id);
        }

        dataCascadeService.deleteUser(user);
    }

    @SneakyThrows
    public synchronized void toggleStatus(long id, int status) {
        requireStatus(status);
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<WebUser, Long> dao = accessor.getUserDao();
            WebUser user = dao.queryForId(id);
            if (user == null) {
                throw BizException.notFound("用户不存在");
            }
            user.setStatus(status);
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                if (status == 0 && "ADMIN".equals(user.getRole())) {
                    requireAnotherActiveAdmin(id);
                }
                dao.update(user);
                sessionService.revokeUser(id);
                return null;
            });
        }
    }

    private static void requireStrongPassword(String password) {
        if (!PasswordUtil.meetsStrengthRequirements(password)) {
            throw new BizException(
                    "Password must contain 12-128 characters from at least three character classes");
        }
    }

    private static void requireRole(String role) {
        if (!"USER".equals(role) && !"ADMIN".equals(role)) {
            throw new BizException("角色只能是 USER 或 ADMIN");
        }
    }

    private static void requireStatus(int status) {
        if (status != 0 && status != 1) {
            throw new BizException("状态只能是0或1");
        }
    }

    private void requireAnotherActiveAdmin(long excludedUserId) throws java.sql.SQLException {
        long remaining = accessor.getUserDao().queryBuilder().where()
                .eq("role", "ADMIN")
                .and().eq("status", 1)
                .and().ne("id", excludedUserId)
                .countOf();
        if (remaining == 0) {
            throw new BizException("必须至少保留一个已启用的管理员账号");
        }
    }
}

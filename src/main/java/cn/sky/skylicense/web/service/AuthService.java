package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.PasswordUtil;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.dto.request.ChangePasswordRequest;
import cn.sky.skylicense.web.dto.request.LoginRequest;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import cn.sky.skylicense.web.security.UsernamePolicy;
import com.j256.ormlite.dao.Dao;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final WebDataAccessor accessor;
    private final SessionService sessionService;
    private final MfaService mfaService;
    private final LoginRateLimiter rateLimiter;

    @Autowired
    public AuthService(
            WebDataAccessor accessor,
            SessionService sessionService,
            MfaService mfaService,
            LoginRateLimiter rateLimiter
    ) {
        this.accessor = accessor;
        this.sessionService = sessionService;
        this.mfaService = mfaService;
        this.rateLimiter = rateLimiter;
    }

    /** Unit-test compatibility constructor; production always injects persistent throttling. */
    public AuthService(WebDataAccessor accessor, SessionService sessionService) {
        this.accessor = accessor;
        this.sessionService = sessionService;
        this.mfaService = null;
        this.rateLimiter = new InMemoryLoginRateLimiter();
    }

    @SneakyThrows
    public SessionService.SessionToken login(LoginRequest request, String clientAddress) {
        LoginOutcome outcome = authenticate(request, clientAddress);
        if (outcome.session() == null) {
            throw new BizException(401, "需要完成MFA验证");
        }
        return outcome.session();
    }

    @SneakyThrows
    public LoginOutcome authenticate(LoginRequest request, String clientAddress) {
        String username = UsernamePolicy.normalizeForLogin(request.getUsername());
        String accountKey = UsernamePolicy.accountKey(username);
        String addressKey = normalizeAddress(clientAddress);
        String accountReference = rateLimiter.reference(
                LoginRateLimiter.Scope.ACCOUNT, accountKey);
        String addressReference = rateLimiter.reference(
                LoginRateLimiter.Scope.ADDRESS, addressKey);
        checkRateLimit(accountReference, addressReference);

        if (username == null) {
            recordFailedAttempt(accountReference, addressReference);
            throw new BizException(401, "用户名或密码错误");
        }

        Dao<WebUser, Long> dao = accessor.getUserDao();
        WebUser user = UsernamePolicy.findCaseInsensitive(dao, username);

        if (user == null) {
            recordFailedAttempt(accountReference, addressReference);
            throw new BizException(401, "用户名或密码错误");
        }
        if (user.getStatus() == 0) {
            throw new BizException(403, "账号已被禁用");
        }
        if (!PasswordUtil.verifyPassword(request.getPassword(), user.getPassword())) {
            recordFailedAttempt(accountReference, addressReference);
            throw new BizException(401, "用户名或密码错误");
        }

        boolean passwordRehashRequired = PasswordUtil.needsRehash(user.getPassword());
        if (passwordRehashRequired) {
            user.setPassword(PasswordUtil.hashPassword(request.getPassword()));
        }
        if (user.getMfaEnabled() == 1) {
            if (mfaService == null) {
                throw new BizException(503, "MFA service is unavailable");
            }
            if (passwordRehashRequired) {
                dao.update(user);
            }
            return LoginOutcome.challenge(mfaService.createChallenge(user, addressKey));
        }

        user.setLastLoginTime(TimeUtil.getCurtTime());
        SessionService.SessionToken session = DatabaseTransactions.call(
                accessor.getConnectionSource(), () -> {
                    dao.update(user);
                    return sessionService.createSession(user.getId());
                });
        rateLimiter.clear(LoginRateLimiter.Scope.ACCOUNT, accountReference);
        rateLimiter.clear(LoginRateLimiter.Scope.ADDRESS, addressReference);
        return LoginOutcome.authenticated(session);
    }

    public SessionService.SessionToken verifyMfa(
            String challengeToken,
            String factor,
            String clientAddress
    ) {
        if (mfaService == null) {
            throw new BizException(503, "MFA service is unavailable");
        }
        return mfaService.verifyChallenge(challengeToken, factor, clientAddress);
    }

    public void logout(String token) {
        sessionService.revoke(token);
    }

    @SneakyThrows
    public WebUser getCurrentUser() {
        UserContext ctx = UserContext.get();
        if (ctx == null) {
            throw BizException.unauthorized("未登录");
        }
        WebUser user = accessor.getUserDao().queryForId(ctx.getUserId());
        if (user == null) {
            throw BizException.unauthorized("用户不存在");
        }
        user.setPassword(null);
        return user;
    }

    @SneakyThrows
    public void changePassword(ChangePasswordRequest request) {
        UserContext ctx = UserContext.get();
        if (ctx == null) {
            throw BizException.unauthorized("未登录");
        }

        Dao<WebUser, Long> dao = accessor.getUserDao();
        WebUser user = dao.queryForId(ctx.getUserId());
        if (user == null) {
            throw BizException.unauthorized("用户不存在");
        }

        if (!PasswordUtil.verifyPassword(request.getOldPassword(), user.getPassword())) {
            throw new BizException("旧密码错误");
        }

        // 密码强度校验
        validatePasswordStrength(request.getNewPassword());

        user.setPassword(PasswordUtil.hashPassword(request.getNewPassword()));
        DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
            dao.update(user);
            sessionService.revokeUser(user.getId());
            return null;
        });
    }

    private void validatePasswordStrength(String password) {
        if (!PasswordUtil.meetsStrengthRequirements(password)) {
            throw new BizException(
                    "Password must contain 12-128 characters from at least three character classes");
        }
    }

    private void checkRateLimit(String accountReference, String addressReference) {
        long accountRetry = rateLimiter.retryAfterSeconds(
                LoginRateLimiter.Scope.ACCOUNT,
                accountReference,
                LoginRateLimiter.ACCOUNT_POLICY);
        long addressRetry = rateLimiter.retryAfterSeconds(
                LoginRateLimiter.Scope.ADDRESS,
                addressReference,
                LoginRateLimiter.ADDRESS_POLICY);
        long retryAfter = Math.max(accountRetry, addressRetry);
        if (retryAfter > 0) {
            throw new BizException(429, "Too many login failures; retry after " + retryAfter + " seconds");
        }
    }

    private void recordFailedAttempt(String accountReference, String addressReference) {
        boolean accountRecorded = rateLimiter.recordFailure(
                LoginRateLimiter.Scope.ACCOUNT,
                accountReference,
                LoginRateLimiter.ACCOUNT_POLICY);
        boolean addressRecorded = rateLimiter.recordFailure(
                LoginRateLimiter.Scope.ADDRESS,
                addressReference,
                LoginRateLimiter.ADDRESS_POLICY);
        if (!accountRecorded || !addressRecorded) {
            throw new BizException(429, "Login limiter capacity reached; retry later");
        }
    }

    private static String normalizeAddress(String clientAddress) {
        if (clientAddress == null || clientAddress.isBlank() || clientAddress.length() > 256) {
            return "unknown";
        }
        return clientAddress;
    }

    public record LoginOutcome(
            SessionService.SessionToken session,
            MfaService.LoginChallenge challenge
    ) {
        static LoginOutcome authenticated(SessionService.SessionToken session) {
            return new LoginOutcome(session, null);
        }

        static LoginOutcome challenge(MfaService.LoginChallenge challenge) {
            return new LoginOutcome(null, challenge);
        }

        public boolean mfaRequired() {
            return challenge != null;
        }
    }
}

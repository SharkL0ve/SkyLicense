package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.BanRecord;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.WebUser;
import lombok.SneakyThrows;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

/**
 * Authoritative bridge between the protocol-v4 listener and the Web license model.
 * The hello phase is deliberately read-only; bindings are committed at the
 * server's resource-release boundary, before any client-controlled ACK.
 */
public final class NativeLicenseService {
    static final Object AUTHORIZATION_LOCK = new Object();
    static final String PENDING = "PENDING";
    static final String RELEASED = "RELEASED";
    static final String OK = "OK";
    static final String DELIVERY_FAILED = "DELIVERY_FAILED";
    static final String DELIVERY_UNCONFIRMED = "DELIVERY_UNCONFIRMED";

    private final WebDataAccessor accessor;
    private final BanService banService;

    public NativeLicenseService(WebDataAccessor accessor, BanService banService) {
        this.accessor = accessor;
        this.banService = banService;
    }

    public Decision preAuthorize(
            String code,
            String clientIp,
            String hwid,
            String pluginName
    ) {
        return inspect(code, clientIp, hwid, pluginName, false, true, true, 0).decision();
    }

    /** Serializes reservations and binding updates so concurrent first-use requests cannot exceed a limit. */
    @SneakyThrows
    public Decision completeAuthorization(
            String code,
            String clientIp,
            String hwid,
            String pluginName
    ) {
        synchronized (AUTHORIZATION_LOCK) {
            try {
                return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                    Inspection inspection = inspect(
                            code, clientIp, hwid, pluginName, false, true, true, 0);
                    if (!inspection.decision().allowed()) {
                        return inspection.decision();
                    }

                    License license = inspection.license();
                    long authLogId = logAuth(license, code, clientIp, hwid, PENDING);
                    return Decision.allow(license.getId(), authLogId);
                });
            } catch (java.sql.SQLException error) {
                throw new IllegalStateException("Unable to reserve native authorization", error);
            }
        }
    }

    /** Re-checks revocation state for every renewable heartbeat without writing success logs. */
    public boolean isSessionAuthorized(
            String code,
            String clientIp,
            String hwid,
            String pluginName,
            long authLogId
    ) {
        return inspect(
                code, clientIp, hwid, pluginName, true, false, false, authLogId)
                .decision()
                .allowed();
    }

    /** Finalizes a pre-release failure or records an unconfirmed released resource. */
    public void recordDeliveryFailure(long authLogId) {
        synchronized (AUTHORIZATION_LOCK) {
            finalizeDeliveryFailure(authLogId);
        }
    }

    /**
     * Commits binding and quota immediately before the encrypted resource is
     * released to the network. A client-controlled ACK cannot roll this back.
     */
    public void commitResourceRelease(long authLogId) {
        if (authLogId <= 0) {
            throw new IllegalArgumentException("authorization log id must be positive");
        }
        synchronized (AUTHORIZATION_LOCK) {
            try {
                boolean committed = DatabaseTransactions.call(
                        accessor.getConnectionSource(),
                        () -> commitResourceReleaseTransaction(authLogId));
                if (!committed) {
                    throw new IllegalStateException(
                            "Authorization was revoked before resource release");
                }
            } catch (java.sql.SQLException error) {
                throw new IllegalStateException("Unable to commit resource release", error);
            }
        }
    }

    /** Marks a released resource as client-confirmed after a valid ACK. */
    public void recordDeliverySuccess(long authLogId) {
        if (authLogId <= 0) {
            throw new IllegalArgumentException("authorization log id must be positive");
        }
        synchronized (AUTHORIZATION_LOCK) {
            try {
                boolean committed = DatabaseTransactions.call(
                        accessor.getConnectionSource(),
                        () -> confirmReleasedResource(authLogId));
                if (!committed) {
                    throw new IllegalStateException(
                            "Released authorization is no longer confirmable");
                }
            } catch (java.sql.SQLException error) {
                throw new IllegalStateException("Unable to confirm resource delivery", error);
            }
        }
    }

    /** Recovers pre-release reservations and released resources left by a prior process. */
    public int recoverPendingDeliveries() {
        synchronized (AUTHORIZATION_LOCK) {
            try {
                return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                    List<AuthLog> pending = accessor.getAuthLogDao().queryBuilder()
                            .where().eq("result", PENDING)
                            .or().eq("result", RELEASED)
                            .query();
                    for (AuthLog authLog : pending) {
                        authLog.setResult(RELEASED.equals(authLog.getResult())
                                ? DELIVERY_UNCONFIRMED : DELIVERY_FAILED);
                        accessor.getAuthLogDao().update(authLog);
                    }
                    return pending.size();
                });
            } catch (java.sql.SQLException error) {
                throw new IllegalStateException(
                        "Unable to recover unfinished native authorizations", error);
            }
        }
    }

    @SneakyThrows
    private Inspection inspect(
            String code,
            String clientIp,
            String hwid,
            String pluginName,
            boolean requireExistingBindings,
            boolean logFailure,
            boolean enforceDailyLimit,
            long pendingAuthLogId
    ) {
        License license = accessor.getLicenseDao().queryBuilder()
                .where().eq("code", code).queryForFirst();
        if (license == null) {
            return reject(null, code, clientIp, hwid, "FAILED", "License does not exist", logFailure);
        }

        Program program = accessor.getProgramDao().queryForId(license.getProgramId());
        if (program == null || program.getStatus() != 1) {
            return reject(license, code, clientIp, hwid,
                    "PROGRAM_DISABLED", "Program is missing or disabled", logFailure);
        }
        if (pluginName == null || !program.getName().equals(pluginName)) {
            return reject(license, code, clientIp, hwid,
                    "PROGRAM_MISMATCH", "License does not belong to this program", logFailure);
        }
        if (license.getUserId() != program.getUserId()) {
            return reject(license, code, clientIp, hwid,
                    "LICENSE_OWNER_MISMATCH", "License owner does not match program owner", logFailure);
        }

        WebUser owner = accessor.getUserDao().queryForId(license.getUserId());
        if (owner == null || owner.getStatus() != 1) {
            return reject(license, code, clientIp, hwid,
                    "USER_DISABLED", "Program owner is missing or disabled", logFailure);
        }
        if (license.getExpirationDate() != null
                && !license.getExpirationDate().isEmpty()
                && TimeUtil.getCurtTime().compareTo(license.getExpirationDate()) > 0) {
            return reject(license, code, clientIp, hwid,
                    "EXPIRED", "License has expired", logFailure);
        }
        if (license.getStatus() != 1) {
            return reject(license, code, clientIp, hwid,
                    "BANNED", license.getBanReason(), logFailure);
        }

        if (requireExistingBindings
                && !isRenewableAuthorization(
                license.getId(), code, clientIp, hwid, pendingAuthLogId)) {
            return reject(
                    license,
                    code,
                    clientIp,
                    hwid,
                    "SESSION_REVOKED",
                    "Authorization delivery was not committed or has been revoked",
                    logFailure);
        }

        if (enforceDailyLimit && hasReachedDailyLimit(license)) {
            return reject(license, code, clientIp, hwid,
                    "DAILY_AUTH_LIMIT", "Daily authentication limit has been reached", logFailure);
        }

        BanRecord banHit = banService.checkBanned(license, clientIp, hwid);
        if (banHit != null) {
            return reject(license, code, clientIp, hwid,
                    "BANNED_BY_" + banHit.getType(), banHit.getReason(), logFailure);
        }

        PendingBindings pendingBindings = requireExistingBindings
                ? new PendingBindings(List.of(), List.of())
                : pendingBindings(license.getId(), 0);
        Decision ipDecision = checkBinding(
                license,
                license.parseIps(),
                pendingBindings.ips(),
                clientIp,
                license.getBindableIps(),
                requireExistingBindings,
                "IP");
        if (ipDecision != null) {
            return reject(license, code, clientIp, hwid,
                    ipDecision.result(), ipDecision.reason(), logFailure);
        }
        Decision hwidDecision = checkBinding(
                license,
                license.parseHwids(),
                pendingBindings.hwids(),
                hwid,
                license.getBindableHwids(),
                requireExistingBindings,
                "HWID");
        if (hwidDecision != null) {
            return reject(license, code, clientIp, hwid,
                    hwidDecision.result(), hwidDecision.reason(), logFailure);
        }
        return new Inspection(license, Decision.allow(license.getId()));
    }

    private boolean commitResourceReleaseTransaction(long authLogId)
            throws java.sql.SQLException {
        return commitBindingAndSetResult(authLogId, RELEASED);
    }

    private boolean commitBindingAndSetResult(
            long authLogId,
            String committedResult
    ) throws java.sql.SQLException {
        AuthLog authLog = accessor.getAuthLogDao().queryForId(authLogId);
        if (authLog == null || !PENDING.equals(authLog.getResult())) {
            return false;
        }
        Program program = accessor.getProgramDao().queryForId(authLog.getProgramId());
        if (program == null) {
            authLog.setResult(DELIVERY_FAILED);
            accessor.getAuthLogDao().update(authLog);
            return false;
        }
        Inspection inspection = inspect(
                authLog.getCode(),
                authLog.getIp(),
                authLog.getHwid(),
                program.getName(),
                false,
                false,
                false,
                authLogId);
        License license = inspection.license();
        if (!inspection.decision().allowed()
                || license == null
                || !canCommitBinding(
                license.parseIps(), authLog.getIp(), license.getBindableIps())
                || !canCommitBinding(
                license.parseHwids(), authLog.getHwid(), license.getBindableHwids())) {
            authLog.setResult(DELIVERY_FAILED);
            accessor.getAuthLogDao().update(authLog);
            return false;
        }

        List<String> ips = new ArrayList<>(license.parseIps());
        List<String> hwids = new ArrayList<>(license.parseHwids());
        addCommittedBinding(ips, authLog.getIp(), license.getBindableIps());
        addCommittedBinding(hwids, authLog.getHwid(), license.getBindableHwids());
        license.setIps(License.joinList(ips));
        license.setHwids(License.joinList(hwids));
        license.setLastAuthTime(TimeUtil.getCurtTime());
        accessor.getLicenseDao().update(license);

        authLog.setResult(committedResult);
        accessor.getAuthLogDao().update(authLog);
        return true;
    }

    private boolean confirmReleasedResource(long authLogId) throws java.sql.SQLException {
        AuthLog authLog = accessor.getAuthLogDao().queryForId(authLogId);
        if (authLog == null || !RELEASED.equals(authLog.getResult())) {
            return false;
        }
        Program program = accessor.getProgramDao().queryForId(authLog.getProgramId());
        if (program == null) {
            authLog.setResult(DELIVERY_UNCONFIRMED);
            accessor.getAuthLogDao().update(authLog);
            return false;
        }
        Inspection inspection = inspect(
                authLog.getCode(),
                authLog.getIp(),
                authLog.getHwid(),
                program.getName(),
                true,
                false,
                false,
                authLogId);
        if (!inspection.decision().allowed()) {
            authLog.setResult(DELIVERY_UNCONFIRMED);
            accessor.getAuthLogDao().update(authLog);
            return false;
        }
        authLog.setResult(OK);
        accessor.getAuthLogDao().update(authLog);
        return true;
    }

    @SneakyThrows
    private boolean isRenewableAuthorization(
            long licenseId,
            String code,
            String clientIp,
            String hwid,
            long authLogId
    ) {
        if (authLogId <= 0) {
            return false;
        }
        AuthLog authLog = accessor.getAuthLogDao().queryForId(authLogId);
        return authLog != null
                && authLog.getLicenseId() == licenseId
                && Objects.equals(code, authLog.getCode())
                && Objects.equals(clientIp, authLog.getIp())
                && Objects.equals(hwid, authLog.getHwid())
                && (RELEASED.equals(authLog.getResult()) || OK.equals(authLog.getResult()));
    }

    @SneakyThrows
    private PendingBindings pendingBindings(long licenseId, long specificAuthLogId) {
        List<AuthLog> pending;
        if (specificAuthLogId > 0) {
            AuthLog candidate = accessor.getAuthLogDao().queryForId(specificAuthLogId);
            pending = candidate != null
                    && candidate.getLicenseId() == licenseId
                    && "PENDING".equals(candidate.getResult())
                    ? List.of(candidate)
                    : List.of();
        } else {
            pending = accessor.getAuthLogDao().queryBuilder()
                .where().eq("license_id", licenseId)
                .and().eq("result", PENDING)
                    .query();
        }
        LinkedHashSet<String> ips = new LinkedHashSet<>();
        LinkedHashSet<String> hwids = new LinkedHashSet<>();
        for (AuthLog authLog : pending) {
            if (authLog.getIp() != null && !authLog.getIp().isBlank()) {
                ips.add(authLog.getIp());
            }
            if (authLog.getHwid() != null && !authLog.getHwid().isBlank()) {
                hwids.add(authLog.getHwid());
            }
        }
        return new PendingBindings(List.copyOf(ips), List.copyOf(hwids));
    }

    private static boolean canCommitBinding(
            List<String> current,
            String presented,
            int limit
    ) {
        return limit <= 0
                || current.contains(presented)
                || current.size() < limit;
    }

    private static void addCommittedBinding(
            List<String> current,
            String presented,
            int limit
    ) {
        if (limit > 0 && !current.contains(presented)) {
            current.add(presented);
        }
    }

    @SneakyThrows
    private boolean hasReachedDailyLimit(License license) {
        if (license.getMaxDailyAuth() <= 0) {
            return false;
        }
        String todayPattern = TimeUtil.getCurtTime().substring(0, 10) + "-%";
        long successful = accessor.getAuthLogDao().queryBuilder()
                .where().eq("license_id", license.getId())
                .and().eq("result", OK)
                .and().like("timestamp", todayPattern)
                .countOf();
        long reserved = accessor.getAuthLogDao().queryBuilder()
                .where().eq("license_id", license.getId())
                .and().in("result", List.of(PENDING, RELEASED, DELIVERY_UNCONFIRMED))
                .and().like("timestamp", todayPattern)
                .countOf();
        return successful + reserved >= license.getMaxDailyAuth();
    }

    private static Decision checkBinding(
            License license,
            List<String> current,
            List<String> pending,
            String presented,
            int limit,
            boolean requireExisting,
            String type
    ) {
        if (limit <= 0) {
            return null;
        }
        if (presented == null || presented.isBlank()) {
            return Decision.reject(license.getId(), type + "_MISSING", type + " is required");
        }
        if (current.contains(presented) || pending.contains(presented)) {
            return null;
        }
        if (requireExisting) {
            return Decision.reject(
                    license.getId(), "BINDING_REVOKED", type + " binding is no longer active");
        }
        LinkedHashSet<String> reserved = new LinkedHashSet<>(current);
        reserved.addAll(pending);
        if (reserved.size() >= limit) {
            return Decision.reject(
                    license.getId(), type + "_LIMIT", type + " binding limit has been reached");
        }
        return null;
    }

    private Inspection reject(
            License license,
            String code,
            String clientIp,
            String hwid,
            String result,
            String reason,
            boolean logFailure
    ) {
        if (logFailure) {
            logAuth(license, code, clientIp, hwid, result);
        }
        return new Inspection(
                license,
                Decision.reject(license == null ? 0 : license.getId(), result, reason));
    }

    @SneakyThrows
    private long logAuth(
            License license,
            String code,
            String clientIp,
            String hwid,
            String result
    ) {
        AuthLog authLog = AuthLog.builder()
                .licenseId(license == null ? 0 : license.getId())
                .code(code)
                .ip(clientIp)
                .hwid(hwid)
                .result(result)
                .programId(license == null ? 0 : license.getProgramId())
                .userId(license == null ? 0 : license.getUserId())
                .timestamp(TimeUtil.getCurtTime())
                .build();
        accessor.getAuthLogDao().create(authLog);
        return authLog.getId();
    }

    private void finalizeDeliveryFailure(long authLogId) {
        if (authLogId <= 0) {
            return;
        }
        try {
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                AuthLog authLog = accessor.getAuthLogDao().queryForId(authLogId);
                if (authLog != null && PENDING.equals(authLog.getResult())) {
                    authLog.setResult(DELIVERY_FAILED);
                    accessor.getAuthLogDao().update(authLog);
                } else if (authLog != null && RELEASED.equals(authLog.getResult())) {
                    authLog.setResult(DELIVERY_UNCONFIRMED);
                    accessor.getAuthLogDao().update(authLog);
                } else if (authLog != null && OK.equals(authLog.getResult())) {
                    // The ACK was verified, but the confirmation byte could not
                    // be delivered. Keep the consumed binding/quota while making
                    // the audit reflect that the client never received ACCEPT.
                    authLog.setResult(DELIVERY_UNCONFIRMED);
                    accessor.getAuthLogDao().update(authLog);
                }
                return null;
            });
        } catch (java.sql.SQLException error) {
            throw new IllegalStateException("Unable to finalize native authorization", error);
        }
    }

    private record Inspection(License license, Decision decision) {
    }

    private record PendingBindings(List<String> ips, List<String> hwids) {
    }

    public record Decision(
            boolean allowed,
            long licenseId,
            long authLogId,
            String result,
            String reason
    ) {
        public static Decision allow(long licenseId) {
            return allow(licenseId, 0);
        }

        public static Decision allow(long licenseId, long authLogId) {
            return new Decision(true, licenseId, authLogId, "OK", null);
        }

        public static Decision reject(long licenseId, String result, String reason) {
            return new Decision(false, licenseId, 0, result, reason);
        }
    }
}

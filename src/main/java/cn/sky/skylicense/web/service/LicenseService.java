package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.StringUtil;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.security.NativeIdentifierValidator;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.dto.query.LicenseQuery;
import cn.sky.skylicense.web.dto.request.BatchLicenseRequest;
import cn.sky.skylicense.web.dto.request.CreateLicenseRequest;
import cn.sky.skylicense.web.dto.request.UnbindRequest;
import cn.sky.skylicense.web.dto.request.UpdateLicenseRequest;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.entity.AuthLog;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.stmt.Where;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class LicenseService {
    private static final DateTimeFormatter DATE_TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd-HH:mm");
    private static final Pattern PARTIAL_IP_PATTERN = Pattern.compile("[0-9A-Fa-f:.]{1,64}");
    private static final Pattern PARTIAL_HWID_PATTERN =
            Pattern.compile("[A-Za-z0-9+/=]{1,256}");
    private static final Pattern AUTH_RESULT_PATTERN =
            Pattern.compile("[A-Z][A-Z0-9_]{0,63}");

    private final WebDataAccessor accessor;

    public LicenseService(WebDataAccessor accessor) {
        this.accessor = accessor;
    }

    @SneakyThrows
    public License createLicense(long programId, CreateLicenseRequest request) {
        Program program = accessor.getProgramDao().queryForId(programId);
        if (program == null) {
            throw BizException.notFound("程序不存在");
        }
        checkProgramOwnership(program);

        String code = requestedLicenseCode(request.getCode());

        License existing = accessor.getLicenseDao().queryBuilder()
                .where().eq("code", code).queryForFirst();
        if (existing != null) {
            throw new BizException("授权码已存在: " + code);
        }

        License license = buildLicense(
                code,
                program,
                request.getQq(),
                request.getBindableIps(),
                request.getBindableHwids(),
                request.getNotes(),
                request.getExpirationDate(),
                request.getMaxDailyAuth());

        accessor.getLicenseDao().create(license);
        return license;
    }

    /**
     * 为多个程序创建授权码（用户只能选择自己的程序）
     */
    @SneakyThrows
    public List<License> createLicenseMulti(CreateLicenseRequest request) {
        UserContext ctx = UserContext.get();
        if (ctx == null) {
            throw BizException.unauthorized("Authentication is required");
        }

        List<Long> programIds = request.getProgramIds();
        if (programIds == null || programIds.isEmpty()) {
            throw new BizException("programIds 不能为空");
        }
        List<Long> uniqueProgramIds = new ArrayList<>(new LinkedHashSet<>(programIds));

        return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
            List<License> created = new ArrayList<>();
            for (Long programId : uniqueProgramIds) {
                Program program = accessor.getProgramDao().queryForId(programId);
                if (program == null) {
                    throw BizException.notFound("程序不存在: ID=" + programId);
                }
                if (!ctx.isAdmin() && program.getUserId() != ctx.getUserId()) {
                    throw BizException.forbidden(
                            "无权为程序 " + program.getName() + " 创建授权码");
                }

                String code = batchCode(
                        request.getCode(), programId, uniqueProgramIds.size() > 1);

                License existing = accessor.getLicenseDao().queryBuilder()
                        .where().eq("code", code).queryForFirst();
                if (existing != null) {
                    throw new BizException("授权码已存在: " + code);
                }

                License license = buildLicense(
                        code,
                        program,
                        request.getQq(),
                        request.getBindableIps(),
                        request.getBindableHwids(),
                        request.getNotes(),
                        request.getExpirationDate(),
                        request.getMaxDailyAuth());

                accessor.getLicenseDao().create(license);
                created.add(license);
            }
            return created;
        });
    }

    // ===== PLACEHOLDER_QUERY_METHODS =====

    public static final int MAX_PAGE_SIZE = 100;

    private int clampPageSize(int pageSize) {
        return Math.min(Math.max(pageSize, 1), MAX_PAGE_SIZE);
    }

    @SneakyThrows
    public PageResult<License> listByProgram(long programId, int page, int pageSize, LicenseQuery query) {
        Program program = accessor.getProgramDao().queryForId(programId);
        if (program == null) {
            throw BizException.notFound("程序不存在");
        }
        checkProgramOwnership(program);
        pageSize = clampPageSize(pageSize);
        query = normalizeLicenseQuery(query);

        Dao<License, Long> dao = accessor.getLicenseDao();
        QueryBuilder<License, Long> qb = dao.queryBuilder();
        Where<License, Long> where = qb.where();

        // 基础条件：属于该程序
        where.eq("program_id", programId);

        // 状态筛选
        if (query.getStatus() != null) {
            if ("active".equals(query.getStatus())) {
                where.and().eq("status", 1);
            } else if ("banned".equals(query.getStatus())) {
                where.and().eq("status", 0);
            }
        }

        // QQ筛选
        if (query.getQq() != null) {
            where.and().eq("qq", query.getQq());
        }

        // IP筛选
        if (query.getIp() != null) {
            where.and().raw(
                    "ips LIKE ? ESCAPE '\\'",
                    new com.j256.ormlite.stmt.SelectArg(
                            SqlType.STRING, containsLikePattern(query.getIp())));
        }

        // HWID筛选
        if (query.getHwid() != null) {
            where.and().raw(
                    "hwids LIKE ? ESCAPE '\\'",
                    new com.j256.ormlite.stmt.SelectArg(
                            SqlType.STRING, containsLikePattern(query.getHwid())));
        }

        // 关键词搜索（使用 OR 组合，避免 SQL 注入）
        if (query.getKeyword() != null) {
            String kw = containsLikePattern(query.getKeyword());
            where.and().raw(
                    "(code LIKE ? ESCAPE '\\' OR qq LIKE ? ESCAPE '\\' "
                            + "OR notes LIKE ? ESCAPE '\\')",
                    new com.j256.ormlite.stmt.SelectArg(SqlType.STRING, kw),
                    new com.j256.ormlite.stmt.SelectArg(SqlType.STRING, kw),
                    new com.j256.ormlite.stmt.SelectArg(SqlType.STRING, kw)
            );
        }

        // 排序（白名单校验防止注入）
        String sortBy = "id";
        if (query.getSortBy() != null) {
            sortBy = switch (query.getSortBy()) {
                case "createTime" -> "create_time";
                case "lastAuthTime" -> "last_auth_time";
                case "code" -> "code";
                case "qq" -> "qq";
                case "status" -> "status";
                default -> "id";
            };
        }
        boolean ascending = "asc".equalsIgnoreCase(query.getOrder());
        qb.orderBy(sortBy, ascending);

        long total = qb.countOf();
        List<License> licenses = qb
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .query();

        return PageResult.of(licenses, total, page, pageSize);
    }

    @SneakyThrows
    public License getByCode(String code) {
        License license = accessor.getLicenseDao().queryBuilder()
                .where().eq("code", code).queryForFirst();
        if (license == null) {
            throw BizException.notFound("授权码不存在");
        }
        checkLicenseOwnership(license);
        return license;
    }

    @SneakyThrows
    public License updateLicense(String code, UpdateLicenseRequest request) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<License, Long> dao = accessor.getLicenseDao();
            License license = dao.queryBuilder().where().eq("code", code).queryForFirst();
            if (license == null) {
                throw BizException.notFound("授权码不存在");
            }
            checkLicenseOwnership(license);

            if (request.getQq() != null) {
                license.setQq(normalizeQq(request.getQq()));
            }
            if (request.getBindableIps() != null) {
                validateBindingLimit(
                        "IP",
                        request.getBindableIps(),
                        license.parseIps());
                license.setBindableIps(request.getBindableIps());
            }
            if (request.getBindableHwids() != null) {
                validateBindingLimit(
                        "机器码",
                        request.getBindableHwids(),
                        license.parseHwids());
                license.setBindableHwids(request.getBindableHwids());
            }
            if (request.getNotes() != null) {
                license.setNotes(normalizeOptionalText(request.getNotes()));
            }
            if (request.getExpirationDate() != null) {
                license.setExpirationDate(normalizeExpirationDate(request.getExpirationDate()));
            }
            if (request.getMaxDailyAuth() != null) {
                license.setMaxDailyAuth(request.getMaxDailyAuth());
            }
            license.setLastModifiedTime(TimeUtil.getCurtTime());
            dao.update(license);
            return license;
        }
    }

    private static void validateBindingLimit(
            String type,
            int requestedLimit,
            List<String> currentBindings
    ) {
        if (requestedLimit < 0) {
            throw new BizException(type + "绑定数不能为负数");
        }
        if (requestedLimit > 0 && currentBindings.size() > requestedLimit) {
            throw new BizException(
                    type + "绑定数不能低于当前已绑定数量，请先解绑设备");
        }
    }

    @SneakyThrows
    public void deleteLicense(String code) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<License, Long> dao = accessor.getLicenseDao();
            License license = dao.queryBuilder().where().eq("code", code).queryForFirst();
            if (license == null) {
                throw BizException.notFound("授权码不存在");
            }
            checkLicenseOwnership(license);
            dao.delete(license);
        }
    }

    // ===== 精细解绑 =====

    @SneakyThrows
    public License unbind(String code, UnbindRequest request) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            String requestedIp = request.isAll() ? null : normalizeUnbindIp(request.getIp());
            String requestedHwid = request.isAll() ? null : normalizeUnbindHwid(request.getHwid());
            Dao<License, Long> dao = accessor.getLicenseDao();
            License license = dao.queryBuilder().where().eq("code", code).queryForFirst();
            if (license == null) {
                throw BizException.notFound("授权码不存在");
            }
            checkLicenseOwnership(license);

            return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                if (request.isAll()) {
                    license.setIps("");
                    license.setHwids("");
                } else {
                    if (requestedIp != null) {
                        List<String> ips = new ArrayList<>(license.parseIps());
                        ips.remove(requestedIp);
                        license.setIps(License.joinList(ips));
                    }
                    if (requestedHwid != null) {
                        List<String> hwids = new ArrayList<>(license.parseHwids());
                        hwids.remove(requestedHwid);
                        license.setHwids(License.joinList(hwids));
                    }
                }

                failPendingBindings(
                        license.getId(), request.isAll(), requestedIp, requestedHwid);
                license.setLastModifiedTime(TimeUtil.getCurtTime());
                dao.update(license);
                return license;
            });
        }
    }

    private void failPendingBindings(
            long licenseId,
            boolean all,
            String requestedIp,
            String requestedHwid
    )
            throws java.sql.SQLException {
        List<AuthLog> pending = accessor.getAuthLogDao().queryBuilder()
                .where().eq("license_id", licenseId)
                .and().in("result", List.of(
                        NativeLicenseService.PENDING,
                        NativeLicenseService.RELEASED))
                .query();
        for (AuthLog authLog : pending) {
            boolean affected = all
                    || requestedIp != null && requestedIp.equals(authLog.getIp())
                    || requestedHwid != null && requestedHwid.equals(authLog.getHwid());
            if (affected) {
                authLog.setResult(NativeLicenseService.RELEASED.equals(authLog.getResult())
                        ? NativeLicenseService.DELIVERY_UNCONFIRMED
                        : NativeLicenseService.DELIVERY_FAILED);
                accessor.getAuthLogDao().update(authLog);
            }
        }
    }

    // ===== 封禁/解封 =====

    @SneakyThrows
    public void banLicense(String code, String reason) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<License, Long> dao = accessor.getLicenseDao();
            License license = dao.queryBuilder().where().eq("code", code).queryForFirst();
            if (license == null) {
                throw BizException.notFound("授权码不存在");
            }
            checkLicenseOwnership(license);
            if (license.getStatus() == 0) {
                throw new BizException("授权码已处于封禁状态");
            }
            license.setStatus(0);
            license.setBanReason(reason);
            license.setLastModifiedTime(TimeUtil.getCurtTime());
            dao.update(license);
        }
    }

    @SneakyThrows
    public void unbanLicense(String code) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<License, Long> dao = accessor.getLicenseDao();
            License license = dao.queryBuilder().where().eq("code", code).queryForFirst();
            if (license == null) {
                throw BizException.notFound("授权码不存在");
            }
            checkLicenseOwnership(license);
            if (license.getStatus() == 1) {
                throw new BizException("授权码未被封禁");
            }
            license.setStatus(1);
            license.setBanReason(null);
            license.setLastModifiedTime(TimeUtil.getCurtTime());
            dao.update(license);
        }
    }

    // ===== 批量操作 =====

    @SneakyThrows
    public int batchBan(BatchLicenseRequest request) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<License, Long> dao = accessor.getLicenseDao();
            List<License> licenses = findOwnedLicenses(request.getCodes());
            String reason = request.getReason() != null ? request.getReason() : "批量封禁";
            return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                for (License l : licenses) {
                    l.setStatus(0);
                    l.setBanReason(reason);
                    l.setLastModifiedTime(TimeUtil.getCurtTime());
                    dao.update(l);
                }
                return licenses.size();
            });
        }
    }

    @SneakyThrows
    public int batchUnban(BatchLicenseRequest request) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<License, Long> dao = accessor.getLicenseDao();
            List<License> licenses = findOwnedLicenses(request.getCodes());
            return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                for (License l : licenses) {
                    l.setStatus(1);
                    l.setBanReason(null);
                    l.setLastModifiedTime(TimeUtil.getCurtTime());
                    dao.update(l);
                }
                return licenses.size();
            });
        }
    }

    @SneakyThrows
    public int batchDelete(BatchLicenseRequest request) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<License, Long> dao = accessor.getLicenseDao();
            List<License> licenses = findOwnedLicenses(request.getCodes());
            return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                for (License l : licenses) {
                    dao.delete(l);
                }
                return licenses.size();
            });
        }
    }

    private List<License> findOwnedLicenses(List<String> codes) throws java.sql.SQLException {
        Dao<License, Long> dao = accessor.getLicenseDao();
        List<License> licenses = new ArrayList<>();
        for (String code : new LinkedHashSet<>(codes)) {
            License license = dao.queryBuilder().where().eq("code", code).queryForFirst();
            if (license != null) {
                checkLicenseOwnership(license);
                licenses.add(license);
            }
        }
        return licenses;
    }

    // ===== 管理员创建授权码（支持多程序） =====

    @SneakyThrows
    public List<License> adminCreateLicense(cn.sky.skylicense.web.dto.request.AdminCreateLicenseRequest request) {
        UserContext ctx = UserContext.get();
        if (ctx == null || !ctx.isAdmin()) {
            throw BizException.forbidden("需要管理员权限");
        }

        List<Long> targetProgramIds;
        if (request.isAllPrograms()) {
            // 为所有程序创建
            List<Program> allPrograms = accessor.getProgramDao().queryForAll();
            targetProgramIds = allPrograms.stream().map(Program::getId).toList();
        } else {
            targetProgramIds = request.getProgramIds();
        }

        if (targetProgramIds == null || targetProgramIds.isEmpty()) {
            throw new BizException("目标程序列表不能为空");
        }
        List<Long> uniqueTargetProgramIds =
                new ArrayList<>(new LinkedHashSet<>(targetProgramIds));

        return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
            List<License> created = new ArrayList<>();
            for (Long programId : uniqueTargetProgramIds) {
                Program program = accessor.getProgramDao().queryForId(programId);
                if (program == null) {
                    throw BizException.notFound("程序不存在: ID=" + programId);
                }

                String code = batchCode(
                        request.getCode(), programId, uniqueTargetProgramIds.size() > 1);
                License existing = accessor.getLicenseDao().queryBuilder()
                        .where().eq("code", code).queryForFirst();
                if (existing != null) {
                    throw new BizException("授权码已存在: " + code);
                }

                License license = buildLicense(
                        code,
                        program,
                        request.getQq(),
                        request.getBindableIps(),
                        request.getBindableHwids(),
                        request.getNotes(),
                        request.getExpirationDate(),
                        request.getMaxDailyAuth());

                accessor.getLicenseDao().create(license);
                created.add(license);
            }
            return created;
        });
    }

    private static String batchCode(String requested, long programId, boolean appendProgramId) {
        if (requested == null || requested.isBlank()) {
            return StringUtil.generateCustomUUID();
        }
        String normalized = normalizeLicenseCode(requested);
        String code = appendProgramId ? normalized + "-" + programId : normalized;
        if (!NativeIdentifierValidator.isValidLicenseCode(code)) {
            throw new BizException("生成的授权码格式无效或超过256个字符");
        }
        return code;
    }

    private static String requestedLicenseCode(String requested) {
        if (requested == null || requested.isBlank()) {
            return StringUtil.generateCustomUUID();
        }
        return normalizeLicenseCode(requested);
    }

    private static String normalizeLicenseCode(String value) {
        String normalized = value.trim();
        if (!NativeIdentifierValidator.isValidLicenseCode(normalized)) {
            throw new BizException(
                    "授权码只能包含字母、数字、点、下划线、加号和连字符，长度1-256");
        }
        return normalized;
    }

    private static String normalizeUnbindIp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return NativeIdentifierValidator.normalizeIpLiteral(value);
        } catch (IllegalArgumentException error) {
            throw new BizException("解绑IP必须是合法的IPv4或IPv6地址");
        }
    }

    private static String normalizeUnbindHwid(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > 256) {
            throw new BizException("解绑机器码不能超过256个字符");
        }
        return normalized;
    }

    private static License buildLicense(
            String code,
            Program program,
            String qq,
            int bindableIps,
            int bindableHwids,
            String notes,
            String expirationDate,
            int maxDailyAuth
    ) {
        String now = TimeUtil.getCurtTime();
        return License.builder()
                .code(code)
                .programId(program.getId())
                .userId(program.getUserId())
                .qq(normalizeQq(qq))
                .bindableIps(bindableIps)
                .bindableHwids(bindableHwids)
                .status(1)
                .ips("")
                .hwids("")
                .createTime(now)
                .lastModifiedTime(now)
                .notes(normalizeOptionalText(notes))
                .expirationDate(normalizeExpirationDate(expirationDate))
                .maxDailyAuth(maxDailyAuth)
                .build();
    }

    private static String normalizeExpirationDate(String value) {
        String normalized = normalizeOptionalText(value);
        if (normalized == null) {
            return null;
        }
        try {
            LocalDateTime.parse(normalized, DATE_TIME_FORMAT);
            return normalized;
        } catch (DateTimeParseException error) {
            throw new BizException("到期时间格式必须为 yyyy-MM-dd-HH:mm");
        }
    }

    private static String normalizeOptionalText(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    /** QQ is a numeric identifier; keep legacy rows readable but reject new invalid values. */
    private static String normalizeQq(String value) {
        String normalized = normalizeOptionalText(value);
        if (normalized == null) {
            return null;
        }
        if (!NativeIdentifierValidator.isValidQq(normalized)) {
            throw new BizException("QQ号必须是1-20位数字");
        }
        return normalized;
    }

    private static LicenseQuery normalizeLicenseQuery(LicenseQuery query) {
        LicenseQuery normalized = query == null ? new LicenseQuery() : query;
        normalized.setStatus(normalizeEnumQuery(
                normalized.getStatus(), "许可证状态", "active", "banned"));
        normalized.setQq(normalizeQueryText(normalized.getQq(), 128, "QQ"));
        normalized.setIp(normalizeQueryPattern(
                normalized.getIp(), PARTIAL_IP_PATTERN, 64, "IP"));
        normalized.setHwid(normalizeQueryPattern(
                normalized.getHwid(), PARTIAL_HWID_PATTERN, 256, "HWID"));
        normalized.setKeyword(normalizeQueryText(normalized.getKeyword(), 256, "关键词"));
        normalized.setSortBy(normalizeEnumQuery(
                normalized.getSortBy(), "排序字段",
                "createTime", "lastAuthTime", "code", "qq", "status"));
        normalized.setOrder(normalizeEnumQuery(
                normalized.getOrder(), "排序方向", "asc", "desc"));
        return normalized;
    }

    private static cn.sky.skylicense.web.dto.query.AuthLogQuery normalizeAuthLogQuery(
            cn.sky.skylicense.web.dto.query.AuthLogQuery query
    ) {
        cn.sky.skylicense.web.dto.query.AuthLogQuery normalized =
                query == null ? new cn.sky.skylicense.web.dto.query.AuthLogQuery() : query;
        String code = normalizeQueryText(normalized.getCode(), 256, "许可证");
        if (code != null && !NativeIdentifierValidator.isValidLicenseCode(code)) {
            throw new BizException("许可证筛选格式无效");
        }
        normalized.setCode(code);
        normalized.setIp(normalizeQueryPattern(
                normalized.getIp(), PARTIAL_IP_PATTERN, 64, "IP"));
        normalized.setHwid(normalizeQueryPattern(
                normalized.getHwid(), PARTIAL_HWID_PATTERN, 256, "HWID"));
        String result = normalizeQueryText(normalized.getResult(), 64, "验证结果");
        if (result != null && !AUTH_RESULT_PATTERN.matcher(result).matches()) {
            throw new BizException("验证结果格式无效");
        }
        normalized.setResult(result);
        String start = normalizeQueryTime(normalized.getStartTime(), "开始时间");
        String end = normalizeQueryTime(normalized.getEndTime(), "结束时间");
        if (start != null && end != null && start.compareTo(end) > 0) {
            throw new BizException("开始时间不能晚于结束时间");
        }
        normalized.setStartTime(start);
        normalized.setEndTime(end);
        if (normalized.getProgramId() != null && normalized.getProgramId() <= 0) {
            throw new BizException("程序ID必须大于0");
        }
        return normalized;
    }

    private static String normalizeEnumQuery(String value, String field, String... allowed) {
        String normalized = normalizeQueryText(value, 32, field);
        if (normalized == null) {
            return null;
        }
        for (String candidate : allowed) {
            if (candidate.equalsIgnoreCase(normalized)) {
                return candidate;
            }
        }
        throw new BizException(field + "无效");
    }

    private static String normalizeQueryPattern(
            String value, Pattern pattern, int maxLength, String field
    ) {
        String normalized = normalizeQueryText(value, maxLength, field);
        if (normalized != null && !pattern.matcher(normalized).matches()) {
            throw new BizException(field + "筛选格式无效");
        }
        return normalized;
    }

    private static String normalizeQueryText(String value, int maxLength, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > maxLength) {
            throw new BizException(field + "筛选条件过长");
        }
        return normalized;
    }

    private static String normalizeQueryTime(String value, String field) {
        String normalized = normalizeQueryText(value, 16, field);
        if (normalized == null) {
            return null;
        }
        try {
            LocalDateTime.parse(normalized, DATE_TIME_FORMAT);
            return normalized;
        } catch (DateTimeParseException error) {
            throw new BizException(field + "格式必须为 yyyy-MM-dd-HH:mm");
        }
    }

    private static String containsLikePattern(String value) {
        return "%" + value
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_") + "%";
    }

    // ===== 验证历史 =====

    @SneakyThrows
    public PageResult<AuthLog> getAuthLogs(String code, int page, int pageSize) {
        License license = accessor.getLicenseDao().queryBuilder()
                .where().eq("code", code).queryForFirst();
        if (license == null) {
            throw BizException.notFound("授权码不存在");
        }
        checkLicenseOwnership(license);
        pageSize = clampPageSize(pageSize);

        Dao<AuthLog, Long> logDao = accessor.getAuthLogDao();
        long total = logDao.queryBuilder()
                .where().eq("license_id", license.getId())
                .countOf();
        List<AuthLog> logs = logDao.queryBuilder()
                .where().eq("license_id", license.getId())
                .queryBuilder()
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .orderBy("id", false)
                .query();

        return PageResult.of(logs, total, page, pageSize);
    }

    /**
     * 查询用户所有程序的验证历史（支持筛选）
     */
    @SneakyThrows
    public PageResult<AuthLog> getAuthLogsByUser(cn.sky.skylicense.web.dto.query.AuthLogQuery query, int page, int pageSize) {
        UserContext ctx = UserContext.get();
        query = normalizeAuthLogQuery(query);
        pageSize = clampPageSize(pageSize);

        Dao<AuthLog, Long> logDao = accessor.getAuthLogDao();
        com.j256.ormlite.stmt.QueryBuilder<AuthLog, Long> qb = logDao.queryBuilder();
        com.j256.ormlite.stmt.Where<AuthLog, Long> where = qb.where();

        // 非管理员只能看自己的
        if (!ctx.isAdmin()) {
            where.eq("user_id", ctx.getUserId());
        } else {
            where.raw("1=1"); // 管理员无限制
        }

        // 按程序筛选
        if (query.getProgramId() != null) {
            where.and().eq("program_id", query.getProgramId());
        }

        // 按授权码筛选
        if (query.getCode() != null && !query.getCode().isBlank()) {
            where.and().eq("code", query.getCode());
        }

        // 按IP筛选
        if (query.getIp() != null && !query.getIp().isBlank()) {
            where.and().eq("ip", query.getIp());
        }

        // 按HWID筛选
        if (query.getHwid() != null && !query.getHwid().isBlank()) {
            where.and().eq("hwid", query.getHwid());
        }

        // 按结果筛选
        if (query.getResult() != null && !query.getResult().isBlank()) {
            where.and().eq("result", query.getResult());
        }

        // 时间范围筛选
        if (query.getStartTime() != null && !query.getStartTime().isBlank()) {
            where.and().ge("timestamp", query.getStartTime());
        }
        if (query.getEndTime() != null && !query.getEndTime().isBlank()) {
            where.and().le("timestamp", query.getEndTime());
        }

        long total = qb.countOf();
        List<AuthLog> logs = qb
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .orderBy("id", false)
                .query();

        return PageResult.of(logs, total, page, pageSize);
    }

    /**
     * 查询指定程序的所有验证历史
     */
    @SneakyThrows
    public PageResult<AuthLog> getAuthLogsByProgram(long programId, cn.sky.skylicense.web.dto.query.AuthLogQuery query, int page, int pageSize) {
        Program program = accessor.getProgramDao().queryForId(programId);
        if (program == null) {
            throw BizException.notFound("程序不存在");
        }
        checkProgramOwnership(program);
        query = normalizeAuthLogQuery(query);
        pageSize = clampPageSize(pageSize);

        Dao<AuthLog, Long> logDao = accessor.getAuthLogDao();
        com.j256.ormlite.stmt.QueryBuilder<AuthLog, Long> qb = logDao.queryBuilder();
        com.j256.ormlite.stmt.Where<AuthLog, Long> where = qb.where();

        where.eq("program_id", programId);

        if (query != null && query.getResult() != null && !query.getResult().isBlank()) {
            where.and().eq("result", query.getResult());
        }
        if (query != null && query.getIp() != null && !query.getIp().isBlank()) {
            where.and().eq("ip", query.getIp());
        }
        if (query != null && query.getHwid() != null && !query.getHwid().isBlank()) {
            where.and().eq("hwid", query.getHwid());
        }
        if (query != null && query.getCode() != null && !query.getCode().isBlank()) {
            where.and().eq("code", query.getCode());
        }
        if (query != null && query.getStartTime() != null && !query.getStartTime().isBlank()) {
            where.and().ge("timestamp", query.getStartTime());
        }
        if (query != null && query.getEndTime() != null && !query.getEndTime().isBlank()) {
            where.and().le("timestamp", query.getEndTime());
        }

        long total = qb.countOf();
        List<AuthLog> logs = qb
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .orderBy("id", false)
                .query();

        return PageResult.of(logs, total, page, pageSize);
    }

    @SneakyThrows
    public PageResult<License> listAll(int page, int pageSize) {
        pageSize = clampPageSize(pageSize);
        Dao<License, Long> dao = accessor.getLicenseDao();
        long total = dao.countOf();
        List<License> licenses = dao.queryBuilder()
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .orderBy("id", false)
                .query();
        return PageResult.of(licenses, total, page, pageSize);
    }

    // ===== 权限检查 =====

    private void checkProgramOwnership(Program program) {
        UserContext ctx = UserContext.get();
        if (!ctx.isAdmin() && program.getUserId() != ctx.getUserId()) {
            throw BizException.forbidden("无权操作此程序");
        }
    }

    private void checkLicenseOwnership(License license) {
        UserContext ctx = UserContext.get();
        if (!ctx.isAdmin() && license.getUserId() != ctx.getUserId()) {
            throw BizException.forbidden("无权操作此授权码");
        }
    }
}

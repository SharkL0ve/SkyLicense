package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.security.NativeIdentifierValidator;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.dto.request.BanRequest;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.entity.BanRecord;
import cn.sky.skylicense.web.entity.License;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.stmt.Where;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

@Service
public class BanService {
    private static final String RULE_MARKER_PREFIX = "[license-ban-rule:";
    private static final DateTimeFormatter DATE_TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd-HH:mm");
    private static final Pattern BAN_TYPE_PATTERN = Pattern.compile("IP|HWID|QQ|CODE");

    private final WebDataAccessor accessor;
    private final LicenseService licenseService;

    public BanService(WebDataAccessor accessor, LicenseService licenseService) {
        this.accessor = accessor;
        this.licenseService = licenseService;
    }

    /** Checks only relevant indexed rule values; it never scans the complete ban table. */
    @SneakyThrows
    public BanRecord checkBanned(License license, String ip, String hwid) {
        String now = TimeUtil.getCurtTime();
        BanRecord hit = findActiveRule(
                "CODE", List.of(license.getCode()), license.getProgramId(), license.getUserId(), now);
        if (hit != null) {
            return hit;
        }
        if (license.getQq() != null && !license.getQq().isEmpty()) {
            hit = findActiveRule(
                    "QQ", List.of(license.getQq()), license.getProgramId(), license.getUserId(), now);
            if (hit != null) {
                return hit;
            }
        }

        List<String> ipValues = new ArrayList<>(license.parseIps());
        if (ip != null && !ip.isEmpty() && !ipValues.contains(ip)) {
            ipValues.add(ip);
        }
        hit = findActiveRule("IP", ipValues, license.getProgramId(), license.getUserId(), now);
        if (hit != null) {
            return hit;
        }

        List<String> hwidValues = new ArrayList<>(license.parseHwids());
        if (hwid != null && !hwid.isEmpty() && !hwidValues.contains(hwid)) {
            hwidValues.add(hwid);
        }
        return findActiveRule("HWID", hwidValues, license.getProgramId(), license.getUserId(), now);
    }

    @SneakyThrows
    private BanRecord findActiveRule(
            String type,
            List<String> values,
            long programId,
            long licenseUserId,
            String now
    ) {
        Set<String> uniqueValues = new LinkedHashSet<>();
        for (String value : values) {
            if (value != null && !value.isEmpty()) {
                uniqueValues.add(value);
            }
        }
        if (uniqueValues.isEmpty()) {
            return null;
        }
        List<String> candidates = new ArrayList<>(uniqueValues);
        Dao<BanRecord, Long> dao = accessor.getBanRecordDao();
        // SQLite's default bind-variable limit is commonly 999.
        for (int offset = 0; offset < candidates.size(); offset += 500) {
            List<String> chunk = candidates.subList(
                    offset, Math.min(offset + 500, candidates.size()));
            List<BanRecord> records = dao.queryBuilder()
                    .where().eq("type", type)
                    .and().eq("status", 1)
                    .and().in("value", chunk)
                    .query();
            for (BanRecord record : records) {
                if (ruleAppliesTo(record, programId, licenseUserId)
                        && !isExpired(record, now)) {
                    return record;
                }
            }
        }
        return null;
    }

    @SneakyThrows
    private boolean ruleAppliesTo(BanRecord record, long programId, long licenseUserId) {
        if (record.getProgramId() != 0) {
            return record.getProgramId() == programId;
        }
        if (licenseUserId != 0 && record.getOperatorId() == licenseUserId) {
            return true;
        }
        WebUser operator = accessor.getUserDao().queryForId(record.getOperatorId());
        return operator != null && "ADMIN".equals(operator.getRole());
    }

    private static boolean isExpired(BanRecord record, String now) {
        String expiration = record.getExpirationDate();
        return expiration != null && !expiration.isEmpty() && now.compareTo(expiration) > 0;
    }

    /**
     * 仅通过值快速检查是否存在封禁（不依赖 License 实体）
     */
    @SneakyThrows
    public BanRecord checkBannedByValue(String type, String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        String normalizedType = type == null ? "" : type.trim().toUpperCase(Locale.ROOT);
        try {
            value = normalizeBanValue(normalizedType, value);
        } catch (IllegalArgumentException error) {
            return null;
        }
        return findActiveRule(
                normalizedType, List.of(value), 0, 0, TimeUtil.getCurtTime());
    }

    public BanRecord createBan(BanRequest request) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            return createBanLocked(request);
        }
    }

    @SneakyThrows
    private BanRecord createBanLocked(BanRequest request) {
        UserContext ctx = UserContext.get();
        if (ctx == null) {
            throw BizException.unauthorized("Authentication is required");
        }

        if (request == null || request.getType() == null || request.getValue() == null) {
            throw new BizException("封禁类型和值不能为空");
        }
        String type = request.getType().trim().toUpperCase(Locale.ROOT);
        if (!BAN_TYPE_PATTERN.matcher(type).matches()) {
            throw new BizException("无效的封禁类型，支持: IP, HWID, QQ, CODE");
        }
        String value;
        try {
            value = normalizeBanValue(type, request.getValue());
        } catch (IllegalArgumentException error) {
            throw new BizException(error.getMessage());
        }

        long programId = request.getProgramId() == null ? 0 : request.getProgramId();
        if (programId < 0) {
            throw new BizException("程序ID不能为负数");
        }
        if (programId == 0 && !ctx.isAdmin()) {
            throw new BizException("普通用户创建封禁时必须选择自己的程序");
        }
        if (programId > 0) {
            Program program = accessor.getProgramDao().queryForId(programId);
            if (program == null) {
                throw BizException.notFound("程序不存在");
            }
            if (!ctx.isAdmin() && program.getUserId() != ctx.getUserId()) {
                throw BizException.forbidden("无权为此程序创建封禁");
            }
        }
        String expirationDate = normalizeExpirationDate(request.getExpirationDate());
        String reason = normalizeReason(request.getReason());

        // 检查是否已存在相同封禁
        BanRecord existing = accessor.getBanRecordDao().queryBuilder()
                .where().eq("type", type).and().eq("value", value)
                .and().eq("status", 1)
                .and().eq("program_id", programId)
                .queryForFirst();
        if (existing != null) {
            throw new BizException("该 " + type + " 已被封禁");
        }

        if ("CODE".equals(type) && programId > 0) {
            License target = licenseService.getByCode(value);
            if (target.getProgramId() != programId) {
                throw new BizException("许可证不属于所选程序");
            }
        }

        BanRecord record = BanRecord.builder()
                .type(type)
                .value(value)
                .reason(reason)
                .operatorId(ctx.getUserId())
                .programId(programId)
                .status(1) // 生效
                .expirationDate(expirationDate)
                .createTime(TimeUtil.getCurtTime())
                .build();

        return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
            accessor.getBanRecordDao().create(record);
            applyBanToExistingLicenses(record);
            return record;
        });
    }

    private void applyBanToExistingLicenses(BanRecord record) {
        String reason = ruleReason(record.getType(), record.getValue(), record.getReason());
        switch (record.getType()) {
            case "CODE" -> {
                try {
                    licenseService.banLicense(record.getValue(), reason);
                } catch (BizException error) {
                    if (!error.getMessage().contains("已处于封禁状态")) {
                        throw error;
                    }
                }
            }
            case "QQ" -> banLicensesByQQ(record.getValue(), reason, record.getProgramId());
            case "IP" -> banLicensesContaining(
                    "ips", record.getValue(), reason, record.getProgramId());
            case "HWID" -> banLicensesContaining(
                    "hwids", record.getValue(), reason, record.getProgramId());
            default -> throw new IllegalStateException("Unsupported ban type");
        }
    }

    @SneakyThrows
    private void banLicensesByQQ(String qq, String reason, long programId) {
        Dao<License, Long> dao = accessor.getLicenseDao();
        UserContext ctx = UserContext.get();

        QueryBuilder<License, Long> qb = dao.queryBuilder();
        Where<License, Long> where = qb.where();
        where.eq("qq", qq);
        if (!ctx.isAdmin()) {
            where.and().eq("user_id", ctx.getUserId());
        }
        if (programId > 0) {
            where.and().eq("program_id", programId);
        }

        List<License> licenses = qb.query();
        dao.callBatchTasks(() -> {
            for (License license : licenses) {
                if (license.getStatus() != 1) {
                    continue;
                }
                license.setStatus(0);
                license.setBanReason(reason != null ? reason : "QQ " + qq + " 被封禁");
                license.setLastModifiedTime(TimeUtil.getCurtTime());
                dao.update(license);
            }
            return null;
        });
    }

    /**
     * 封禁所有包含指定 IP 或 HWID 的授权码
     */
    @SneakyThrows
    private void banLicensesContaining(String field, String value, String reason, long programId) {
        Dao<License, Long> dao = accessor.getLicenseDao();
        UserContext ctx = UserContext.get();

        // 使用 LIKE 查询包含该值的授权码
        QueryBuilder<License, Long> qb = dao.queryBuilder();
        Where<License, Long> where = qb.where();
        where.like(field, "%" + value + "%");
        if (!ctx.isAdmin()) {
            where.and().eq("user_id", ctx.getUserId());
        }
        if (programId > 0) {
            where.and().eq("program_id", programId);
        }

        List<License> licenses = qb.query();
        String banReason = reason != null ? reason : field.replace("s", "").toUpperCase() + " " + value + " 被封禁";
        dao.callBatchTasks(() -> {
            for (License license : licenses) {
                // 二次确认精确匹配（避免 LIKE 的模糊匹配误伤）
                boolean match = "ips".equals(field)
                        ? license.parseIps().contains(value)
                        : license.parseHwids().contains(value);
                if (match) {
                    if (license.getStatus() != 1) {
                        continue;
                    }
                    license.setStatus(0);
                    license.setBanReason(banReason);
                    license.setLastModifiedTime(TimeUtil.getCurtTime());
                    dao.update(license);
                }
            }
            return null;
        });
    }

    @SneakyThrows
    public PageResult<BanRecord> listBans(String type, int page, int pageSize) {
        UserContext ctx = UserContext.get();
        if (ctx == null) {
            throw BizException.unauthorized("Authentication is required");
        }
        if (type != null && !type.isBlank()) {
            type = type.trim().toUpperCase(Locale.ROOT);
            if (!BAN_TYPE_PATTERN.matcher(type).matches()) {
                throw new BizException("无效的封禁类型，支持: IP, HWID, QQ, CODE");
            }
        }
        Dao<BanRecord, Long> dao = accessor.getBanRecordDao();

        boolean hasType = type != null && !type.isBlank();
        boolean isAdmin = ctx.isAdmin();

        long total;
        List<BanRecord> records;

        if (!hasType && isAdmin) {
            total = dao.countOf();
            records = dao.queryBuilder()
                    .offset((long) (page - 1) * pageSize)
                    .limit((long) pageSize)
                    .orderBy("id", false)
                    .query();
        } else {
            QueryBuilder<BanRecord, Long> qb = dao.queryBuilder();
            Where<BanRecord, Long> where = qb.where();

            if (hasType && !isAdmin) {
                where.eq("type", type).and().eq("operator_id", ctx.getUserId());
            } else if (hasType) {
                where.eq("type", type);
            } else {
                where.eq("operator_id", ctx.getUserId());
            }

            total = qb.countOf();
            records = qb
                    .offset((long) (page - 1) * pageSize)
                    .limit((long) pageSize)
                    .orderBy("id", false)
                    .query();
        }

        return PageResult.of(records, total, page, pageSize);
    }

    @SneakyThrows
    public PageResult<BanRecord> listBansByProgram(long programId, int page, int pageSize) {
        UserContext ctx = UserContext.get();
        Program program = accessor.getProgramDao().queryForId(programId);
        if (program == null) {
            throw BizException.notFound("程序不存在");
        }
        if (ctx == null || (!ctx.isAdmin() && program.getUserId() != ctx.getUserId())) {
            throw BizException.forbidden("无权查看此程序的封禁记录");
        }
        Dao<BanRecord, Long> dao = accessor.getBanRecordDao();
        long total = dao.queryBuilder().where().eq("program_id", programId).countOf();
        List<BanRecord> records = dao.queryBuilder()
                .where().eq("program_id", programId)
                .queryBuilder()
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .orderBy("id", false)
                .query();
        return PageResult.of(records, total, page, pageSize);
    }

    public void deleteBan(long id) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            deleteBanLocked(id);
        }
    }

    @SneakyThrows
    private void deleteBanLocked(long id) {
        UserContext ctx = UserContext.get();
        Dao<BanRecord, Long> dao = accessor.getBanRecordDao();
        BanRecord record = dao.queryForId(id);
        if (record == null) {
            throw BizException.notFound("封禁记录不存在");
        }
        if (!ctx.isAdmin() && record.getOperatorId() != ctx.getUserId()) {
            throw BizException.forbidden("无权操作此封禁记录");
        }

        DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
            dao.deleteById(id);
            // Reconcile all rule-managed licenses so overlapping rules do not
            // leave a permanent status=0 after one rule is removed.
            restoreRuleManagedLicenses();
            return null;
        });
    }

    /** Restores rule-managed licenses that are no longer covered by any rule. */
    @SneakyThrows
    private void restoreRuleManagedLicenses() {
        Dao<License, Long> licenseDao = accessor.getLicenseDao();
        List<License> affected = licenseDao.queryBuilder()
                .where().eq("status", 0)
                .and().like("ban_reason", RULE_MARKER_PREFIX + "%")
                .query();

        for (License license : affected) {
            if (checkBanned(license, null, null) != null) {
                continue;
            }
            license.setStatus(1);
            license.setBanReason(null);
            license.setLastModifiedTime(TimeUtil.getCurtTime());
            licenseDao.update(license);
        }

    }

    private static String ruleMarker(String type, String value) {
        return RULE_MARKER_PREFIX + type.toUpperCase(Locale.ROOT) + "=" + value + "]";
    }

    /**
     * Marks expired rules inactive and reconciles the licenses they previously
     * affected. The operation is serialized with native authorization release.
     */
    public int expireDueBans() {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            try {
                return DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                    String now = TimeUtil.getCurtTime();
                    List<BanRecord> due = accessor.getBanRecordDao().queryBuilder()
                            .where().eq("status", 1)
                            .and().isNotNull("expiration_date")
                            .and().le("expiration_date", now)
                            .query();
                    if (due.isEmpty()) {
                        return 0;
                    }
                    for (BanRecord record : due) {
                        record.setStatus(0);
                        accessor.getBanRecordDao().update(record);
                    }
                    restoreRuleManagedLicenses();
                    return due.size();
                });
            } catch (java.sql.SQLException error) {
                throw new IllegalStateException("Unable to expire ban rules", error);
            }
        }
    }

    private static String normalizeBanValue(String type, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("封禁值不能为空");
        }
        String normalized = value.trim();
        return switch (type) {
            case "IP" -> {
                try {
                    yield NativeIdentifierValidator.normalizeIpLiteral(normalized);
                } catch (IllegalArgumentException error) {
                    throw new IllegalArgumentException("IP封禁值必须是合法的IPv4或IPv6地址");
                }
            }
            case "HWID" -> {
                if (!NativeIdentifierValidator.isValidHwid(normalized)) {
                    throw new IllegalArgumentException("HWID封禁值必须是有效的32字节Base64机器码");
                }
                yield normalized;
            }
            case "QQ" -> {
                if (!NativeIdentifierValidator.isValidQq(normalized)) {
                    throw new IllegalArgumentException("QQ封禁值必须是1-20位数字");
                }
                yield normalized;
            }
            case "CODE" -> {
                if (!NativeIdentifierValidator.isValidLicenseCode(normalized)) {
                    throw new IllegalArgumentException(
                            "许可证封禁值只能包含字母、数字、点、下划线、加号和连字符，长度1-256");
                }
                yield normalized;
            }
            default -> throw new IllegalArgumentException("无效的封禁类型");
        };
    }

    private static String ruleReason(String type, String value, String reason) {
        String detail = reason == null || reason.isBlank() ? "rule matched" : reason;
        return ruleMarker(type, value) + " " + detail;
    }

    private static String normalizeExpirationDate(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        try {
            LocalDateTime expiration = LocalDateTime.parse(normalized, DATE_TIME_FORMAT);
            if (!expiration.isAfter(LocalDateTime.now())) {
                throw new BizException("封禁到期时间必须晚于当前时间");
            }
            return normalized;
        } catch (DateTimeParseException error) {
            throw new BizException("封禁到期时间格式必须为 yyyy-MM-dd-HH:mm");
        }
    }

    private static String normalizeReason(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > 1_024) {
            throw new BizException("封禁原因不能超过1024个字符");
        }
        return normalized;
    }
}

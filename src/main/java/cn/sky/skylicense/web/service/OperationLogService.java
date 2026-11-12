package cn.sky.skylicense.web.service;

import cn.sky.skylicense.security.SecretSource;
import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.DatabaseTransactions;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.dto.response.OperationIntegrityResponse;
import cn.sky.skylicense.web.dto.response.OperationLogView;
import cn.sky.skylicense.web.entity.OperationLog;
import cn.sky.skylicense.web.entity.OperationLogState;
import cn.sky.skylicense.web.entity.SystemMetadata;
import cn.sky.skylicense.web.security.UserContext;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.GenericRawResults;
import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.stmt.UpdateBuilder;
import lombok.SneakyThrows;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * Persists privacy-preserving operation events and maintains a verifiable MAC
 * chain. Chain fields are immutable; completion updates only the row MAC, so
 * concurrent audit attempts cannot invalidate one another.
 */
@Service
public final class OperationLogService {
    public static final String MAX_ROWS_ENV = "SKYLICENSE_OPERATION_LOG_MAX_ROWS";

    private static final Logger LOG = LogManager.getLogger(OperationLogService.class);
    private static final Gson GSON = new Gson();
    private static final int DEFAULT_MAX_ROWS = 500_000;
    private static final int MIN_MAX_ROWS = 10_000;
    private static final int MAX_MAX_ROWS = 10_000_000;
    private static final int DEFAULT_PRUNE_INTERVAL = 256;
    private static final int CHAIN_STATE_ID = 1;
    private static final String GENESIS_MAC = "0".repeat(64);
    private static final String CHAIN_MAC_DOMAIN = "SkyLicense operation audit chain v1";
    private static final String ROW_MAC_DOMAIN = "SkyLicense operation audit row v1";
    private static final String STATE_MAC_DOMAIN = "SkyLicense operation audit state v1";
    private static final String USERNAME_REFERENCE_MIGRATION_KEY =
            "operation-log-username-ref-v1";
    private static final String IP_REFERENCE_MIGRATION_KEY =
            "operation-log-ip-ref-v1";
    private static final int MAX_LEGACY_IDENTIFIER_VALUES = 100_000;
    private static final Pattern VERSIONED_REFERENCE =
            Pattern.compile("ref:(?:v1:)?[0-9a-f]{64}");
    private static final Pattern MAC_PATTERN = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern EVENT_ID_PATTERN =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
    private static final Set<String> VALID_OUTCOMES =
            Set.of("ATTEMPT", "SUCCESS", "REJECTED", "LEGACY");
    private static final int MAX_AUDIT_LIMIT_KEYS = 50_000;
    private static final Duration AUDIT_REJECTION_WINDOW = Duration.ofMinutes(1);
    private static final DateTimeFormatter LEGACY_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd-HH:mm");

    private final WebDataAccessor accessor;
    private final OperationLogSanitizer sanitizer;
    private final int maximumRows;
    private final int pruneInterval;
    private int writesSincePrune;
    private final AtomicBoolean auditHealthy = new AtomicBoolean(true);
    private final LoginAttemptLimiter rejectionAuditLimiter = new LoginAttemptLimiter(
            MAX_AUDIT_LIMIT_KEYS, 1, AUDIT_REJECTION_WINDOW);

    @Autowired
    public OperationLogService(
            WebDataAccessor accessor,
            OperationLogSanitizer sanitizer
    ) {
        this(accessor, sanitizer, maximumRowsFromEnvironment(), DEFAULT_PRUNE_INTERVAL);
    }

    OperationLogService(
            WebDataAccessor accessor,
            OperationLogSanitizer sanitizer,
            int maximumRows,
            int pruneInterval
    ) {
        if (maximumRows <= 0 || pruneInterval <= 0) {
            throw new IllegalArgumentException("operation-log retention settings must be positive");
        }
        this.accessor = accessor;
        this.sanitizer = sanitizer;
        this.maximumRows = maximumRows;
        this.pruneInterval = pruneInterval;
        migrateLegacyIdentifierColumns();
        initializeOrVerifyIntegrity();
        pruneOperationLogs();
        verifyIntegrity();
    }

    public static void validateEnvironment() {
        maximumRowsFromEnvironment();
    }

    static int parseMaximumRows(String value) {
        if (value == null || value.isBlank()) {
            return DEFAULT_MAX_ROWS;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < MIN_MAX_ROWS || parsed > MAX_MAX_ROWS) {
                throw new IllegalStateException(
                        MAX_ROWS_ENV + " must be between " + MIN_MAX_ROWS + " and " + MAX_MAX_ROWS);
            }
            return parsed;
        } catch (NumberFormatException error) {
            throw new IllegalStateException(MAX_ROWS_ENV + " must be a decimal integer", error);
        }
    }

    private static int maximumRowsFromEnvironment() {
        return parseMaximumRows(SecretSource.readOptional(MAX_ROWS_ENV, 32));
    }

    private void migrateLegacyIdentifierColumns() {
        try {
            TransactionManager.callInTransaction(accessor.getConnectionSource(), () -> {
                Dao<OperationLog, Long> dao = accessor.getOperationLogDao();
                migrateLegacyColumn(
                        dao, "username", "anonymous", USERNAME_REFERENCE_MIGRATION_KEY);
                migrateLegacyColumn(dao, "ip", "unknown", IP_REFERENCE_MIGRATION_KEY);
                return null;
            });
        } catch (Exception error) {
            throw new IllegalStateException(
                    "Unable to migrate operation-log identifiers to references", error);
        }
    }

    private void migrateLegacyColumn(
            Dao<OperationLog, Long> dao,
            String column,
            String preservedLiteral,
            String migrationKey
    ) throws Exception {
        if (accessor.getSystemMetadataDao().queryForId(migrationKey) != null) {
            return;
        }
        List<String> legacyValues = new ArrayList<>();
        GenericRawResults<String[]> raw = dao.queryRaw(
                "SELECT DISTINCT " + column + " FROM operation_log "
                        + "WHERE " + column + " IS NOT NULL AND " + column + " <> '"
                        + preservedLiteral + "' LIMIT " + (MAX_LEGACY_IDENTIFIER_VALUES + 1));
        try {
            for (String[] row : raw) {
                if (row.length == 0 || row[0] == null
                        || VERSIONED_REFERENCE.matcher(row[0]).matches()) {
                    continue;
                }
                legacyValues.add(row[0]);
                if (legacyValues.size() > MAX_LEGACY_IDENTIFIER_VALUES) {
                    throw new IllegalStateException(
                            "too many legacy operation-log identifiers to migrate safely");
                }
            }
        } finally {
            try {
                raw.close();
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw error;
            }
        }

        for (String legacyValue : legacyValues) {
            UpdateBuilder<OperationLog, Long> update = dao.updateBuilder();
            update.updateColumnValue(column, sanitizer.reference(legacyValue));
            update.where().eq(column, legacyValue);
            update.update();
        }
        accessor.getSystemMetadataDao().createOrUpdate(SystemMetadata.builder()
                .key(migrationKey)
                .value(Integer.toString(legacyValues.size()))
                .build());
    }

    @SneakyThrows
    public long log(String action, String target, String detail, String ip) {
        UserContext ctx = UserContext.get();
        if (ctx == null) {
            return 0L;
        }
        return persist(
                ctx.getUserId(), ctx.getUsername(), action, target, detail, ip, "ATTEMPT");
    }

    /** Records a login attempt before a browser session exists. */
    @SneakyThrows
    public long logAnonymous(
            String action,
            String target,
            String detail,
            String ip,
            boolean rateLimited
    ) {
        if (rateLimited && !acquireRejectionAudit("anonymous:" + action, ip)) {
            return -1L;
        }
        return persist(0L, "anonymous", action, target, detail, ip, "ATTEMPT");
    }

    /** Records a high-signal filter rejection without retaining request credentials. */
    @SneakyThrows
    public void logSecurityRejection(
            UserContext actor,
            String reason,
            String method,
            String ip
    ) {
        String actorKey = actor == null ? "anonymous" : Long.toString(actor.getUserId());
        if (!acquireRejectionAudit("web:" + actorKey + ':' + reason, ip)) {
            return;
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("outcome", "REJECTED");
        detail.put("reason", reason);
        detail.put("method", method);
        String serialized = sanitizer.serialize(detail);
        if (actor == null) {
            persist(
                    0L,
                    "anonymous",
                    "WEB_SECURITY_REJECT",
                    "web_security",
                    serialized,
                    ip,
                    "REJECTED");
        } else {
            persist(
                    actor.getUserId(),
                    actor.getUsername(),
                    "WEB_SECURITY_REJECT",
                    "web_security",
                    serialized,
                    ip,
                    "REJECTED");
        }
    }

    public boolean isHealthy() {
        return auditHealthy.get();
    }

    public void markUnhealthy() {
        auditHealthy.set(false);
    }

    /** Compatibility overload for callers that still carry outcome in detail JSON. */
    public void complete(long auditId, String detail) {
        complete(auditId, outcomeFromDetail(detail, "REJECTED"), detail);
    }

    /** Completes an ATTEMPT row without modifying its immutable chain link. */
    @SneakyThrows
    public synchronized void complete(long auditId, String outcome, String detail) {
        if (auditId <= 0) {
            return;
        }
        requireCompletionOutcome(outcome);
        try {
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                OperationLog log = accessor.getOperationLogDao().queryForId(auditId);
                if (log == null) {
                    throw new SQLException("operation audit attempt row is missing");
                }
                verifyRowIntegrity(log);
                if (!"ATTEMPT".equals(log.getOutcome())) {
                    throw new SQLException("operation audit event is already complete");
                }
                long completedAt = System.currentTimeMillis();
                log.setOutcome(outcome);
                log.setDetail(detail);
                log.setCompletedAtMillis(completedAt);
                log.setTimestamp(utcTimestamp(completedAt));
                log.setIntegrityMac(rowMac(log));
                if (accessor.getOperationLogDao().update(log) != 1) {
                    throw new SQLException("operation audit attempt row is missing");
                }
                return null;
            });
            auditHealthy.set(true);
        } catch (RuntimeException | Error error) {
            auditHealthy.set(false);
            throw error;
        } catch (Exception error) {
            auditHealthy.set(false);
            throw error;
        }
    }

    private static void requireCompletionOutcome(String outcome) {
        if (!"SUCCESS".equals(outcome) && !"REJECTED".equals(outcome)) {
            throw new IllegalArgumentException("audit completion outcome must be SUCCESS or REJECTED");
        }
    }

    private boolean acquireRejectionAudit(String scope, String ip) {
        String addressReference = "unknown".equals(ip) ? ip : sanitizer.reference(ip);
        String key = scope + ':' + addressReference;
        if (rejectionAuditLimiter.retryAfterSeconds(key) > 0) {
            return false;
        }
        return rejectionAuditLimiter.recordFailure(key);
    }

    @SneakyThrows
    private synchronized long persist(
            long userId,
            String username,
            String action,
            String target,
            String detail,
            String ip,
            String outcome
    ) {
        long occurredAt = System.currentTimeMillis();
        OperationLog log = OperationLog.builder()
                .userId(userId)
                .username("anonymous".equals(username) || username == null
                        ? username
                        : sanitizer.reference(username))
                .action(action)
                .target(target)
                .detail(detail)
                .ip("unknown".equals(ip) ? ip : sanitizer.reference(ip))
                .timestamp(utcTimestamp(occurredAt))
                .eventId(UUID.randomUUID().toString())
                .outcome(outcome)
                .occurredAtMillis(occurredAt)
                .completedAtMillis("ATTEMPT".equals(outcome) ? null : occurredAt)
                .build();

        try {
            long auditId = DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                OperationLogState state = requireValidChainHead();
                log.setChainPreviousMac(state.getHeadMac());
                accessor.getOperationLogDao().create(log);
                log.setChainMac(chainMac(log));
                log.setIntegrityMac(rowMac(log));
                if (accessor.getOperationLogDao().update(log) != 1) {
                    throw new SQLException("unable to finalize operation audit row");
                }

                state.setHeadId(log.getId());
                state.setHeadMac(log.getChainMac());
                state.setRowCount(Math.addExact(state.getRowCount(), 1L));
                persistState(state, occurredAt);

                writesSincePrune++;
                if (writesSincePrune >= pruneInterval) {
                    pruneOperationLogsInCurrentTransaction(state);
                    writesSincePrune = 0;
                }
                return log.getId();
            });
            auditHealthy.set(true);
            return auditId;
        } catch (RuntimeException | Error error) {
            auditHealthy.set(false);
            throw error;
        } catch (Exception error) {
            auditHealthy.set(false);
            throw error;
        }
    }

    private synchronized void initializeOrVerifyIntegrity() {
        try {
            DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
                OperationLogState state = accessor.getOperationLogStateDao()
                        .queryForId(CHAIN_STATE_ID);
                if (state == null) {
                    if (!accessor.isOperationAuditMigrationPending()) {
                        throw new SQLException(
                                "operation audit checkpoint is missing outside a schema migration");
                    }
                    backfillLegacyIntegrity();
                } else {
                    verifyIntegrityInCurrentTransaction();
                }
                accessor.getOperationLogDao().executeRaw(
                        "CREATE UNIQUE INDEX IF NOT EXISTS operation_log_event_id_uidx "
                                + "ON operation_log(event_id)");
                return null;
            });
            // Clear the one-process migration permit only after the transaction
            // manager has committed the authenticated checkpoint and unique index.
            accessor.markOperationAuditMigrationComplete();
            auditHealthy.set(true);
        } catch (Exception error) {
            auditHealthy.set(false);
            throw new IllegalStateException(
                    "Operation audit integrity initialization failed", error);
        }
    }

    private void backfillLegacyIntegrity() throws SQLException {
        Dao<OperationLog, Long> dao = accessor.getOperationLogDao();
        List<OperationLog> rows = dao.queryBuilder().orderBy("id", true).query();
        String previousMac = GENESIS_MAC;
        long headId = 0L;
        for (OperationLog row : rows) {
            row.setEventId(UUID.randomUUID().toString());
            row.setOutcome(outcomeFromDetail(row.getDetail(), "LEGACY"));
            long occurredAt = legacyEpochMillis(row.getTimestamp());
            row.setOccurredAtMillis(occurredAt);
            row.setCompletedAtMillis(
                    "ATTEMPT".equals(row.getOutcome()) ? null : occurredAt);
            row.setTimestamp(utcTimestamp(occurredAt));
            row.setChainPreviousMac(previousMac);
            row.setChainMac(chainMac(row));
            row.setIntegrityMac(rowMac(row));
            if (dao.update(row) != 1) {
                throw new SQLException("unable to backfill operation audit row " + row.getId());
            }
            previousMac = row.getChainMac();
            headId = row.getId();
        }

        OperationLogState state = OperationLogState.builder()
                .singletonId(CHAIN_STATE_ID)
                .anchorId(0L)
                .anchorMac(GENESIS_MAC)
                .headId(headId)
                .headMac(previousMac)
                .rowCount(rows.size())
                .build();
        persistState(state, System.currentTimeMillis());
        LOG.info("Initialized authenticated operation-audit chain for {} rows", rows.size());
    }

    /** Performs a full retained-chain verification and returns an exportable checkpoint. */
    @SneakyThrows
    public synchronized AuditIntegrityReport verifyIntegrity() {
        try {
            AuditIntegrityReport report = DatabaseTransactions.call(
                    accessor.getConnectionSource(), this::verifyIntegrityInCurrentTransaction);
            auditHealthy.set(true);
            return report;
        } catch (RuntimeException | Error error) {
            auditHealthy.set(false);
            throw error;
        } catch (Exception error) {
            auditHealthy.set(false);
            throw error;
        }
    }

    private AuditIntegrityReport verifyIntegrityInCurrentTransaction() throws SQLException {
        OperationLogState state = accessor.getOperationLogStateDao().queryForId(CHAIN_STATE_ID);
        verifyStateIntegrity(state);

        List<OperationLog> rows = accessor.getOperationLogDao()
                .queryBuilder().orderBy("id", true).query();
        String previousMac = state.getAnchorMac();
        long previousId = state.getAnchorId();
        long count = 0L;
        Set<String> eventIds = new HashSet<>();
        for (OperationLog row : rows) {
            if (row.getId() <= previousId) {
                throw new SQLException("operation audit ids are not strictly increasing");
            }
            if (!Objects.equals(previousMac, row.getChainPreviousMac())) {
                throw new SQLException(
                        "operation audit chain predecessor mismatch at row " + row.getId());
            }
            verifyRowIntegrity(row);
            if (!eventIds.add(row.getEventId())) {
                throw new SQLException(
                        "operation audit event id is duplicated at row " + row.getId());
            }
            previousMac = row.getChainMac();
            previousId = row.getId();
            count++;
        }

        long expectedHeadId = count == 0 ? state.getAnchorId() : previousId;
        String expectedHeadMac = count == 0 ? state.getAnchorMac() : previousMac;
        if (count != state.getRowCount()
                || state.getHeadId() != expectedHeadId
                || !Objects.equals(state.getHeadMac(), expectedHeadMac)) {
            throw new SQLException("operation audit checkpoint does not match retained rows");
        }
        return new AuditIntegrityReport(
                true,
                count,
                state.getAnchorId(),
                state.getHeadId(),
                state.getHeadMac(),
                System.currentTimeMillis());
    }

    private OperationLogState requireValidChainHead() throws SQLException {
        OperationLogState state = accessor.getOperationLogStateDao().queryForId(CHAIN_STATE_ID);
        verifyStateIntegrity(state);
        if (state.getRowCount() == 0) {
            if (state.getHeadId() != state.getAnchorId()
                    || !Objects.equals(state.getHeadMac(), state.getAnchorMac())) {
                throw new SQLException("empty operation audit checkpoint is inconsistent");
            }
            return state;
        }
        OperationLog head = accessor.getOperationLogDao().queryForId(state.getHeadId());
        if (head == null || !Objects.equals(head.getChainMac(), state.getHeadMac())) {
            throw new SQLException("operation audit head row is missing or mismatched");
        }
        verifyRowIntegrity(head);
        return state;
    }

    private void verifyRowIntegrity(OperationLog row) throws SQLException {
        requireEventShape(row);
        String expectedChainMac = chainMac(row);
        if (!Objects.equals(expectedChainMac, row.getChainMac())) {
            throw new SQLException("operation audit chain MAC mismatch at row " + row.getId());
        }
        byte[] payload = rowPayload(row);
        try {
            if (!sanitizer.matchesAuditMac(ROW_MAC_DOMAIN, payload, row.getIntegrityMac())) {
                throw new SQLException(
                        "operation audit row integrity mismatch at row " + row.getId());
            }
        } finally {
            java.util.Arrays.fill(payload, (byte) 0);
        }
    }

    private void verifyStateIntegrity(OperationLogState state) throws SQLException {
        if (state == null
                || state.getSingletonId() != CHAIN_STATE_ID
                || state.getAnchorId() < 0
                || state.getHeadId() < state.getAnchorId()
                || state.getRowCount() < 0
                || state.getUpdatedAtMillis() < 0
                || !isMac(state.getAnchorMac())
                || !isMac(state.getHeadMac())
                || !isMac(state.getStateMac())) {
            throw new SQLException("operation audit checkpoint is missing or malformed");
        }
        if ((state.getRowCount() == 0 && state.getHeadId() != state.getAnchorId())
                || (state.getRowCount() > 0 && state.getHeadId() <= state.getAnchorId())) {
            throw new SQLException("operation audit checkpoint shape is inconsistent");
        }
        byte[] payload = statePayload(state);
        try {
            if (!sanitizer.matchesAuditMac(STATE_MAC_DOMAIN, payload, state.getStateMac())) {
                throw new SQLException("operation audit checkpoint integrity mismatch");
            }
        } finally {
            java.util.Arrays.fill(payload, (byte) 0);
        }
    }

    static void requireEventShape(OperationLog row) throws SQLException {
        if (row == null
                || row.getId() <= 0
                || row.getEventId() == null
                || !EVENT_ID_PATTERN.matcher(row.getEventId()).matches()
                || !VALID_OUTCOMES.contains(row.getOutcome())
                || row.getOccurredAtMillis() < 0
                || !isMac(row.getChainPreviousMac())
                || !isMac(row.getChainMac())
                || !isMac(row.getIntegrityMac())) {
            throw new SQLException("operation audit row is missing integrity fields");
        }

        Long completedAt = row.getCompletedAtMillis();
        switch (row.getOutcome()) {
            case "ATTEMPT" -> {
                if (completedAt != null) {
                    throw new SQLException("open operation audit attempt has a completion time");
                }
            }
            case "SUCCESS", "REJECTED" -> {
                if (completedAt == null || completedAt < row.getOccurredAtMillis()) {
                    throw new SQLException(
                            "completed operation audit event has an invalid completion time");
                }
            }
            case "LEGACY" -> {
                if (completedAt != null && completedAt < row.getOccurredAtMillis()) {
                    throw new SQLException(
                            "legacy operation audit event has an invalid completion time");
                }
            }
            default -> throw new SQLException("operation audit outcome is not supported");
        }

        long displayedAt = completedAt == null ? row.getOccurredAtMillis() : completedAt;
        if (!Objects.equals(row.getTimestamp(), utcTimestamp(displayedAt))) {
            throw new SQLException("operation audit UTC timestamp is inconsistent");
        }
        if (!"LEGACY".equals(row.getOutcome()) && row.getOccurredAtMillis() == 0L) {
            throw new SQLException("operation audit event start time is invalid");
        }
    }

    private String chainMac(OperationLog row) {
        byte[] payload = chainPayload(row);
        try {
            return sanitizer.auditMac(CHAIN_MAC_DOMAIN, payload);
        } finally {
            java.util.Arrays.fill(payload, (byte) 0);
        }
    }

    private String rowMac(OperationLog row) {
        byte[] payload = rowPayload(row);
        try {
            return sanitizer.auditMac(ROW_MAC_DOMAIN, payload);
        } finally {
            java.util.Arrays.fill(payload, (byte) 0);
        }
    }

    private String stateMac(OperationLogState state) {
        byte[] payload = statePayload(state);
        try {
            return sanitizer.auditMac(STATE_MAC_DOMAIN, payload);
        } finally {
            java.util.Arrays.fill(payload, (byte) 0);
        }
    }

    private static byte[] chainPayload(OperationLog row) {
        return canonical(output -> {
            writeString(output, row.getChainPreviousMac());
            output.writeLong(row.getId());
            writeString(output, row.getEventId());
            output.writeLong(row.getUserId());
            writeString(output, row.getUsername());
            writeString(output, row.getAction());
            writeString(output, row.getTarget());
            writeString(output, row.getIp());
            output.writeLong(row.getOccurredAtMillis());
        });
    }

    private static byte[] rowPayload(OperationLog row) {
        return canonical(output -> {
            output.writeLong(row.getId());
            writeString(output, row.getEventId());
            output.writeLong(row.getUserId());
            writeString(output, row.getUsername());
            writeString(output, row.getAction());
            writeString(output, row.getTarget());
            writeString(output, row.getDetail());
            writeString(output, row.getIp());
            writeString(output, row.getTimestamp());
            writeString(output, row.getOutcome());
            output.writeLong(row.getOccurredAtMillis());
            writeNullableLong(output, row.getCompletedAtMillis());
            writeString(output, row.getChainPreviousMac());
            writeString(output, row.getChainMac());
        });
    }

    private static byte[] statePayload(OperationLogState state) {
        return canonical(output -> {
            output.writeInt(state.getSingletonId());
            output.writeLong(state.getAnchorId());
            writeString(output, state.getAnchorMac());
            output.writeLong(state.getHeadId());
            writeString(output, state.getHeadMac());
            output.writeLong(state.getRowCount());
            output.writeLong(state.getUpdatedAtMillis());
        });
    }

    private void persistState(OperationLogState state, long updatedAtMillis) throws SQLException {
        state.setUpdatedAtMillis(updatedAtMillis);
        state.setStateMac(stateMac(state));
        accessor.getOperationLogStateDao().createOrUpdate(state);
    }

    @SneakyThrows
    private synchronized void pruneOperationLogs() {
        DatabaseTransactions.call(accessor.getConnectionSource(), () -> {
            OperationLogState state = requireValidChainHead();
            pruneOperationLogsInCurrentTransaction(state);
            writesSincePrune = 0;
            return null;
        });
    }

    private void pruneOperationLogsInCurrentTransaction(OperationLogState state)
            throws SQLException {
        if (state.getRowCount() <= maximumRows) {
            return;
        }
        OperationLog newAnchor = accessor.getOperationLogDao().queryBuilder()
                .orderBy("id", false)
                .offset((long) maximumRows)
                .limit(1L)
                .queryForFirst();
        if (newAnchor == null) {
            throw new SQLException("unable to locate operation audit retention anchor");
        }
        verifyRowIntegrity(newAnchor);
        int deleted = accessor.getOperationLogDao().executeRaw(
                "DELETE FROM operation_log WHERE id <= " + newAnchor.getId());
        if (deleted <= 0 || deleted > state.getRowCount()) {
            throw new SQLException("operation audit retention deleted an invalid row count");
        }
        state.setAnchorId(newAnchor.getId());
        state.setAnchorMac(newAnchor.getChainMac());
        state.setRowCount(state.getRowCount() - deleted);
        persistState(state, System.currentTimeMillis());
        LOG.warn(
                "Pruned {} operation-log rows above the configured retention limit {}",
                deleted,
                maximumRows);
    }

    private static String outcomeFromDetail(String detail, String fallback) {
        if (detail == null || detail.isBlank()) {
            return fallback;
        }
        try {
            JsonElement parsed = GSON.fromJson(detail, JsonElement.class);
            if (parsed != null && parsed.isJsonObject()) {
                JsonObject object = parsed.getAsJsonObject();
                JsonElement outcome = object.get("outcome");
                if (outcome != null && outcome.isJsonPrimitive()
                        && outcome.getAsJsonPrimitive().isString()) {
                    String value = outcome.getAsString();
                    if ("ATTEMPT".equals(value)
                            || "SUCCESS".equals(value)
                            || "REJECTED".equals(value)) {
                        return value;
                    }
                }
            }
        } catch (RuntimeException ignored) {
            // Preserve malformed historical detail and mark its explicit outcome as LEGACY.
        }
        return fallback;
    }

    private static long legacyEpochMillis(String timestamp) {
        if (timestamp == null || timestamp.isBlank()) {
            return 0L;
        }
        try {
            return Instant.parse(timestamp).toEpochMilli();
        } catch (DateTimeParseException ignored) {
            try {
                return LocalDateTime.parse(timestamp, LEGACY_TIME)
                        .atZone(ZoneId.systemDefault())
                        .toInstant()
                        .toEpochMilli();
            } catch (DateTimeParseException invalidLegacyTimestamp) {
                return 0L;
            }
        }
    }

    private static String utcTimestamp(long epochMillis) {
        return Instant.ofEpochMilli(epochMillis).toString();
    }

    private static boolean isMac(String value) {
        return value != null && MAC_PATTERN.matcher(value).matches();
    }

    private static byte[] canonical(CanonicalWriter writer) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(512);
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                writer.write(output);
                output.flush();
                return bytes.toByteArray();
            }
        } catch (IOException error) {
            throw new IllegalStateException("unable to canonicalize operation audit data", error);
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        if (value == null) {
            output.writeInt(-1);
            return;
        }
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            output.writeInt(encoded.length);
            output.write(encoded);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    private static void writeNullableLong(DataOutputStream output, Long value) throws IOException {
        output.writeBoolean(value != null);
        if (value != null) {
            output.writeLong(value);
        }
    }

    @SneakyThrows
    public PageResult<OperationLogView> listByUser(long userId, int page, int pageSize) {
        Dao<OperationLog, Long> dao = accessor.getOperationLogDao();
        long total = dao.queryBuilder().where().eq("user_id", userId).countOf();
        List<OperationLog> logs = dao.queryBuilder()
                .where().eq("user_id", userId)
                .queryBuilder()
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .orderBy("id", false)
                .query();
        return PageResult.of(logs.stream().map(OperationLogView::from).toList(), total, page, pageSize);
    }

    @SneakyThrows
    public PageResult<OperationLogView> listAll(int page, int pageSize) {
        Dao<OperationLog, Long> dao = accessor.getOperationLogDao();
        long total = dao.countOf();
        List<OperationLog> logs = dao.queryBuilder()
                .offset((long) (page - 1) * pageSize)
                .limit((long) pageSize)
                .orderBy("id", false)
                .query();
        return PageResult.of(logs.stream().map(OperationLogView::from).toList(), total, page, pageSize);
    }

    /** Runs the expensive full-chain check on demand without disclosing MACs or SQL details. */
    public OperationIntegrityResponse integrityStatus() {
        long checkedAt = System.currentTimeMillis();
        try {
            AuditIntegrityReport report = verifyIntegrity();
            return new OperationIntegrityResponse(
                    true,
                    report.rowCount(),
                    report.anchorId(),
                    report.headId(),
                    report.checkedAtMillis(),
                    "VERIFIED");
        } catch (Exception error) {
            LOG.error("Administrator operation-audit integrity check failed", error);
            return OperationIntegrityResponse.failed(checkedAt);
        }
    }

    public record AuditIntegrityReport(
            boolean verified,
            long rowCount,
            long anchorId,
            long headId,
            String headMac,
            long checkedAtMillis
    ) {
    }

    @FunctionalInterface
    private interface CanonicalWriter {
        void write(DataOutputStream output) throws IOException;
    }
}

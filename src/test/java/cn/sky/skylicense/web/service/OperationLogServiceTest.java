package cn.sky.skylicense.web.service;

import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.OperationLog;
import cn.sky.skylicense.web.entity.OperationLogState;
import cn.sky.skylicense.web.entity.SystemMetadata;
import cn.sky.skylicense.web.security.UserContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OperationLogServiceTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void storesOnlyAnIrreversiblePeerAddressReference() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("operations.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            String peerAddress = "203.0.113.10";
            new OperationLogService(accessor, sanitizer)
                    .log("TEST", "target", "{}", peerAddress);

            OperationLog stored = accessor.getOperationLogDao().queryForAll().get(0);
            assertEquals(sanitizer.reference(peerAddress), stored.getIp());
            assertEquals(sanitizer.reference("admin"), stored.getUsername());
            assertFalse(stored.getUsername().contains("admin"));
            assertFalse(stored.getIp().contains(peerAddress));
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    @Test
    void securityRejectionUsesTheActorAndSanitizesThePeerAddress() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("security-rejection.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 8);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            UserContext actor = new UserContext(7, "admin", "ADMIN", "csrf");
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            service.logSecurityRejection(actor, "CSRF_REJECTED", "POST", "198.51.100.8");
            service.logSecurityRejection(actor, "CSRF_REJECTED", "POST", "198.51.100.8");

            OperationLog stored = accessor.getOperationLogDao().queryForAll().get(0);
            assertEquals(1, accessor.getOperationLogDao().countOf());
            assertEquals(7L, stored.getUserId());
            assertEquals("WEB_SECURITY_REJECT", stored.getAction());
            assertTrue(stored.getDetail().contains("CSRF_REJECTED"));
            assertTrue(stored.getDetail().contains("\"outcome\":\"REJECTED\""));
            assertFalse(stored.getIp().contains("198.51.100.8"));
        } finally {
            accessor.close();
        }
    }

    @Test
    void migratesLegacyPlaintextUsernamesBeforeWritingNewAuditRows() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("legacy-usernames.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 9);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            accessor.getOperationLogDao().create(OperationLog.builder()
                    .userId(12)
                    .username("legacy-admin")
                    .action("OLD")
                    .target("user")
                    .detail("{}")
                    .ip("198.51.100.77")
                    .timestamp("2026-01-01-00:00")
                    .build());

            new OperationLogService(accessor, sanitizer);

            OperationLog stored = accessor.getOperationLogDao().queryForAll().get(0);
            assertEquals(sanitizer.reference("legacy-admin"), stored.getUsername());
            assertEquals(sanitizer.reference("198.51.100.77"), stored.getIp());
            assertFalse(stored.getUsername().contains("legacy-admin"));
            SystemMetadata marker = accessor.getSystemMetadataDao()
                    .queryForId("operation-log-username-ref-v1");
            assertEquals("1", marker.getValue());
            assertEquals("1", accessor.getSystemMetadataDao()
                    .queryForId("operation-log-ip-ref-v1").getValue());
        } finally {
            accessor.close();
        }
    }

    @Test
    void retentionKeepsOnlyTheNewestConfiguredRows() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("retention.db").toString());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 10);
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer, 3, 1);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            for (int index = 1; index <= 5; index++) {
                service.log("TEST-" + index, "target", "{}", "203.0.113.10");
            }

            java.util.List<OperationLog> stored = accessor.getOperationLogDao()
                    .queryBuilder().orderBy("id", true).query();
            assertEquals(3, stored.size());
            assertEquals("TEST-3", stored.get(0).getAction());
            assertEquals("TEST-5", stored.get(2).getAction());
            OperationLogService.AuditIntegrityReport report = service.verifyIntegrity();
            assertTrue(report.verified());
            assertEquals(3L, report.rowCount());
            assertTrue(report.anchorId() > 0L);
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    @Test
    void productionRetentionBoundaryRejectsInvalidEnvironmentValues() {
        assertEquals(500_000, OperationLogService.parseMaximumRows(null));
        assertEquals(10_000, OperationLogService.parseMaximumRows("10000"));
        assertEquals(10_000, OperationLogService.parseMaximumRows(" 10000 "));
        assertThrows(IllegalStateException.class,
                () -> OperationLogService.parseMaximumRows("9999"));
        assertThrows(IllegalStateException.class,
                () -> OperationLogService.parseMaximumRows("not-a-number"));
    }

    @Test
    void eventShapeRejectsUnknownOutcomesAndInconsistentTimes() {
        long occurredAt = 1_800_000_000_000L;
        OperationLog attempt = shapedLog("ATTEMPT", occurredAt, null, occurredAt);
        assertDoesNotThrow(() -> OperationLogService.requireEventShape(attempt));

        attempt.setOutcome("UNKNOWN");
        assertThrows(Exception.class, () -> OperationLogService.requireEventShape(attempt));

        OperationLog completed = shapedLog(
                "SUCCESS", occurredAt, occurredAt + 100L, occurredAt + 100L);
        assertDoesNotThrow(() -> OperationLogService.requireEventShape(completed));

        completed.setCompletedAtMillis(null);
        assertThrows(Exception.class, () -> OperationLogService.requireEventShape(completed));
        completed.setCompletedAtMillis(occurredAt - 1L);
        assertThrows(Exception.class, () -> OperationLogService.requireEventShape(completed));
        completed.setCompletedAtMillis(occurredAt + 100L);
        completed.setTimestamp(Instant.ofEpochMilli(occurredAt).toString());
        assertThrows(Exception.class, () -> OperationLogService.requireEventShape(completed));
    }

    @Test
    void detectsRowAndChainFieldTampering() throws Exception {
        assertRowTamperDetected("detail", "'tampered'");
        assertRowTamperDetected("outcome", "'REJECTED'");
        assertRowTamperDetected("chain_mac", "'" + "0".repeat(64) + "'");
        assertRowTamperDetected("event_id", "'" + UUID.randomUUID() + "'");
    }

    @Test
    void detectsDeletedMiddleAndHeadRows() throws Exception {
        assertDeletedRowDetected(false);
        assertDeletedRowDetected(true);
    }

    @Test
    void detectsCheckpointTampering() throws Exception {
        Path database = temporaryDirectory.resolve("checkpoint-tamper.db");
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(database.toString());
        try (OperationLogSanitizer sanitizer = sanitizer((byte) 21)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            service.log("TEST", "target", "{}", "203.0.113.10");
            execute(accessor, "UPDATE operation_log_state SET head_id = head_id + 1");

            assertThrows(Exception.class, service::verifyIntegrity);
            assertFalse(service.isHealthy());
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    @Test
    void missingCheckpointCannotBeSilentlyReanchoredAfterMigration() throws Exception {
        Path database = temporaryDirectory.resolve("missing-checkpoint.db");
        byte[] key = filledKey((byte) 22);
        WebDataAccessor first = new WebDataAccessor();
        first.connect(database.toString());
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OperationLogService service = new OperationLogService(first, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            service.log("TEST", "target", "{}", "203.0.113.10");
            execute(first, "DELETE FROM operation_log_state");
        } finally {
            UserContext.clear();
            first.close();
        }

        WebDataAccessor reopened = new WebDataAccessor();
        reopened.connect(database.toString());
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            IllegalStateException error = assertThrows(
                    IllegalStateException.class,
                    () -> new OperationLogService(reopened, sanitizer));
            assertTrue(error.getMessage().contains("integrity initialization"));
        } finally {
            Arrays.fill(key, (byte) 0);
            reopened.close();
        }
    }

    @Test
    void initializedCheckpointSurvivesAProcessRestartBeforeWebStartup() throws Exception {
        Path database = temporaryDirectory.resolve("startup-boundary.db");
        byte[] key = filledKey((byte) 27);
        WebDataAccessor first = new WebDataAccessor();
        first.connect(database.toString());
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            new OperationLogService(first, sanitizer);
            assertNotNull(first.getOperationLogStateDao().queryForId(1));
        } finally {
            first.close();
        }

        WebDataAccessor reopened = new WebDataAccessor();
        reopened.connect(database.toString());
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            assertDoesNotThrow(() -> new OperationLogService(reopened, sanitizer));
        } finally {
            Arrays.fill(key, (byte) 0);
            reopened.close();
        }
    }

    @Test
    void anAttemptCanOnlyBeCompletedOnce() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("complete-once.db").toString());
        try (OperationLogSanitizer sanitizer = sanitizer((byte) 23)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            long id = service.log("TEST", "target", "{\"outcome\":\"ATTEMPT\"}", "203.0.113.10");
            service.complete(id, "SUCCESS", "{\"outcome\":\"SUCCESS\"}");
            assertThrows(
                    Exception.class,
                    () -> service.complete(id, "SUCCESS", "{\"outcome\":\"SUCCESS\"}"));
            assertFalse(service.isHealthy());
            assertEquals("SUCCESS", accessor.getOperationLogDao().queryForId(id).getOutcome());
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    @Test
    void completionWriteFailureLeavesAttemptAndMarksAuditUnhealthy() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("completion-failure.db").toString());
        try (OperationLogSanitizer sanitizer = sanitizer((byte) 24)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            long id = service.log("TEST", "target", "{\"outcome\":\"ATTEMPT\"}", "203.0.113.10");
            execute(accessor, """
                    CREATE TRIGGER reject_audit_completion
                    BEFORE UPDATE ON operation_log
                    WHEN OLD.id = %d AND NEW.outcome <> OLD.outcome
                    BEGIN
                      SELECT RAISE(ABORT, 'injected audit completion failure');
                    END
                    """.formatted(id));

            assertThrows(
                    Exception.class,
                    () -> service.complete(id, "SUCCESS", "{\"outcome\":\"SUCCESS\"}"));
            assertFalse(service.isHealthy());
            OperationLog stored = accessor.getOperationLogDao().queryForId(id);
            assertEquals("ATTEMPT", stored.getOutcome());
            assertNull(stored.getCompletedAtMillis());

            execute(accessor, "DROP TRIGGER reject_audit_completion");
            assertTrue(service.verifyIntegrity().verified());
            assertTrue(service.isHealthy());
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    @Test
    void corruptedAuditRowCausesStartupFailure() throws Exception {
        Path database = temporaryDirectory.resolve("startup-corruption.db");
        byte[] key = filledKey((byte) 25);
        WebDataAccessor first = new WebDataAccessor();
        first.connect(database.toString());
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            OperationLogService service = new OperationLogService(first, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            service.log("TEST", "target", "{}", "203.0.113.10");
            execute(first, "UPDATE operation_log SET detail = 'tampered'");
        } finally {
            UserContext.clear();
            first.close();
        }

        WebDataAccessor reopened = new WebDataAccessor();
        reopened.connect(database.toString());
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.forKey(key)) {
            assertThrows(
                    IllegalStateException.class,
                    () -> new OperationLogService(reopened, sanitizer));
        } finally {
            Arrays.fill(key, (byte) 0);
            reopened.close();
        }
    }

    @Test
    void versionSixRowsAreMigratedOnceAndAuthenticated() throws Exception {
        Path database = temporaryDirectory.resolve("v6-audit.db");
        WebDataAccessor initial = new WebDataAccessor();
        initial.connect(database.toString());
        initial.close();

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("DROP TABLE operation_log_state");
            statement.executeUpdate("DROP TABLE operation_log");
            statement.executeUpdate("""
                    CREATE TABLE operation_log (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      username TEXT,
                      action TEXT,
                      target TEXT,
                      detail TEXT,
                      ip TEXT,
                      timestamp TEXT
                    )
                    """);
            statement.executeUpdate("""
                    INSERT INTO operation_log(
                      user_id, username, action, target, detail, ip, timestamp)
                    VALUES(
                      9, 'legacy-admin', 'OLD_ACTION', 'program',
                      '{"outcome":"SUCCESS"}', '198.51.100.20',
                      '2026-01-01T00:00:00Z')
                    """);
            statement.execute("PRAGMA user_version = 6");
        }

        WebDataAccessor migrated = new WebDataAccessor();
        migrated.connect(database.toString());
        try (OperationLogSanitizer sanitizer = sanitizer((byte) 26)) {
            assertTrue(migrated.isOperationAuditMigrationPending());
            OperationLogService service = new OperationLogService(migrated, sanitizer);
            assertFalse(migrated.isOperationAuditMigrationPending());

            OperationLog row = migrated.getOperationLogDao().queryForAll().get(0);
            assertNotNull(row.getEventId());
            assertEquals("SUCCESS", row.getOutcome());
            assertEquals("2026-01-01T00:00:00Z", row.getTimestamp());
            assertNotNull(row.getCompletedAtMillis());
            assertNotNull(row.getChainMac());
            assertNotNull(row.getIntegrityMac());
            assertTrue(service.verifyIntegrity().verified());
            OperationLogState state = migrated.getOperationLogStateDao().queryForId(1);
            assertNotNull(state);

            try (Connection connection = migrated.getDataSource().getConnection();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("PRAGMA user_version")) {
                assertTrue(result.next());
                assertEquals(WebDataAccessor.supportedSchemaVersion(), result.getInt(1));
            }
        } finally {
            migrated.close();
        }
    }

    private void assertRowTamperDetected(String column, String valueExpression) throws Exception {
        Path database = temporaryDirectory.resolve("tamper-" + column + ".db");
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(database.toString());
        try (OperationLogSanitizer sanitizer = sanitizer((byte) (30 + column.length()))) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            long id = service.log("TEST", "target", "{}", "203.0.113.10");
            service.complete(id, "SUCCESS", "{\"outcome\":\"SUCCESS\"}");
            execute(accessor, "UPDATE operation_log SET " + column + " = "
                    + valueExpression + " WHERE id = " + id);

            assertThrows(Exception.class, service::verifyIntegrity);
            assertFalse(service.isHealthy());
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    private void assertDeletedRowDetected(boolean head) throws Exception {
        Path database = temporaryDirectory.resolve(head ? "deleted-head.db" : "deleted-middle.db");
        WebDataAccessor accessor = new WebDataAccessor();
        accessor.connect(database.toString());
        try (OperationLogSanitizer sanitizer = sanitizer(head ? (byte) 41 : (byte) 42)) {
            OperationLogService service = new OperationLogService(accessor, sanitizer);
            UserContext.set(new UserContext(7, "admin", "ADMIN", "csrf"));
            long first = service.log("FIRST", "target", "{}", "203.0.113.10");
            long middle = service.log("MIDDLE", "target", "{}", "203.0.113.10");
            long last = service.log("LAST", "target", "{}", "203.0.113.10");
            assertTrue(first < middle && middle < last);
            execute(accessor, "DELETE FROM operation_log WHERE id = " + (head ? last : middle));

            assertThrows(Exception.class, service::verifyIntegrity);
            assertFalse(service.isHealthy());
        } finally {
            UserContext.clear();
            accessor.close();
        }
    }

    private static OperationLog shapedLog(
            String outcome,
            long occurredAt,
            Long completedAt,
            long displayedAt
    ) {
        return OperationLog.builder()
                .id(1L)
                .eventId(UUID.randomUUID().toString())
                .userId(1L)
                .username("ref:v1:" + "1".repeat(64))
                .action("TEST")
                .target("target")
                .detail("{}")
                .ip("ref:v1:" + "2".repeat(64))
                .timestamp(Instant.ofEpochMilli(displayedAt).toString())
                .outcome(outcome)
                .occurredAtMillis(occurredAt)
                .completedAtMillis(completedAt)
                .chainPreviousMac("3".repeat(64))
                .chainMac("4".repeat(64))
                .integrityMac("5".repeat(64))
                .build();
    }

    private static OperationLogSanitizer sanitizer(byte fill) {
        return OperationLogSanitizer.forKey(filledKey(fill));
    }

    private static byte[] filledKey(byte fill) {
        byte[] key = new byte[32];
        Arrays.fill(key, fill);
        return key;
    }

    private static void execute(WebDataAccessor accessor, String sql) throws Exception {
        try (Connection connection = accessor.getDataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }
}

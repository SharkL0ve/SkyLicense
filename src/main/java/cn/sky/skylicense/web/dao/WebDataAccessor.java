package cn.sky.skylicense.web.dao;

import cn.sky.skylicense.web.entity.*;
import cn.sky.skylicense.security.SecureFiles;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.DataSourceConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sqlite.SQLiteConfig;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.io.IOException;
import java.sql.SQLException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

@Getter
public class WebDataAccessor {

    private static final Logger LOG = LogManager.getLogger(WebDataAccessor.class);
    public static final String DEFAULT_DATABASE_PATH = "./web_magiclicense.db";
    private static final int BUSY_TIMEOUT_MILLIS = 10_000;
    private static final int SIDECAR_RELEASE_WAIT_MILLIS = 5_000;
    private static final int SIDECAR_STABLE_ABSENCE_MILLIS = 250;

    private ConnectionSource connectionSource;
    private DataSource dataSource;
    private String databasePath;
    private Dao<WebUser, Long> userDao;
    private Dao<Program, Long> programDao;
    private Dao<ProgramVersion, Long> programVersionDao;
    private Dao<License, Long> licenseDao;
    private Dao<AuthLog, Long> authLogDao;
    private Dao<OperationLog, Long> operationLogDao;
    private Dao<BanRecord, Long> banRecordDao;
    private Dao<WebSession, String> sessionDao;
    private Dao<WebMfaChallenge, String> mfaChallengeDao;
    private Dao<WebLoginAttempt, String> loginAttemptDao;
    private Dao<SystemMetadata, String> systemMetadataDao;
    private Dao<OperationLogState, Integer> operationLogStateDao;
    private volatile boolean operationAuditMigrationPending;

    public static int supportedSchemaVersion() {
        return WebSchemaMigrator.CURRENT_SCHEMA_VERSION;
    }

    public void connect(String dbPath) throws SQLException {
        databasePath = dbPath;
        HikariConfig config = new HikariConfig();
        String url = "jdbc:sqlite:" + dbPath;
        config.setJdbcUrl(url);
        config.setDriverClassName("org.sqlite.JDBC");
        config.setMaximumPoolSize(5);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(BUSY_TIMEOUT_MILLIS);
        config.setPoolName("SkyLicense-SQLite");

        SQLiteConfig sqliteConfig = new SQLiteConfig();
        sqliteConfig.setBusyTimeout(BUSY_TIMEOUT_MILLIS);
        sqliteConfig.setJournalMode(SQLiteConfig.JournalMode.WAL);
        sqliteConfig.setSynchronous(SQLiteConfig.SynchronousMode.FULL);
        sqliteConfig.enforceForeignKeys(true);
        sqliteConfig.setWalAutocheckpoint(1_000);
        config.setDataSourceProperties(sqliteConfig.toProperties());

        HikariDataSource hikariDataSource = new HikariDataSource(config);
        dataSource = hikariDataSource;
        try {
            hardenDatabaseFiles();
            connectionSource = new DataSourceConnectionSource(dataSource, url);
            verifyDatabaseHealth();
            hardenDatabaseFiles();
            assertSupportedSchema();
            createTablesIfMissing();
            migrateSchema();
            hardenDatabaseFiles();
            assertRelationshipIntegrity();
            initDaos();
            LOG.info(
                    "Web database connected: {} (WAL, schema v{})",
                    dbPath,
                    WebSchemaMigrator.CURRENT_SCHEMA_VERSION);
        } catch (SQLException | RuntimeException error) {
            close();
            throw error;
        }
    }

    private void hardenDatabaseFiles() throws SQLException {
        Path database = Path.of(databasePath).toAbsolutePath().normalize();
        try {
            if (Files.exists(database, LinkOption.NOFOLLOW_LINKS)) {
                SecureFiles.makePrivateReadWrite(database);
            }
            for (String suffix : new String[]{"-wal", "-shm"}) {
                Path sidecar = database.resolveSibling(database.getFileName() + suffix);
                if (Files.exists(sidecar, LinkOption.NOFOLLOW_LINKS)) {
                    SecureFiles.makePrivateReadWrite(sidecar);
                }
            }
        } catch (IOException error) {
            throw new SQLException("Unable to enforce private SQLite file permissions", error);
        }
    }

    private void initDaos() throws SQLException {
        userDao = createDao(WebUser.class);
        programDao = createDao(Program.class);
        programVersionDao = createDao(ProgramVersion.class);
        licenseDao = createDao(License.class);
        authLogDao = createDao(AuthLog.class);
        operationLogDao = createDao(OperationLog.class);
        banRecordDao = createDao(BanRecord.class);
        sessionDao = createStringDao(WebSession.class);
        mfaChallengeDao = createStringDao(WebMfaChallenge.class);
        loginAttemptDao = createStringDao(WebLoginAttempt.class);
        systemMetadataDao = createStringDao(SystemMetadata.class);
        operationLogStateDao = createIntDao(OperationLogState.class);
    }

    private void verifyDatabaseHealth() throws SQLException {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("PRAGMA quick_check")) {
            boolean found = false;
            while (result.next()) {
                found = true;
                String status = result.getString(1);
                if (!"ok".equalsIgnoreCase(status)) {
                    throw new SQLException("SQLite quick_check failed: " + status);
                }
            }
            if (!found) {
                throw new SQLException("SQLite quick_check returned no result");
            }
        }
    }

    private void assertSupportedSchema() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            WebSchemaMigrator.assertSupportedVersion(connection);
        }
    }

    private void createTablesIfMissing() throws SQLException {
        createTableIfMissing("web_user", WebUser.class);
        createTableIfMissing("program", Program.class);
        createTableIfMissing("program_version", ProgramVersion.class);
        createTableIfMissing("license", License.class);
        createTableIfMissing("auth_log", AuthLog.class);
        createTableIfMissing("operation_log", OperationLog.class);
        createTableIfMissing("ban_record", BanRecord.class);
        createTableIfMissing("web_session", WebSession.class);
        createTableIfMissing("system_metadata", SystemMetadata.class);
        createTableIfMissing("operation_log_state", OperationLogState.class);
    }

    private <T> void createTableIfMissing(String tableName, Class<T> entityClass)
            throws SQLException {
        if (tableExists(tableName)) {
            return;
        }
        TableUtils.createTable(connectionSource, entityClass);
    }

    private boolean tableExists(String tableName) throws SQLException {
        String sql = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tableName);
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private void migrateSchema() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            WebSchemaMigrator.MigrationResult result = WebSchemaMigrator.migrate(connection);
            operationAuditMigrationPending = result.auditBackfillRequired();
        }
    }

    /**
     * True only after this process has just committed a pre-v7 schema upgrade.
     * It is intentionally not persisted in SQLite: deleting the audit
     * checkpoint on a later process must not silently re-anchor the chain.
     */
    public boolean isOperationAuditMigrationPending() {
        return operationAuditMigrationPending;
    }

    public synchronized void markOperationAuditMigrationComplete() {
        operationAuditMigrationPending = false;
    }

    private <T> Dao<T, Long> createDao(Class<T> clazz) throws SQLException {
        return DaoManager.createDao(connectionSource, clazz);
    }

    private <T> Dao<T, String> createStringDao(Class<T> clazz) throws SQLException {
        return DaoManager.createDao(connectionSource, clazz);
    }

    private <T> Dao<T, Integer> createIntDao(Class<T> clazz) throws SQLException {
        return DaoManager.createDao(connectionSource, clazz);
    }

    public synchronized void close() {
        ConnectionSource source = connectionSource;
        checkpointWriteAheadLog();
        if (source != null) {
            try {
                DaoManager.unregisterDaos(source);
            } catch (RuntimeException error) {
                LOG.error("Failed to unregister web database DAOs", error);
            }
            try {
                source.close();
            } catch (Exception error) {
                LOG.error("Failed to close web database connection source", error);
            }
        }
        connectionSource = null;
        if (dataSource instanceof HikariDataSource hikariDataSource) {
            try {
                hikariDataSource.close();
            } catch (RuntimeException error) {
                LOG.error("Failed to close web database pool", error);
            }
        }
        dataSource = null;
        awaitSQLiteSidecarRelease(databasePath);
        databasePath = null;
        userDao = null;
        programDao = null;
        programVersionDao = null;
        licenseDao = null;
        authLogDao = null;
        operationLogDao = null;
        banRecordDao = null;
        sessionDao = null;
        mfaChallengeDao = null;
        loginAttemptDao = null;
        systemMetadataDao = null;
        operationLogStateDao = null;
        operationAuditMigrationPending = false;
    }

    /**
     * SQLite may release Windows WAL handles shortly after the final JDBC close.
     * Wait for the driver to remove its own sidecars; never delete files that a
     * second process could still be using.
     */
    private void awaitSQLiteSidecarRelease(String dbPath) {
        if (dbPath == null || dbPath.isBlank() || ":memory:".equals(dbPath)) {
            return;
        }
        Path database = Path.of(dbPath).toAbsolutePath().normalize();
        Path wal = Path.of(database + "-wal");
        Path sharedMemory = Path.of(database + "-shm");
        int consecutiveAbsentChecks = 0;
        for (int attempt = 0; attempt < SIDECAR_RELEASE_WAIT_MILLIS / 10; attempt++) {
            if (!Files.exists(wal) && !Files.exists(sharedMemory)) {
                consecutiveAbsentChecks++;
                if (consecutiveAbsentChecks >= SIDECAR_STABLE_ABSENCE_MILLIS / 10) {
                    return;
                }
            } else {
                consecutiveAbsentChecks = 0;
            }
            try {
                Thread.sleep(10L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        LOG.debug("SQLite sidecars remain after pool shutdown: {} / {}", wal, sharedMemory);
    }

    private void checkpointWriteAheadLog() {
        if (dataSource == null) {
            return;
        }
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } catch (SQLException error) {
            LOG.warn("Unable to checkpoint SQLite WAL during shutdown", error);
        }
    }

    /** Cheap lifecycle check used before attempting a readiness query. */
    public boolean isOpen() {
        DataSource current = dataSource;
        return connectionSource != null
                && current != null
                && (!(current instanceof HikariDataSource hikari) || !hikari.isClosed());
    }

    /** Executes a minimal bounded query without exposing database details to callers. */
    public boolean isHealthy() {
        DataSource current = dataSource;
        if (!isOpen() || current == null) {
            return false;
        }
        try (Connection connection = current.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT 1")) {
            statement.setQueryTimeout(1);
            try (ResultSet result = statement.executeQuery()) {
                if (!(result.next() && result.getInt(1) == 1)) {
                    return false;
                }
            }
            assertRelationshipIntegrity();
            return true;
        } catch (SQLException | RuntimeException ignored) {
            return false;
        }
    }

    /** Fails closed when a trigger or stored relationship has been tampered with. */
    public void assertRelationshipIntegrity() throws SQLException {
        DataSource current = dataSource;
        if (!isOpen() || current == null) {
            throw new SQLException("web database is not open");
        }
        try (Connection connection = current.getConnection()) {
            DatabaseRelationshipIntegrity.verify(connection);
        }
    }
}

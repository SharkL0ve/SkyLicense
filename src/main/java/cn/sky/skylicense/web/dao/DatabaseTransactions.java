package cn.sky.skylicense.web.dao;

import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.support.ConnectionSource;

import java.sql.SQLException;
import java.util.concurrent.Callable;

/** ORMLite transactions that preserve application runtime exceptions. */
public final class DatabaseTransactions {
    private DatabaseTransactions() {
    }

    public static <T> T call(
            ConnectionSource connectionSource,
            Callable<T> operation
    ) throws SQLException {
        try {
            return TransactionManager.callInTransaction(connectionSource, operation);
        } catch (SQLException error) {
            Throwable cause = error.getCause();
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            if (cause instanceof Error fatal) {
                throw fatal;
            }
            throw error;
        }
    }
}

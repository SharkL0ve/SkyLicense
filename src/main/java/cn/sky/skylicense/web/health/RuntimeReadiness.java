package cn.sky.skylicense.web.health;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.netty.SocketManger;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.service.OperationLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.function.BooleanSupplier;

/** Aggregates the minimum runtime conditions required to accept license traffic. */
@Service
public final class RuntimeReadiness implements ReadinessStatus {
    static final long DATABASE_CACHE_NANOS = TimeUnit.SECONDS.toNanos(2);

    private final Supplier<RuntimeInputs> inputSupplier;
    private final LongSupplier nanoTime;
    private final long databaseCacheNanos;
    private final BooleanSupplier auditHealth;
    private final Object databaseCheckLock = new Object();

    private volatile WebDataAccessor cachedAccessor;
    private volatile boolean cachedDatabaseReady;
    private volatile long databaseCheckedAtNanos = Long.MIN_VALUE;

    @Autowired
    public RuntimeReadiness(OperationLogService operationLogService) {
        this(
                RuntimeReadiness::currentInputs,
                System::nanoTime,
                DATABASE_CACHE_NANOS,
                operationLogService::isHealthy);
    }

    RuntimeReadiness(
            Supplier<RuntimeInputs> inputSupplier,
            LongSupplier nanoTime,
            long databaseCacheNanos
    ) {
        this(inputSupplier, nanoTime, databaseCacheNanos, () -> true);
    }

    RuntimeReadiness(
            Supplier<RuntimeInputs> inputSupplier,
            LongSupplier nanoTime,
            long databaseCacheNanos,
            BooleanSupplier auditHealth
    ) {
        this.inputSupplier = inputSupplier;
        this.nanoTime = nanoTime;
        this.databaseCacheNanos = databaseCacheNanos;
        this.auditHealth = auditHealth;
    }

    @Override
    public boolean isReady() {
        RuntimeInputs inputs;
        try {
            inputs = inputSupplier.get();
        } catch (RuntimeException ignored) {
            clearDatabaseCache();
            return false;
        }
        WebDataAccessor accessor = inputs == null ? null : inputs.database();
        if (!auditHealth.getAsBoolean()
                || inputs == null
                || !inputs.lifecycleReady()
                || !inputs.listenerReady()
                || accessor == null
                || !accessor.isOpen()) {
            clearDatabaseCache();
            return false;
        }
        return isDatabaseReady(accessor);
    }

    private boolean isDatabaseReady(WebDataAccessor accessor) {
        long now = nanoTime.getAsLong();
        if (cacheIsFresh(accessor, now)) {
            return cachedDatabaseReady;
        }
        synchronized (databaseCheckLock) {
            now = nanoTime.getAsLong();
            if (cacheIsFresh(accessor, now)) {
                return cachedDatabaseReady;
            }
            boolean ready = accessor.isHealthy();
            cachedAccessor = accessor;
            cachedDatabaseReady = ready;
            databaseCheckedAtNanos = now;
            return ready;
        }
    }

    private boolean cacheIsFresh(WebDataAccessor accessor, long now) {
        long checkedAt = databaseCheckedAtNanos;
        long age = now - checkedAt;
        return cachedAccessor == accessor
                && checkedAt != Long.MIN_VALUE
                && age >= 0
                && age < databaseCacheNanos;
    }

    private void clearDatabaseCache() {
        synchronized (databaseCheckLock) {
            cachedAccessor = null;
            cachedDatabaseReady = false;
            databaseCheckedAtNanos = Long.MIN_VALUE;
        }
    }

    private static RuntimeInputs currentInputs() {
        SkyLicense service = SkyLicense.instance;
        if (service == null) {
            return RuntimeInputs.UNAVAILABLE;
        }
        SocketManger listener = service.getSocketManager();
        return new RuntimeInputs(
                !service.isShutdownInProgress(),
                listener != null && listener.isAcceptingConnections(),
                service.getWebDataAccessor());
    }

    record RuntimeInputs(
            boolean lifecycleReady,
            boolean listenerReady,
            WebDataAccessor database
    ) {
        private static final RuntimeInputs UNAVAILABLE =
                new RuntimeInputs(false, false, null);
    }
}

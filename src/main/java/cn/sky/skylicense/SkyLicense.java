package cn.sky.skylicense;

import cn.sky.skylicense.command.Command;
import cn.sky.skylicense.command.impl.*;
import cn.sky.skylicense.config.Configuration;
import cn.sky.skylicense.netty.SocketManger;
import cn.sky.skylicense.netty.SessionManager;
import cn.sky.skylicense.netty.SocketHandler;
import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.runnable.AutoTask;
import cn.sky.skylicense.runnable.ResourceTask;
import cn.sky.skylicense.security.StartupSecurity;
import cn.sky.skylicense.security.ResourceCatalog;
import cn.sky.skylicense.web.aop.OperationLogSanitizer;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.config.DatabaseConfig;
import cn.sky.skylicense.web.service.BanService;
import cn.sky.skylicense.web.service.LegacyLicenseMigrationService;
import cn.sky.skylicense.web.service.LicenseService;
import cn.sky.skylicense.web.service.NativeLicenseService;
import cn.sky.skylicense.web.service.NativeIdentityMigrationService;
import cn.sky.skylicense.web.service.OperationLogService;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.context.ConfigurableApplicationContext;
@Getter
public class SkyLicense {
    public static final Logger LOG = LogManager.getLogger(SkyLicense.class);
    // Loading lifecycle helpers must not require or create deployment files.
    // Normal startup still fails closed when its required config is missing.
    private static final class RuntimeConfiguration {
        private static final Configuration INSTANCE = Configuration.loadRequired(new File("config.json"));
    }

    public static Configuration configuration() {
        return RuntimeConfiguration.INSTANCE;
    }
    public static SkyLicense instance;
    private final WebDataAccessor webDataAccessor;
    private final LicenseService webLicenseService;
    private final BanService webBanService;
    private final NativeLicenseService nativeLicenseService;
    private final Set<Command> commands = new HashSet<>();
    private final ExecutorService serviceExecutor = Executors.newCachedThreadPool();
    private final AtomicBoolean shutdownStarted = new AtomicBoolean();
    private volatile SocketManger socketManager;
    private volatile ScheduledExecutorService scheduler;
    private volatile ExecutorService commandExecutor;
    private volatile Thread commandThread;
    private volatile ConfigurableApplicationContext webApplicationContext;

    private SkyLicense() {
        Thread.currentThread().setName("Main Thread");
        StartupSecurity.validate(configuration().getStorage());
        webDataAccessor = new WebDataAccessor();
        try {
            webDataAccessor.connect(WebDataAccessor.DEFAULT_DATABASE_PATH);
            initializeOperationAudit();
            new LegacyLicenseMigrationService(webDataAccessor).migrateIfNeeded();
            new NativeIdentityMigrationService(webDataAccessor).migrateIfNeeded();
            DatabaseConfig.initializeBootstrapAdministrator(webDataAccessor);
            webLicenseService = new LicenseService(webDataAccessor);
            webBanService = new BanService(webDataAccessor, webLicenseService);
            int expiredBanRules = webBanService.expireDueBans();
            if (expiredBanRules > 0) {
                LOG.info("Expired {} ban rules during startup", expiredBanRules);
            }
            nativeLicenseService = new NativeLicenseService(webDataAccessor, webBanService);
            int recoveredDeliveries = nativeLicenseService.recoverPendingDeliveries();
            if (recoveredDeliveries > 0) {
                LOG.warn(
                        "Recovered {} unfinished native authorization deliveries",
                        recoveredDeliveries);
            }
        } catch (Exception error) {
            webDataAccessor.close();
            throw new IllegalStateException("Unable to initialize the Web license database", error);
        }
    }

    private void initializeOperationAudit() {
        // Commit the authenticated checkpoint before any later startup stage can
        // fail. Spring creates the runtime service after this boundary and
        // verifies the same chain before accepting Web traffic.
        try (OperationLogSanitizer sanitizer = OperationLogSanitizer.fromEnvironment()) {
            new OperationLogService(webDataAccessor, sanitizer);
        }
    }

    public static SkyLicense start() {
        SkyLicense service = new SkyLicense();
        instance = service;
        try {
            service.loadLicense();
            return service;
        } catch (RuntimeException | Error failure) {
            instance = null;
            service.shutdownServices();
            service.webDataAccessor.close();
            throw failure;
        }
    }

    @SneakyThrows
    public void loadLicense() {

        /*InetAddress inet = InetAddress.getByName("api.nyacho.cn");
        boolean a = inet.isReachable(5000);*/

        // 打印启动信息
        printStartupBanner();

        LOG.info("天空验证服务端 v1.0.0 - by pi_ka");

        SessionManager.beginStartup();

        int quarantined = ResourceCatalog.quarantineUnreferenced(
                webDataAccessor, Paths.get("resources"));
        if (quarantined > 0) {
            LOG.warn("Quarantined {} unreferenced resource artifacts during startup", quarantined);
        }
        if (!reloadProtectedResources(true)) {
            throw new IllegalStateException(
                    "Initial protected resource scan failed; authentication listener was not started");
        }

        SocketHandler.startResourceExecutor();

        // 启动异步任务
        startServiceThreads();

        startRunnable();

        // 加载命令
        loadCommand();
    }

    public boolean reloadProtectedResources(boolean logDetails) {
        return ResourceCatalog.reload(
                webDataAccessor, Paths.get("resources"), logDetails);
    }

    private void printStartupBanner() {
        String banner = """
                \u001b[0;34m================================================================================
                      __  ___               _        __     _                                 \s
                     /  |/  /____ _ ____ _ (_)_____ / /    (_)_____ ___   ____   _____ ___    \s
                    / /|_/ // __ `// __ `// // ___// /    / // ___// _ \\ / __ \\ / ___// _ \\\s
                   / /  / // /_/ // /_/ // // /__ / /___ / // /__ /  __// / / /(__  )/  __/   \s
                  /_/  /_/ \\__,_/ \\__, //_/ \\___//_____//_/ \\___/ \\___//_/ /_//____/ \\___/
                                 /____/                                                       \s
                ===============================================================================\u001b[0m""";
        System.out.println(banner);
    }

    private void startServiceThreads() throws Exception {
        CompletableFuture<Void> authenticationReady = new CompletableFuture<>();
        serviceExecutor.execute(() -> {
            try {
                SocketManger manager = new SocketManger(configuration().getStorage().getAuthPort());
                socketManager = manager;
                manager.startNetty(authenticationReady);
            } catch (Exception e) {
                authenticationReady.completeExceptionally(e);
                LOG.error("SocketManager 启动失败", e);
            }
        });

        try {
            authenticationReady.get(10, TimeUnit.SECONDS);
        } catch (Exception error) {
            serviceExecutor.shutdownNow();
            throw new IllegalStateException(
                    "Authentication listener did not become ready", error);
        }

    }

    private void startRunnable() {
        scheduler = Executors.newScheduledThreadPool(1, runnable -> {
            Thread thread = new Thread(runnable, "skylicense-scheduler");
            thread.setDaemon(false);
            return thread;
        });

        ResourceTask task = new ResourceTask();
        scheduler.scheduleAtFixedRate(task, 0, 30, TimeUnit.MINUTES);

        AutoTask autoTask = new AutoTask();
        scheduler.scheduleAtFixedRate(autoTask, 0, 1, TimeUnit.SECONDS);
    }

    public void loadCommand() {
        registerCommands(
                new HelpCommand(),
                new OnlineCommand(),
                new RefreshCommand(),
                new ReloadCommand(),
                new StopCommand()
        );
        commandExecutor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "skylicense-command");
            thread.setDaemon(true);
            commandThread = thread;
            return thread;
        });
        commandExecutor.execute(this::commandService);
    }

    public void stop() {
        try {
            shutdownServices();
            configuration().save();
            LOG.info("Configuration file saved.");
        } finally {
            ConfigurableApplicationContext context = webApplicationContext;
            if (context != null && context.isActive()) {
                context.close();
            } else {
                webDataAccessor.close();
            }
            instance = null;
        }
    }

    /** Invoked by Spring before its beans, including the database, are destroyed. */
    public void shutdownServices() {
        if (!shutdownStarted.compareAndSet(false, true)) {
            return;
        }
        SessionManager.stopAcceptingRegistrations();
        SocketManger manager = socketManager;
        if (manager != null) {
            manager.stopAccepting();
        }
        int destroyed = SessionManager.destroyAllSessions();
        if (manager != null) {
            manager.stop();
        }
        SocketHandler.shutdownResourceExecutor();
        SocketHandler.clearAll();
        ScheduledExecutorService currentScheduler = scheduler;
        if (currentScheduler != null) {
            currentScheduler.shutdownNow();
        }
        ExecutorService currentCommandExecutor = commandExecutor;
        shutdownCommandExecutor(currentCommandExecutor, commandThread);
        serviceExecutor.shutdownNow();
        awaitTermination(currentScheduler, "scheduler");
        if (Thread.currentThread() != commandThread) {
            awaitTermination(currentCommandExecutor, "command executor");
        }
        awaitTermination(serviceExecutor, "service executor");
        LOG.info("SkyLicense services stopped; destroyed {} client sessions", destroyed);
    }

    static void shutdownCommandExecutor(ExecutorService executor, Thread ownerThread) {
        if (executor == null) {
            return;
        }
        if (Thread.currentThread() == ownerThread) {
            executor.shutdown();
        } else {
            executor.shutdownNow();
        }
    }

    public void attachWebApplicationContext(ConfigurableApplicationContext context) {
        webApplicationContext = context;
    }

    public boolean isShutdownInProgress() {
        return shutdownStarted.get();
    }

    private static void awaitTermination(ExecutorService executor, String name) {
        if (executor == null) {
            return;
        }
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                LOG.warn("{} did not terminate within the shutdown deadline", name);
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            LOG.warn("Interrupted while stopping {}", name);
        }
    }

    private void commandService() {
        Scanner scanner = new Scanner(System.in);
        while (scanner.hasNext()) {
            String[] args = scanner.nextLine().split(" ");
            String cmdName = args[0];


            if (cmdName.isEmpty()) {
                LOG.info("Please write a command, not empty text!");
                continue;
            }

            Command command = commands.stream()
                    .filter(cmd -> cmd.getCommand().equalsIgnoreCase(cmdName) || cmd.getAliases().contains(cmdName))
                    .findFirst()
                    .orElse(null);

            if (command == null) {
                LOG.info("Command not found!");
                Usage();
                continue;
            }

            try {
                command.executeCommand(Arrays.copyOfRange(args, 1, args.length));
            } catch (Exception exception) {
                LOG.error("Unexpected error while executing command {}", cmdName, exception);
            }
        }
    }

    public void Usage() {
        LOG.info("SkyLicense Help:");
        LOG.info(" - online | View the number of online players.");
        LOG.info(" - refresh | Refresh authentication rate-limit state.");
        LOG.info(" - reload | Atomically reload protected resources and configuration.");
        LOG.info(" - stop | Stop the server.");
        LOG.info("License, ban, user, and program management is available only through the TLS Web console/API.");
    }

    private void registerCommand(Command command) {
        this.commands.add(command);
    }

    private void registerCommands(Command... commands) {
        this.commands.addAll(Arrays.asList(commands));
    }
}

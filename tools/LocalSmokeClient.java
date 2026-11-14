import cn.sky.license.PluginProxy;
import cn.sky.license.Resource;
import cn.sky.license.Response;
import cn.sky.license.SkyLicense;
import java.io.File;
import java.io.InputStream;

/** Disposable JVM probe; never package this fixture with a customer application. */
public final class LocalSmokeClient implements PluginProxy {
    private final File data;
    private volatile boolean disabled;

    private LocalSmokeClient(File data) { this.data = data; }

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3) throw new IllegalArgumentException("expected data directory, endpoint and optional mode");
        String mode = args.length == 3 ? args[2] : "accept";
        LocalSmokeClient host = new LocalSmokeClient(new File(args[0]));
        try (SkyLicense client = new SkyLicense(host)) {
        Response response = client.authenticate(args[1], "LocalSmoke", "1.0.0");
        System.out.println("native_accept=" + (response == Response.ACCEPT));
        System.out.println("entry_started=" + "true".equals(System.getProperty("skylicense.smoke.entry")));
        if (mode.startsWith("reject:")) {
            Response expected = (Response) Response.class.getField(mode.substring(7)).get(null);
            if (response != expected || System.getProperty("skylicense.smoke.entry") != null) System.exit(3);
            System.out.println("rejection_confirmed=true");
            return;
        }
        if (response != Response.ACCEPT) {
            System.out.println("native_response=" + response);
            System.exit(2);
        }
        if (client.authenticate(args[1], "LocalSmoke", "1.0.0") != Response.SESSION_ALREADY_INITIALIZED) System.exit(6);
        if (mode.equals("revoke")) {
            System.out.println("ready_for_revocation=true");
            System.out.flush();
            long deadline = System.nanoTime() + 55_000_000_000L;
            while (!host.disabled && System.nanoTime() < deadline) Thread.sleep(100);
            if (!host.disabled || client.isSessionActive()) System.exit(4);
            try { SkyLicense.authLib.authenticate(null, "@LocalSmoke@lignored"); System.exit(7); }
            catch (SecurityException expected) { System.out.println("revoked_dispatch_blocked=true"); }
            System.out.println("revocation_confirmed=true");
            return;
        }
        Thread.sleep(55_000L);
        long rotations = Long.parseLong(String.valueOf(SkyLicense.authLib.authenticate(null, "!skylicense:v4:rotations")));
        System.out.println("native_rotation_count=" + rotations);
        if (rotations < 1) System.exit(9);
        Object tick = System.getProperties().get("skylicense.smoke.tick");
        if (!(tick instanceof Runnable)) System.exit(8);
        ((Runnable) tick).run();
        System.out.println("protected_dispatch_after_rotation=true");
        System.out.println("heartbeat_count=" + client.getHeartbeatCount());
        if (!client.isSessionActive() || client.getHeartbeatCount() < 2) System.exit(5);
        System.out.println("heartbeat_window_completed=true");
        }
    }

    public File getDataFolder() { return data; }
    public void info(String text) { System.out.println("sdk_info=" + text); }
    public void disablePlugin() { disabled = true; }
    public InputStream getResource(String name) {
        return LocalSmokeClient.class.getClassLoader().getResourceAsStream(name);
    }
    public Resource getResourceType() { return Resource.CLEAR_LOWERCASE; }
    public boolean isPrimaryThread() { return true; }
}

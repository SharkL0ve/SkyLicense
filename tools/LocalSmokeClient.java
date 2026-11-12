import cn.sky.license.PluginProxy;
import cn.sky.license.Resource;
import cn.sky.license.Response;
import cn.sky.license.SkyLicense;
import java.io.File;
import java.io.InputStream;

/** Disposable JVM probe; never package this fixture with a customer application. */
public final class LocalSmokeClient implements PluginProxy {
    private final File data;

    private LocalSmokeClient(File data) { this.data = data; }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("expected data directory and endpoint");
        Response response = new SkyLicense(new LocalSmokeClient(new File(args[0])))
                .authenticate(args[1], "LocalSmoke", "1.0.0");
        System.out.println("native_accept=" + (response == Response.ACCEPT));
        System.out.println("entry_started=" + "true".equals(System.getProperty("skylicense.smoke.entry")));
        if (response != Response.ACCEPT) {
            System.out.println("native_response=" + response);
            System.exit(2);
        }
        Thread.sleep(35_000L);
        System.out.println("heartbeat_window_completed=true");
        System.exit(0);
    }

    public File getDataFolder() { return data; }
    public void info(String text) { System.out.println("sdk_info=" + text); }
    public void disablePlugin() { throw new IllegalStateException("session disabled"); }
    public InputStream getResource(String name) {
        return LocalSmokeClient.class.getClassLoader().getResourceAsStream(name);
    }
    public Resource getResourceType() { return Resource.CLEAR_LOWERCASE; }
    public boolean isPrimaryThread() { return true; }
}

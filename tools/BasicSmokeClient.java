import cn.sky.license.*;
import java.io.File;
import java.io.InputStream;

/** Runs in a separate JVM against the packaged basic SDK, including negative cases. */
public final class BasicSmokeClient implements PluginProxy {
    private final File folder;
    private volatile boolean disabled;
    BasicSmokeClient(File folder) { this.folder = folder; }

    public static void main(String[] args) throws Exception {
        BasicSmokeClient host = new BasicSmokeClient(new File(args[0]));
        try (BasicLicenseClient client = new BasicLicenseClient(host)) {
            Response response = client.authenticate(args[1], "LocalSmoke", "1.0.0");
            System.out.println("basic_accept=" + (response == Response.ACCEPT));
            System.out.println("entry_started=" + "true".equals(System.getProperty("skylicense.smoke.entry")));
            System.out.println("failure_stage=" + client.getLastError());
            if (args[2].startsWith("reject:")) {
                Response expected = (Response) Response.class.getField(args[2].substring(7)).get(null);
                if (response != expected || System.getProperty("skylicense.smoke.entry") != null) System.exit(3);
                System.out.println("rejection_confirmed=true");
                return;
            }
            if (response != Response.ACCEPT) System.exit(2);
            if (args[2].equals("revoke")) {
                System.out.println("ready_for_revocation=true");
                System.out.flush();
                long deadline = System.nanoTime() + 50_000_000_000L;
                while (!host.disabled && System.nanoTime() < deadline) Thread.sleep(100);
                if (!host.disabled || client.isSessionActive()) System.exit(4);
                System.out.println("revocation_confirmed=true");
            } else {
                Thread.sleep(35_000);
                System.out.println("heartbeat_count=" + client.getHeartbeatCount());
                if (!client.isSessionActive() || client.getHeartbeatCount() < 2) System.exit(5);
                System.out.println("heartbeat_window_completed=true");
            }
        }
    }

    public File getDataFolder() { return folder; }
    public void info(String text) { System.out.println(text); }
    public void disablePlugin() { disabled = true; }
    public InputStream getResource(String name) { return getClass().getClassLoader().getResourceAsStream(name); }
    public Resource getResourceType() { return Resource.CLEAR_LOWERCASE; }
    public boolean isPrimaryThread() { return true; }
}

package cn.sky.license;

import java.io.File;
import java.io.InputStream;
import java.util.concurrent.CountDownLatch;

/** Standalone host for the signed native SDK; revocation stops the process. */
public final class NativeLauncher implements PluginProxy {
    private final File data;
    private NativeLauncher(File data) { this.data = data; }

    public static void main(String[] args) throws Exception {
        if (args.length < 3 || args.length > 4) {
            System.err.println("usage: NativeLauncher <host:port> <program> <version> [data-directory]");
            System.exit(1);
        }
        NativeLauncher host = new NativeLauncher(new File(args.length == 4 ? args[3] : "customer-data"));
        SkyLicense client = new SkyLicense(host);
        Response response = client.authenticate(args[0], args[1], args[2]);
        if (response != Response.ACCEPT) {
            System.err.println("License authentication failed: " + response);
            client.close();
            System.exit(2);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(client::close, "skylicense-native-shutdown"));
        System.out.println("License accepted; protected entry completed; signed native heartbeat active.");
        new CountDownLatch(1).await();
    }

    public File getDataFolder() { return data; }
    public void info(String text) { System.out.println(text); }
    public void disablePlugin() {
        System.err.println("License session revoked or expired; stopping application.");
        System.exit(3);
    }
    public InputStream getResource(String name) { return getClass().getClassLoader().getResourceAsStream(name); }
    public Resource getResourceType() { return Resource.CLEAR_LOWERCASE; }
    public boolean isPrimaryThread() { return true; }
}

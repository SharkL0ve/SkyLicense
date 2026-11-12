package cn.sky.license;

import java.io.File;
import java.io.InputStream;
import java.util.concurrent.CountDownLatch;

/** Standalone host for a server-uploaded protected application. */
public final class BasicLauncher implements PluginProxy {
    private final File data;
    private BasicLauncher(File data) { this.data = data; }

    public static void main(String[] args) throws Exception {
        if (args.length < 3 || args.length > 4) {
            System.err.println("usage: BasicLauncher <host:port> <program> <version> [data-directory]");
            System.exit(1);
        }
        BasicLauncher host = new BasicLauncher(new File(args.length == 4 ? args[3] : "customer-data"));
        BasicLicenseClient client = new BasicLicenseClient(host);
        Response response = client.authenticate(args[0], args[1], args[2]);
        if (response != Response.ACCEPT) {
            System.err.println("License authentication failed: " + response + " (" + client.getLastError() + ")");
            client.close();
            System.exit(2);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(client::close, "skylicense-basic-shutdown"));
        System.out.println("License accepted; protected entry completed; heartbeat active.");
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

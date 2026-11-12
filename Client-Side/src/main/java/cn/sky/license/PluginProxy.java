package cn.sky.license;

import java.io.File;
import java.io.InputStream;

public interface PluginProxy {
    File getDataFolder();

    void info(String text);

    void disablePlugin();

    InputStream getResource(String resource);

    Resource getResourceType();

    boolean isPrimaryThread();
}

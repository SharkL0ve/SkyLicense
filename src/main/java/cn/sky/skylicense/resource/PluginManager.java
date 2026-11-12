package cn.sky.skylicense.resource;

import java.util.List;
import java.util.Map;

public final class PluginManager {
    public static volatile Map<String, List<String>> plugins = Map.of();

    private PluginManager() {
    }
}

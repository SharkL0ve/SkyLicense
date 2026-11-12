package cn.sky.skylicense.command.impl;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.command.Command;
import cn.sky.skylicense.netty.SessionManager;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class OnlineCommand extends Command {
    public OnlineCommand() {
        super("online");
    }

    @Override
    public void executeCommand(String... arguments) {
        if (arguments.length != 0) {
            return;
        }
        List<SessionManager.SessionInfo> active = SessionManager.getAllSessions()
                .values()
                .stream()
                .filter(SessionManager.SessionInfo::isActive)
                .toList();
        if (active.isEmpty()) {
            SkyLicense.LOG.info("No active authenticated sessions.");
            return;
        }
        SkyLicense.LOG.info("Active authenticated sessions: total={}", active.size());
        Map<String, Long> byPlugin = active.stream()
                .map(SessionManager.SessionInfo::getPluginName)
                .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));
        for (Map.Entry<String, Long> entry : byPlugin.entrySet()) {
            SkyLicense.LOG.info(
                    "Active sessions by plugin: plugin={}, count={}",
                    entry.getKey(),
                    entry.getValue());
        }
    }
}

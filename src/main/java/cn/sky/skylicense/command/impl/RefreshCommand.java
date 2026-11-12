package cn.sky.skylicense.command.impl;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.command.Command;
import cn.sky.skylicense.netty.SocketHandler;

import java.util.List;

public class RefreshCommand extends Command {
    public RefreshCommand() {
        super("refresh",List.of("rs"));
    }

    @Override
    public void executeCommand(String... args) {
        if (args.length == 0){
            SocketHandler.clearAll();
            SkyLicense.LOG.info("Refresh Cooling Successful.");
        }
    }
}

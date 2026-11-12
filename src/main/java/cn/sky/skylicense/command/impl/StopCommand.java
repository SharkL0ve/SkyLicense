package cn.sky.skylicense.command.impl;

import cn.sky.skylicense.command.Command;
import cn.sky.skylicense.SkyLicense;

public class StopCommand extends Command {
    public StopCommand() {
        super("stop");
    }

    @Override
    public void executeCommand(String... args) {
        if (args.length == 0) {
            SkyLicense.instance.stop();
            SkyLicense.LOG.info("System Exit.");
        }
    }
}

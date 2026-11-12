package cn.sky.skylicense.command.impl;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.command.Command;

public class HelpCommand extends Command {
    public HelpCommand() {
        super("help");
    }

    @Override
    public void executeCommand(String... args) {
        SkyLicense.instance.Usage();
    }
}

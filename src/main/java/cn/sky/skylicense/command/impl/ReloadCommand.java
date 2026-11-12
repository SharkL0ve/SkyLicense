package cn.sky.skylicense.command.impl;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.command.Command;

public class ReloadCommand extends Command {
    public ReloadCommand() {
        super("reload");
    }

    @Override
    public void executeCommand(String... args) {
        if (args.length == 0){
            if (SkyLicense.instance == null
                    || !SkyLicense.instance.reloadProtectedResources(true)) {
                SkyLicense.LOG.error("Resource reload failed; the previous snapshot remains active.");
                return;
            }
            if (!SkyLicense.configuration().reload()) {
                SkyLicense.LOG.error("Configuration reload failed; previous policy remains active.");
                return;
            }
            SkyLicense.LOG.info("Successful resource and configuration reloading.");
        }
    }
}

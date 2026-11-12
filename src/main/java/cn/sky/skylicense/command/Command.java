package cn.sky.skylicense.command;

import java.util.ArrayList;
import java.util.List;

public abstract class Command {
    private final String command;
    private final List<String> aliases;

    public Command(String command, List<String> aliases) {
        this.command = command;
        this.aliases = aliases;
    }

    public Command(String command) {
        this.command = command;
        this.aliases = new ArrayList<>();
    }

    public abstract void executeCommand(String... args);

    public final String getCommand() {
        return command;
    }

    public final List<String> getAliases() {
        return aliases;
    }
}

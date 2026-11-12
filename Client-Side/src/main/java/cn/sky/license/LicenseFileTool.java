package cn.sky.license;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;

/** Creates a v3 license.dat without exposing the authorization code as a CLI argument. */
public final class LicenseFileTool {
    private LicenseFileTool() {
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 1) {
            throw new IllegalArgumentException("usage: LicenseFileTool <output-license.dat>");
        }
        char[] input = readAuthorizationCode();
        byte[] encoded = null;
        try {
            encoded = LicenseFileCodec.encode(
                    input,
                    LicenseFileCodec.secretFromEnvironment());
            Path output = java.nio.file.Paths.get(arguments[0]).toAbsolutePath().normalize();
            Path parent = output.getParent();
            if (parent == null || !Files.isDirectory(parent)) {
                throw new IllegalArgumentException("output parent directory does not exist");
            }
            Path temporary = Files.createTempFile(parent, ".license-", ".part");
            try {
                Files.write(temporary, encoded);
                try {
                    Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE);
                } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                    Files.move(temporary, output);
                }
            } finally {
                Files.deleteIfExists(temporary);
            }
            System.out.println("license_file=" + output);
        } finally {
            Arrays.fill(input, '\0');
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    private static char[] readAuthorizationCode() throws Exception {
        Console console = System.console();
        if (console != null) {
            char[] value = console.readPassword("Authorization code: ");
            if (value == null || value.length == 0) {
                throw new IllegalArgumentException("authorization code must not be empty");
            }
            return value;
        }

        System.err.print("Authorization code: ");
        String value = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("authorization code must not be empty");
        }
        return value.toCharArray();
    }
}

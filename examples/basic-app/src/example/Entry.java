package example;

public final class Entry {
    public static void start() {
        System.out.println(message());
    }
    private static String message() {
        return "Protected DemoApp started successfully.";
    }
}

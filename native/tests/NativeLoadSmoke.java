public final class NativeLoadSmoke {
    private NativeLoadSmoke() {
    }

    public static void main(String[] arguments) {
        if (arguments.length != 1) {
            throw new IllegalArgumentException("expected an absolute native-library path");
        }
        System.load(arguments[0]);
        System.out.println("native_load_verified=true");
    }
}

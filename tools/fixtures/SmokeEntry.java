/** Uploaded to the real license server and delivered as encrypted/transformed classes. */
public final class SmokeEntry {
    public static void start() {
        verify();
        System.getProperties().put("skylicense.smoke.tick", (Runnable) SmokeEntry::verify);
        System.setProperty("skylicense.smoke.entry", "true");
    }

    private static void verify() {
        String text = message();
        Child child = new Child();
        if (!"hello".equals(text) || !"HELLO".equals(text.toUpperCase())
                || answer() != 42 || !"parent".equals(child.inherited())
                || !"default".equals(child.label()) || !"child".equals(child.value())) {
            throw new IllegalStateException("protected method bridge failed");
        }
        try {
            throwingMethod();
            throw new IllegalStateException("protected exception was swallowed");
        } catch (IllegalArgumentException expected) {
            if (!"expected protected exception".equals(expected.getMessage())) throw expected;
        }
    }

    private static String message() { return "hello"; }
    private static int answer() { return 42; }
    private static String throwingMethod() { throw new IllegalArgumentException("expected protected exception"); }

    public interface Named { default String label() { return "default"; } }
    public static class Parent {
        public String inherited() { return "parent"; }
        public Object value() { return "parent"; }
    }
    public static final class Child extends Parent implements Named {
        @Override public String value() { return "child"; }
    }
}

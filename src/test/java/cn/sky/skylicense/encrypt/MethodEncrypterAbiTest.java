package cn.sky.skylicense.encrypt;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MethodEncrypterAbiTest {
    @AfterEach
    void clearBridge() {
        DispatchBridge.authLib = null;
    }

    @Test
    void transformedClassCanInvokeTheStaticNativeBridge() throws Exception {
        String fixtureName = ProtectedDispatchFixture.class.getName();
        String fixtureResource = fixtureName.replace('.', '/') + ".class";
        byte[] original;
        try (InputStream input = MethodEncrypterAbiTest.class.getClassLoader()
                .getResourceAsStream(fixtureResource)) {
            if (input == null) {
                throw new IllegalStateException("fixture bytecode is missing");
            }
            original = input.readAllBytes();
        }

        byte[] transformed = EncryptUtil.encryptClass(
                "AbiPlugin",
                original,
                new HashMap<>(),
                new byte[32],
                DispatchBridge.class.getName().replace('.', '/'),
                Dispatch.class.getName().replace('.', '/'));
        DispatchBridge.authLib = (ignored, token) -> "dispatched";

        Class<?> fixture = new FixtureLoader().define(transformed);
        Method call = fixture.getDeclaredMethod("protectedCall");
        call.setAccessible(true);
        assertEquals("dispatched", call.invoke(null));
    }

    @FunctionalInterface
    public interface Dispatch {
        Object authenticate(Object value, String token);
    }

    public static final class DispatchBridge {
        public static volatile Dispatch authLib;

        private DispatchBridge() {
        }
    }

    static final class ProtectedDispatchFixture {
        private ProtectedDispatchFixture() {
        }

        static String protectedCall() {
            return System.lineSeparator();
        }
    }

    private static final class FixtureLoader extends ClassLoader {
        FixtureLoader() {
            super(MethodEncrypterAbiTest.class.getClassLoader());
        }

        Class<?> define(byte[] bytecode) {
            return defineClass(null, bytecode, 0, bytecode.length);
        }
    }
}

package cn.sky.license;

import org.junit.jupiter.api.Test;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class BasicLicenseClientTest {
    private static byte[] hex(String text) { return HexFormat.of().parseHex(text); }

    @Test
    void decryptsExistingV4InteroperabilityVectorAndRejectsTampering() throws Exception {
        byte[] key = hex("65c5f2dad7eb61583e7ab30df7ebefcd260e092f2bf8a8537c90ea1ad65fb4b0");
        byte[] aad = hex("536b794c6963656e7365207634207265736f757263652061616400"
                + "0202020202020202020202020202020202020202020202020202020202020202"
                + "00000007" + "0303030303030303030303030303030303030303030303030303030303030303"
                + "00000006706c7567696e00000005312e322e33");
        byte[] envelope = hex("534b595245533034000102030405060708090a0b"
                + "5e037fde97dcb8d1c77718b7f5cfadaac9bce06ded38748d987055c6a5146f"
                + "bc4bf07f79511d8dbc0ca55bbbfc0f");
        assertEquals("cross-language resource vector", new String(
                BasicLicenseClient.decrypt(envelope, key, aad, "SKYRES04"), StandardCharsets.UTF_8));
        aad[0] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> BasicLicenseClient.decrypt(envelope, key, aad, "SKYRES04"));
        aad[0] ^= 1;
        envelope[envelope.length - 1] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> BasicLicenseClient.decrypt(envelope, key, aad, "SKYRES04"));
    }

    @Test
    void rejectsWrongEnvelopeDomainAndOversizedInput() {
        assertThrows(GeneralSecurityException.class, () -> BasicLicenseClient.decrypt(
                new byte[36], new byte[32], new byte[0], "SKYRES04"));
        assertThrows(IOException.class, () -> BasicLicenseClient.readBounded(new ByteArrayInputStream(new byte[17]), 16));
    }

    interface Parent { default String inherited() { return "parent"; } }
    static class Child implements Parent { }
    static class ClassParent { public String inherited() { return "class"; } }
    static class ClassAndInterfaceChild extends ClassParent implements Parent { }
    static class GenericParent { public Object value() { return "object"; } }
    static class Covariant extends GenericParent { @Override public String value() { return "string"; } }

    @Test
    void classImplementationTakesPrecedenceOverInterfaceDefault() throws Exception {
        assertEquals(ClassParent.class, BasicLicenseClient.resolveMethod(
                ClassAndInterfaceChild.class, "inherited", MethodType.methodType(String.class)).getDeclaringClass());
    }

    @Test
    void resolvesInheritedAndCovariantJvmDescriptors() throws Exception {
        assertEquals(Parent.class, BasicLicenseClient.resolveMethod(
                Child.class, "inherited", MethodType.methodType(String.class)).getDeclaringClass());
        assertEquals(String.class, BasicLicenseClient.resolveMethod(
                Covariant.class, "value", MethodType.methodType(String.class)).getReturnType());
        assertEquals(Object.class, BasicLicenseClient.resolveMethod(
                Covariant.class, "value", MethodType.methodType(Object.class)).getReturnType());
        assertThrows(NoSuchMethodException.class, () -> BasicLicenseClient.resolveMethod(
                Child.class, "missing", MethodType.methodType(void.class)));
    }
}

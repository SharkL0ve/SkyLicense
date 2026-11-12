package cn.sky.skylicense.netty;

import org.junit.jupiter.api.Test;
import cn.sky.skylicense.security.NativeIdentifierValidator;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SocketHandlerValidationTest {

    @Test
    void acceptsOnlyCurrentHwidEncoding() {
        byte[] fingerprint = new byte[32];
        fingerprint[31] = 1;
        String encoded = Base64.getEncoder().encodeToString(fingerprint);

        assertTrue(SocketHandler.isValidHwid(encoded));
        assertFalse(SocketHandler.isValidHwid(Base64.getEncoder().encodeToString(new byte[32])));
        assertFalse(SocketHandler.isValidHwid("not-a-hwid"));
        assertFalse(SocketHandler.isValidHwid(encoded + "x"));
    }

    @Test
    void validatesResourceLicenseAndRelocationIdentities() {
        assertTrue(SocketHandler.isValidResourceIdentity("MyPlugin-1.0"));
        assertFalse(SocketHandler.isValidResourceIdentity("bad/name"));
        assertFalse(SocketHandler.isValidResourceIdentity("A".repeat(65)));

        assertTrue(SocketHandler.isValidLicenseCode("LICENSE-01"));
        assertFalse(SocketHandler.isValidLicenseCode("bad@code"));

        assertTrue(SocketHandler.isValidInternalClassName(
                "cn/sky/license/SkyLicense$IAuthLib"));
        assertFalse(SocketHandler.isValidInternalClassName("../Unsafe"));
        assertFalse(SocketHandler.isValidInternalClassName("cn.sky.Bad"));
    }

    @Test
    void canonicalizesOnlyIpLiterals() {
        assertEquals(
                "2001:db8::1",
                NativeIdentifierValidator.normalizeIpLiteral(" 2001:0db8:0:0::1 "));
        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> NativeIdentifierValidator.normalizeIpLiteral("license.example.com"));
    }
}

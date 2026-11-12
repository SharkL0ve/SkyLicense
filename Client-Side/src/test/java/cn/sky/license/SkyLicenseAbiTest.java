package cn.sky.license;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SkyLicenseAbiTest {
    @Test
    void exposesTheStaticNativeBridgeRequiredByProtectedClasses() throws Exception {
        Field field = SkyLicense.class.getField("authLib");

        assertEquals(SkyLicense.IAuthLib.class, field.getType());
        assertTrue(Modifier.isPublic(field.getModifiers()));
        assertTrue(Modifier.isStatic(field.getModifiers()));
    }
}

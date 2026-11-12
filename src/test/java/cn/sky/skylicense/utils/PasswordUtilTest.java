package cn.sky.skylicense.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordUtilTest {
    @Test
    void currentPasswordHashRoundTripsAndDoesNotNeedRehash() {
        String encoded = PasswordUtil.hashPassword("Correct-Horse-2026!");

        assertTrue(PasswordUtil.verifyPassword("Correct-Horse-2026!", encoded));
        assertFalse(PasswordUtil.verifyPassword("wrong-password", encoded));
        assertFalse(PasswordUtil.needsRehash(encoded));
    }

    @Test
    void attackerControlledCostAndMalformedLengthsAreRejected() {
        assertFalse(PasswordUtil.verifyPassword(
                "password",
                "2147483647:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:AAAA"));
        assertFalse(PasswordUtil.verifyPassword("password", "x".repeat(257)));
        assertTrue(PasswordUtil.needsRehash("100000:legacy:legacy"));
    }

    @Test
    void strengthPolicyRequiresLengthAndThreeCharacterClasses() {
        assertTrue(PasswordUtil.meetsStrengthRequirements("Correct-Horse-2026!"));
        assertFalse(PasswordUtil.meetsStrengthRequirements("onlylowercasepassword"));
        assertFalse(PasswordUtil.meetsStrengthRequirements("Short-1"));
    }
}

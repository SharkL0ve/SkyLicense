package cn.sky.skylicense.security;

import com.google.common.net.InetAddresses;

import java.net.InetAddress;
import java.util.Base64;
import java.util.regex.Pattern;

/** Shared canonical validation for identities crossing the native authentication boundary. */
public final class NativeIdentifierValidator {
    private static final int FINGERPRINT_BYTES = 32;
    private static final Pattern HWID_PATTERN = Pattern.compile("[A-Za-z0-9+/]{43}=");
    private static final Pattern RESOURCE_IDENTITY_PATTERN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}");
    private static final Pattern LICENSE_CODE_PATTERN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,255}");
    private static final Pattern QQ_PATTERN = Pattern.compile("[0-9]{1,20}");
    private static final Pattern INTERNAL_CLASS_NAME_PATTERN =
            Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(?:/[A-Za-z_$][A-Za-z0-9_$]*)*");

    private NativeIdentifierValidator() {
    }

    public static boolean isValidHwid(String value) {
        if (value == null || !HWID_PATTERN.matcher(value).matches()) {
            return false;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            return decoded.length == FINGERPRINT_BYTES && !allZero(decoded);
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    public static boolean isValidResourceIdentity(String value) {
        return value != null && RESOURCE_IDENTITY_PATTERN.matcher(value).matches();
    }

    public static boolean isValidLicenseCode(String value) {
        return value != null && LICENSE_CODE_PATTERN.matcher(value).matches();
    }

    public static boolean isValidQq(String value) {
        return value != null && QQ_PATTERN.matcher(value).matches();
    }

    public static boolean isValidInternalClassName(String value) {
        return value != null
                && value.length() <= 512
                && INTERNAL_CLASS_NAME_PATTERN.matcher(value).matches();
    }

    /** Accepts only numeric IP literals and returns one stable IPv4/IPv6 representation. */
    public static String normalizeIpLiteral(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("IP address must not be empty");
        }
        return InetAddresses.toAddrString(InetAddresses.forString(value.trim()));
    }

    public static String canonicalPeerAddress(InetAddress address) {
        if (address == null) {
            throw new IllegalArgumentException("peer address is missing");
        }
        return InetAddresses.toAddrString(address);
    }

    private static boolean allZero(byte[] value) {
        int difference = 0;
        for (byte current : value) {
            difference |= current;
        }
        return difference == 0;
    }
}

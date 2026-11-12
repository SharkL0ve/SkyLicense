package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.PasswordUtil;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Generates one-time recovery codes and stores only salted PBKDF2 hashes. */
final class MfaRecoveryCodes {
    static final int CODE_COUNT = 10;
    private static final int RAW_CODE_CHARACTERS = 16;
    private static final char[] ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    private MfaRecoveryCodes() {
    }

    static Generated generate() {
        List<String> displayCodes = new ArrayList<>(CODE_COUNT);
        List<String> hashes = new ArrayList<>(CODE_COUNT);
        for (int index = 0; index < CODE_COUNT; index++) {
            String normalized = randomCode();
            hashes.add(PasswordUtil.hashPassword(normalized));
            displayCodes.add(format(normalized));
        }
        return new Generated(List.copyOf(displayCodes), String.join("\n", hashes));
    }

    static Match findMatch(String encodedHashes, String supplied) {
        String normalized = normalize(supplied);
        List<String> hashes = parseHashes(encodedHashes);
        if (normalized == null || hashes.isEmpty()) {
            return Match.notFound(encodedHashes);
        }
        int matchIndex = -1;
        for (int index = 0; index < hashes.size(); index++) {
            if (PasswordUtil.verifyPassword(normalized, hashes.get(index))) {
                matchIndex = index;
            }
        }
        if (matchIndex < 0) {
            return Match.notFound(encodedHashes);
        }
        hashes.remove(matchIndex);
        return new Match(true, String.join("\n", hashes));
    }

    static int count(String encodedHashes) {
        return parseHashes(encodedHashes).size();
    }

    static boolean looksLikeRecoveryCode(String supplied) {
        return normalize(supplied) != null;
    }

    private static String randomCode() {
        StringBuilder code = new StringBuilder(RAW_CODE_CHARACTERS);
        for (int index = 0; index < RAW_CODE_CHARACTERS; index++) {
            code.append(ALPHABET[RANDOM.nextInt(ALPHABET.length)]);
        }
        return code.toString();
    }

    private static String normalize(String supplied) {
        if (supplied == null || supplied.length() > 64) {
            return null;
        }
        String normalized = supplied.replace("-", "")
                .replace(" ", "")
                .toUpperCase(Locale.ROOT);
        if (normalized.length() != RAW_CODE_CHARACTERS) {
            return null;
        }
        for (int index = 0; index < normalized.length(); index++) {
            char character = normalized.charAt(index);
            boolean found = false;
            for (char allowed : ALPHABET) {
                found |= character == allowed;
            }
            if (!found) {
                return null;
            }
        }
        return normalized;
    }

    private static String format(String normalized) {
        return normalized.substring(0, 4) + "-" + normalized.substring(4, 8)
                + "-" + normalized.substring(8, 12) + "-" + normalized.substring(12);
    }

    private static List<String> parseHashes(String encodedHashes) {
        if (encodedHashes == null || encodedHashes.isEmpty() || encodedHashes.length() > 4_096) {
            return new ArrayList<>();
        }
        String[] parts = encodedHashes.split("\n", -1);
        if (parts.length > CODE_COUNT) {
            return new ArrayList<>();
        }
        List<String> hashes = new ArrayList<>(parts.length);
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 256) {
                return new ArrayList<>();
            }
            hashes.add(part);
        }
        return hashes;
    }

    record Generated(List<String> displayCodes, String encodedHashes) {
    }

    record Match(boolean matched, String remainingHashes) {
        static Match notFound(String unchanged) {
            return new Match(false, unchanged);
        }
    }
}

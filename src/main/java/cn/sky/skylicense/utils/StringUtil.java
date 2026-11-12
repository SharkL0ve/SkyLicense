package cn.sky.skylicense.utils;

import java.security.SecureRandom;

public class StringUtil {
    private static final String CHARACTERS = "abcdef";
    private static final String NUMBERS = "0123456789";
    private static final int UUID_LENGTH = 36;
    private static final SecureRandom random = new SecureRandom();


    public static String generateCustomUUID() {
        StringBuilder sb = new StringBuilder(UUID_LENGTH);
        int numLetter = 25;
        char lastChar1 = ' ';
        char lastChar2 = ' ';
        for (int i = 0; i < UUID_LENGTH; i++) {
            if (i == 9 || i == 14 || i == 19 || i == 24) {
                sb.append('-');
            } else if (i == 10 || i == 11 || i == 12 || i == 13 ||
                    i == 15 || i == 16 || i == 17 || i == 18 ||
                    i == 20 || i == 21 || i == 22 || i == 23) {
                sb.append(NUMBERS.charAt(random.nextInt(NUMBERS.length())));
            } else {
                char c;
                boolean isLetter;
                if (numLetter > 0 && (random.nextInt(100) < 50)) {
                    isLetter = true;
                    c = CHARACTERS.charAt(random.nextInt(CHARACTERS.length()));
                    numLetter--;
                } else {
                    isLetter = false;
                    c = NUMBERS.charAt(random.nextInt(NUMBERS.length()));
                }
                if ((isLetter && Character.isLetter(lastChar1) && Character.isLetter(lastChar2)) || (!isLetter && Character.isDigit(lastChar1) && Character.isDigit(lastChar2))) {
                    isLetter = !isLetter;
                    if (isLetter) {
                        c = CHARACTERS.charAt(random.nextInt(CHARACTERS.length()));
                        numLetter--;
                    } else {
                        c = NUMBERS.charAt(random.nextInt(NUMBERS.length()));
                    }
                }
                sb.append(c);
                lastChar2 = lastChar1;
                lastChar1 = c;
            }
        }
        return sb.toString();
    }

    public static String generateRandomString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            sb.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        sb.append("-");
        for (int i = 0; i < 4; i++) {
            sb.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        sb.append("-");
        for (int i = 0; i < 4; i++) {
            sb.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        sb.append("-");
        for (int i = 0; i < 5; i++) {
            sb.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        return sb.toString();
    }
}
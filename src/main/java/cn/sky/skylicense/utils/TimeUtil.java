package cn.sky.skylicense.utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * @author Araykal
 * @since 2025/1/22
 */
public class TimeUtil {
    public static String getCurtTime() {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd-HH:mm");
        return now.format(formatter);
    }
}

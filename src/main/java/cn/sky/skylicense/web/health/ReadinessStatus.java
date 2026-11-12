package cn.sky.skylicense.web.health;

@FunctionalInterface
public interface ReadinessStatus {
    boolean isReady();
}

package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.web.health.ReadinessStatus;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class HealthController {
    private static final HealthStatus UP = new HealthStatus("UP");
    private static final HealthStatus DOWN = new HealthStatus("DOWN");
    private final ReadinessStatus readiness;

    public HealthController(ReadinessStatus readiness) {
        this.readiness = readiness;
    }

    @GetMapping(path = "/health/live", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<HealthStatus> live() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(UP);
    }

    @GetMapping(path = "/health/ready", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<HealthStatus> ready() {
        boolean ready;
        try {
            ready = readiness.isReady();
        } catch (RuntimeException ignored) {
            ready = false;
        }
        return ResponseEntity.status(ready ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE)
                .cacheControl(CacheControl.noStore())
                .body(ready ? UP : DOWN);
    }

    public record HealthStatus(String status) {
    }
}

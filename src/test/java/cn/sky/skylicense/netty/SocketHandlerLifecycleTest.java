package cn.sky.skylicense.netty;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class SocketHandlerLifecycleTest {
    @Test
    void resourceWorkersCanBeStoppedAndStartedAcrossLifecycles() {
        assertDoesNotThrow(SocketHandler::startResourceExecutor);
        assertDoesNotThrow(SocketHandler::shutdownResourceExecutor);
        assertDoesNotThrow(SocketHandler::shutdownResourceExecutor);
        assertDoesNotThrow(SocketHandler::startResourceExecutor);
        assertDoesNotThrow(SocketHandler::shutdownResourceExecutor);
    }
}

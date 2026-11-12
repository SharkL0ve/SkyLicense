package cn.sky.skylicense.netty;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class SocketMangerLifecycleTest {
    @Test
    void stopIsIdempotentBeforeListenerStartup() {
        SocketManger manager = new SocketManger(0);

        org.junit.jupiter.api.Assertions.assertFalse(manager.isAcceptingConnections());
        assertDoesNotThrow(manager::stopAccepting);
        assertDoesNotThrow(manager::stop);
        assertDoesNotThrow(manager::stop);
        org.junit.jupiter.api.Assertions.assertFalse(manager.isAcceptingConnections());
    }
}

package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.web.config.WebConfig;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

class HealthControllerTest {
    @Test
    void liveProbeIsUnauthenticatedMinimalAndUncached() throws Exception {
        MockMvc mvc = MockMvcBuilders
                .standaloneSetup(new HealthController(() -> false))
                .addFilters(new WebConfig().securityHeadersFilter().getFilter())
                .build();

        MvcResult result = mvc.perform(get("/health/live")).andReturn();

        assertEquals(200, result.getResponse().getStatus());
        assertEquals("no-store", result.getResponse().getHeader("Cache-Control"));
        assertEquals(List.of("no-store"),
                result.getResponse().getHeaders("Cache-Control"));
        assertEquals("{\"status\":\"UP\"}", result.getResponse().getContentAsString());
    }

    @Test
    void readinessReturns503UntilAllRuntimeChecksPasses() throws Exception {
        MockMvc notReady = MockMvcBuilders
                .standaloneSetup(new HealthController(() -> false)).build();
        MvcResult down = notReady.perform(get("/health/ready")).andReturn();
        assertEquals(503, down.getResponse().getStatus());
        assertEquals("no-store", down.getResponse().getHeader("Cache-Control"));
        assertTrue(down.getResponse().getContentAsString().contains("DOWN"));

        MockMvc ready = MockMvcBuilders
                .standaloneSetup(new HealthController(() -> true)).build();
        MvcResult up = ready.perform(get("/health/ready")).andReturn();
        assertEquals(200, up.getResponse().getStatus());
        assertTrue(up.getResponse().getContentAsString().contains("UP"));
    }
}

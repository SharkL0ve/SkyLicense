package cn.sky.skylicense.web.exception;

import cn.sky.skylicense.web.dto.request.CreateUserRequest;
import cn.sky.skylicense.web.dto.response.ApiResponse;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import jakarta.validation.Valid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GlobalExceptionHandlerMvcTest {
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new ValidationProbeController())
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void beanValidationFailureUsesHttp400AndTheJsonErrorEnvelope() throws Exception {
        MvcResult result = mvc.perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.post("/probe")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"ab\",\"password\":\"short\"}"))
                .andReturn();

        assertBadRequestEnvelope(result);
    }

    @Test
    void malformedJsonUsesHttp400AndTheJsonErrorEnvelope() throws Exception {
        MvcResult result = mvc.perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.post("/probe")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":"))
                .andReturn();

        assertBadRequestEnvelope(result);
    }

    @Test
    void queryTypeMismatchUsesHttp400AndTheJsonErrorEnvelope() throws Exception {
        MvcResult result = mvc.perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.get("/probe").param("page", "not-a-number"))
                .andReturn();

        assertBadRequestEnvelope(result);
    }

    @Test
    void missingRequiredQueryUsesHttp400AndTheJsonErrorEnvelope() throws Exception {
        MvcResult result = mvc.perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.get("/probe"))
                .andReturn();

        assertBadRequestEnvelope(result);
    }

    @Test
    void unsupportedMethodUsesHttp405AndTheJsonErrorEnvelope() throws Exception {
        MvcResult result = mvc.perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.put("/probe"))
                .andReturn();

        assertEquals(405, result.getResponse().getStatus());
        assertEquals(
                Set.of("GET", "POST"),
                Set.of(result.getResponse().getHeader("Allow").split(",")));
        JsonObject body = JsonParser.parseString(result.getResponse().getContentAsString())
                .getAsJsonObject();
        assertEquals(405, body.get("code").getAsInt());
        assertEquals("不支持的请求方法", body.get("message").getAsString());
    }

    @Test
    void unsupportedContentTypeUsesHttp415AndTheJsonErrorEnvelope() throws Exception {
        MvcResult result = mvc.perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.post("/probe")
                        .contentType(MediaType.MULTIPART_FORM_DATA)
                        .content("not-a-json-request"))
                .andReturn();

        assertEquals(415, result.getResponse().getStatus());
        JsonObject body = JsonParser.parseString(result.getResponse().getContentAsString())
                .getAsJsonObject();
        assertEquals(415, body.get("code").getAsInt());
        assertEquals("不支持的请求内容类型", body.get("message").getAsString());
    }

    private static void assertBadRequestEnvelope(MvcResult result) throws Exception {
        assertEquals(400, result.getResponse().getStatus());
        JsonObject body = JsonParser.parseString(result.getResponse().getContentAsString())
                .getAsJsonObject();
        assertEquals(400, body.get("code").getAsInt());
        assertEquals(false, body.get("message").getAsString().isBlank());
    }

    @RestController
    private static final class ValidationProbeController {
        @PostMapping("/probe")
        ApiResponse<Void> body(@Valid @RequestBody CreateUserRequest request) {
            return ApiResponse.ok(null);
        }

        @GetMapping("/probe")
        ApiResponse<Void> query(@RequestParam int page) {
            return ApiResponse.ok(null);
        }
    }
}

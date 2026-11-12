package cn.sky.skylicense.web.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiResponseTest {

    @Test
    void nullDataRemainsInTheEnvelopeWithProductionInclusionRules() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setDefaultPropertyInclusion(JsonInclude.Include.NON_NULL);

        JsonNode response = mapper.readTree(mapper.writeValueAsBytes(
                ApiResponse.ok("completed", null)));

        assertTrue(response.has("data"));
        assertTrue(response.get("data").isNull());
    }
}

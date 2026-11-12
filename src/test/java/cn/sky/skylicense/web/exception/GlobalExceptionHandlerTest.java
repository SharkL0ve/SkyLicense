package cn.sky.skylicense.web.exception;

import cn.sky.skylicense.web.dto.response.ApiResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void mapsBusinessStatusToTheActualHttpStatus() {
        ResponseEntity<ApiResponse<?>> response =
                handler.handleBizException(BizException.notFound("missing"));

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(404, response.getBody().getCode());
    }

    @Test
    void keepsInvalidBusinessStatusFailSafeAsBadRequest() {
        ResponseEntity<ApiResponse<?>> response =
                handler.handleBizException(new BizException(700, "invalid"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(700, response.getBody().getCode());
    }

    @Test
    void mapsDatabaseConstraintRacesToConflictWithoutLeakingSql() {
        SQLException constraint = new SQLException(
                "[SQLITE_CONSTRAINT_UNIQUE] UNIQUE constraint failed: web_user.username",
                null,
                19);

        ResponseEntity<ApiResponse<?>> response =
                handler.handleDatabaseException(constraint);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertEquals(409, response.getBody().getCode());
        assertEquals("请求与现有数据冲突，请刷新后重试", response.getBody().getMessage());
    }

    @Test
    void mapsMultipartLimitFailuresToPayloadTooLarge() {
        ApiResponse<?> response = handler.handleUploadTooLarge(
                new MaxUploadSizeExceededException(64L * 1024L * 1024L));

        assertEquals(413, response.getCode());
        assertEquals("请求内容超过大小限制", response.getMessage());
    }

    @Test
    void mapsMissingRequestParametersToBadRequest() {
        ApiResponse<?> response = handler.handleRequestBinding(
                new MissingServletRequestParameterException("status", "int"));

        assertEquals(400, response.getCode());
        assertEquals("缺少或无法绑定必要的请求参数", response.getMessage());
    }

    @Test
    void mapsUnsupportedMethodsAndPreservesTheAllowHeader() {
        ResponseEntity<ApiResponse<?>> response = handler.handleMethodNotSupported(
                new HttpRequestMethodNotSupportedException("PATCH", List.of("GET", "POST")));

        assertEquals(HttpStatus.METHOD_NOT_ALLOWED, response.getStatusCode());
        assertEquals(Set.of(HttpMethod.GET, HttpMethod.POST), response.getHeaders().getAllow());
        assertEquals(405, response.getBody().getCode());
    }

    @Test
    void mapsMissingResourcesToNotFound() {
        ApiResponse<?> response = handler.handleNotFound(
                new NoResourceFoundException(HttpMethod.GET, "missing.js"));

        assertEquals(404, response.getCode());
        assertEquals("请求的资源不存在", response.getMessage());
    }
}

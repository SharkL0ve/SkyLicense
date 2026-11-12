package cn.sky.skylicense.web.exception;

import cn.sky.skylicense.web.dto.response.ApiResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.validation.BindException;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.sql.SQLException;
import java.util.Locale;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOG = LogManager.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(BizException.class)
    public ResponseEntity<ApiResponse<?>> handleBizException(BizException e) {
        HttpStatus status = HttpStatus.resolve(e.getCode());
        if (status == null || status.is1xxInformational() || status.is3xxRedirection()) {
            status = HttpStatus.BAD_REQUEST;
        }
        return ResponseEntity.status(status).body(ApiResponse.error(e.getCode(), e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<?> handleValidationException(MethodArgumentNotValidException e) {
        String message = validationMessage(e.getBindingResult().getFieldErrors());
        return ApiResponse.error(400, message);
    }

    @ExceptionHandler(BindException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<?> handleBindException(BindException e) {
        return ApiResponse.error(400, validationMessage(e.getBindingResult().getAllErrors()));
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<?> handleMethodValidationException(HandlerMethodValidationException e) {
        String message = e.getAllErrors().stream()
                .map(MessageSourceResolvable::getDefaultMessage)
                .filter(value -> value != null && !value.isBlank())
                .collect(Collectors.joining("; "));
        return ApiResponse.error(400, message.isBlank() ? "请求参数校验失败" : message);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<?> handleConstraintViolation(ConstraintViolationException e) {
        String message = e.getConstraintViolations().stream()
                .map(ConstraintViolation::getMessage)
                .collect(Collectors.joining("; "));
        return ApiResponse.error(400, message);
    }

    @ExceptionHandler({MethodArgumentTypeMismatchException.class, HttpMessageNotReadableException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<?> handleMalformedRequest(Exception ignored) {
        return ApiResponse.error(400, "请求参数格式无效");
    }

    @ExceptionHandler(ServletRequestBindingException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<?> handleRequestBinding(ServletRequestBindingException ignored) {
        return ApiResponse.error(400, "缺少或无法绑定必要的请求参数");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<?>> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException error
    ) {
        HttpHeaders headers = new HttpHeaders();
        if (error.getSupportedHttpMethods() != null) {
            headers.setAllow(error.getSupportedHttpMethods());
        }
        return new ResponseEntity<>(
                ApiResponse.error(405, "不支持的请求方法"),
                headers,
                HttpStatus.METHOD_NOT_ALLOWED);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    @ResponseStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
    public ApiResponse<?> handleUnsupportedMediaType(HttpMediaTypeNotSupportedException ignored) {
        return ApiResponse.error(415, "不支持的请求内容类型");
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public ResponseEntity<Void> handleUnacceptableMediaType(
            HttpMediaTypeNotAcceptableException ignored
    ) {
        return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).build();
    }

    @ExceptionHandler(MultipartException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<?> handleMalformedMultipart(MultipartException ignored) {
        return ApiResponse.error(400, "multipart 请求格式无效");
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
    public ApiResponse<?> handleUploadTooLarge(MaxUploadSizeExceededException ignored) {
        return ApiResponse.error(413, "请求内容超过大小限制");
    }

    @ExceptionHandler({NoHandlerFoundException.class, NoResourceFoundException.class})
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApiResponse<?> handleNotFound(Exception ignored) {
        return ApiResponse.error(404, "请求的资源不存在");
    }

    @ExceptionHandler(SQLException.class)
    public ResponseEntity<ApiResponse<?>> handleDatabaseException(SQLException error) {
        if (isConstraintViolation(error)) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponse.error(409, "请求与现有数据冲突，请刷新后重试"));
        }
        LOG.error("Unexpected database error", error);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(500, "服务器内部错误"));
    }

    private static String validationMessage(java.util.List<? extends MessageSourceResolvable> errors) {
        String message = errors.stream()
                .map(MessageSourceResolvable::getDefaultMessage)
                .filter(value -> value != null && !value.isBlank())
                .collect(Collectors.joining("; "));
        return message.isBlank() ? "请求参数校验失败" : message;
    }

    private static boolean isConstraintViolation(SQLException error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (current instanceof SQLException sqlException
                    && (sqlException.getErrorCode() == 19
                    || "23000".equals(sqlException.getSQLState()))) {
                return true;
            }
            String message = current.getMessage();
            if (message != null) {
                String normalized = message.toLowerCase(Locale.ROOT);
                if (normalized.contains("unique constraint")
                        || normalized.contains("not null constraint")
                        || normalized.contains("foreign key constraint")) {
                    return true;
                }
            }
        }
        return false;
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiResponse<?> handleException(Exception e) {
        LOG.error("Unexpected error", e);
        return ApiResponse.error(500, "服务器内部错误");
    }
}

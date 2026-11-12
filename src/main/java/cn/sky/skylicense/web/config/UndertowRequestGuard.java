package cn.sky.skylicense.web.config;

import io.undertow.server.HttpHandler;
import io.undertow.util.Headers;
import io.undertow.util.Methods;
import io.undertow.util.PathTemplate;
import io.undertow.util.StatusCodes;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

final class UndertowRequestGuard {
    static final long MAX_UPLOAD_REQUEST_BYTES = 65L * 1024L * 1024L;
    private static final String MULTIPART_FORM_DATA = "multipart/form-data";
    private static final PathTemplate VERSION_UPLOAD_PATH =
            PathTemplate.create("/api/programs/{id}/versions");

    private UndertowRequestGuard() {
    }

    static HttpHandler wrap(HttpHandler next) {
        Objects.requireNonNull(next, "next");
        return exchange -> {
            String contentType = exchange.getRequestHeaders().getFirst(Headers.CONTENT_TYPE);
            boolean multipart = isMultipartFormData(contentType);

            // GHSA-3x3v-w654-m28m: parameter access can parse GET multipart bodies to disk.
            if (multipart && (Methods.GET.equals(exchange.getRequestMethod())
                    || Methods.HEAD.equals(exchange.getRequestMethod()))) {
                reject(exchange, StatusCodes.UNSUPPORTED_MEDIA_TYPE);
                return;
            }

            if (multipart
                    && Methods.POST.equals(exchange.getRequestMethod())
                    && isVersionUploadPath(exchange.getRequestPath())) {
                exchange.setMaxEntitySize(MAX_UPLOAD_REQUEST_BYTES);
            }
            long contentLength = exchange.getRequestContentLength();
            long maxEntitySize = exchange.getMaxEntitySize();
            if (contentLength > 0
                    && maxEntitySize > 0
                    && contentLength > maxEntitySize) {
                reject(exchange, StatusCodes.REQUEST_ENTITY_TOO_LARGE);
                return;
            }
            next.handleRequest(exchange);
        };
    }

    private static void reject(io.undertow.server.HttpServerExchange exchange, int statusCode) {
        exchange.setPersistent(false);
        exchange.setStatusCode(statusCode);
        exchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-store");
        exchange.getResponseHeaders().put(Headers.X_CONTENT_TYPE_OPTIONS, "nosniff");
        exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, "0");
        exchange.endExchange();
    }

    static boolean isMultipartFormData(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return false;
        }
        try {
            MediaType mediaType = MediaType.parseMediaType(contentType);
            return MULTIPART_FORM_DATA.equalsIgnoreCase(
                    mediaType.getType() + "/" + mediaType.getSubtype());
        } catch (InvalidMediaTypeException ignored) {
            int parameterStart = contentType.indexOf(';');
            String type = parameterStart < 0
                    ? contentType.trim()
                    : contentType.substring(0, parameterStart).trim();
            return MULTIPART_FORM_DATA.equalsIgnoreCase(type);
        }
    }

    static boolean isVersionUploadPath(String requestPath) {
        if (requestPath == null) {
            return false;
        }
        Map<String, String> parameters = new HashMap<>();
        if (!VERSION_UPLOAD_PATH.matches(requestPath, parameters)) {
            return false;
        }
        String id = parameters.get("id");
        try {
            return id != null && Long.parseLong(id) > 0;
        } catch (NumberFormatException ignored) {
            return false;
        }
    }
}

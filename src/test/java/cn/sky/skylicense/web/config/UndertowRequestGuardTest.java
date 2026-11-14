package cn.sky.skylicense.web.config;

import io.undertow.Undertow;
import io.undertow.UndertowOptions;
import io.undertow.server.HttpHandler;
import io.undertow.server.RequestTooBigException;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.util.StatusCodes;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UndertowRequestGuardTest {
    private static final int DEFAULT_ENTITY_LIMIT = 2 * 1024 * 1024;

    @Test
    void recognizesOnlyMultipartFormData() {
        assertTrue(UndertowRequestGuard.isMultipartFormData(
                "multipart/form-data; boundary=test"));
        assertTrue(UndertowRequestGuard.isMultipartFormData(
                "Multipart/Form-Data ; boundary=test"));
        assertFalse(UndertowRequestGuard.isMultipartFormData("multipart/mixed"));
        assertFalse(UndertowRequestGuard.isMultipartFormData("multipart/form-datax"));
        assertFalse(UndertowRequestGuard.isMultipartFormData(null));
    }

    @Test
    void raisesEntityLimitOnlyForTheVersionUploadRoute() {
        assertTrue(UndertowRequestGuard.isVersionUploadPath(
                "/api/programs/42/versions"));
        assertFalse(UndertowRequestGuard.isVersionUploadPath(
                "/api/programs/not-a-number/versions"));
        assertFalse(UndertowRequestGuard.isVersionUploadPath(
                "/api/programs/42/auth-logs"));
        assertFalse(UndertowRequestGuard.isVersionUploadPath(
                "/api/admin/programs/42/versions"));
    }

    @Test
    void rejectsBodylessMultipartMethodsBeforeServletDispatch() throws Exception {
        AtomicInteger delegated = new AtomicInteger();
        try (GuardedServer server = startServer(exchange -> {
            delegated.incrementAndGet();
            exchange.setStatusCode(StatusCodes.NO_CONTENT);
            exchange.endExchange();
        })) {
            HttpResponse<byte[]> get = server.send(request(
                    server.uri("/health/live"), "GET", new byte[0], true));
            HttpResponse<byte[]> head = server.send(request(
                    server.uri("/health/live"), "HEAD", new byte[0], true));
            HttpResponse<byte[]> ordinaryGet = server.send(request(
                    server.uri("/health/live"), "GET", new byte[0], false));

            assertEquals(StatusCodes.UNSUPPORTED_MEDIA_TYPE, get.statusCode());
            assertEquals(StatusCodes.UNSUPPORTED_MEDIA_TYPE, head.statusCode());
            assertEquals("no-store", get.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals(StatusCodes.NO_CONTENT, ordinaryGet.statusCode());
            assertEquals(1, delegated.get());
        }
    }

    @Test
    void acceptsMultipartUploadAboveTheDefaultUndertowLimitOnlyOnUploadRoute()
            throws Exception {
        byte[] body = new byte[3 * 1024 * 1024];
        AtomicInteger delegated = new AtomicInteger();
        HttpHandler receiver = exchange -> exchange.getRequestReceiver().receiveFullBytes(
                (completed, data) -> {
                    delegated.incrementAndGet();
                    completed.setStatusCode(StatusCodes.NO_CONTENT);
                    completed.endExchange();
                },
                (failed, error) -> {
                    failed.setStatusCode(error instanceof RequestTooBigException
                            ? StatusCodes.REQUEST_ENTITY_TOO_LARGE
                            : StatusCodes.INTERNAL_SERVER_ERROR);
                    failed.endExchange();
                });

        try (GuardedServer server = startServer(receiver)) {
            HttpResponse<byte[]> upload = server.send(request(
                    server.uri("/api/programs/42/versions?version=1.0.0"),
                    "POST", body, true));
            HttpResponse<byte[]> other = server.send(request(
                    server.uri("/api/auth/login"), "POST", body, true, true));

            assertEquals(StatusCodes.NO_CONTENT, upload.statusCode());
            assertEquals(StatusCodes.REQUEST_ENTITY_TOO_LARGE, other.statusCode());
            assertEquals("no-store", other.headers()
                    .firstValue("Cache-Control").orElseThrow());
            assertEquals(1, delegated.get());
        }
    }

    @Test
    void rejectsKnownOversizedBodiesBeforeDelegating() throws Exception {
        AtomicInteger delegated = new AtomicInteger();
        try (GuardedServer server = startServer(exchange -> {
            delegated.incrementAndGet();
            exchange.setStatusCode(StatusCodes.NO_CONTENT);
            exchange.endExchange();
        })) {
            HttpResponse<byte[]> response = server.send(request(
                    server.uri("/api/auth/login"),
                    "POST", new byte[3 * 1024 * 1024], false, true));

            assertEquals(StatusCodes.REQUEST_ENTITY_TOO_LARGE, response.statusCode());
            assertEquals("no-store", response.headers()
                    .firstValue("Cache-Control").orElseThrow());
            assertEquals(0, response.body().length);
            assertEquals(0, delegated.get());
        }
    }

    private static GuardedServer startServer(HttpHandler delegate) {
        DeploymentInfo deploymentInfo = new DeploymentInfo();
        new WebConfig().undertowRequestGuard().customize(deploymentInfo);
        assertEquals(1, deploymentInfo.getInitialHandlerChainWrappers().size());

        HttpHandler guarded = deploymentInfo.getInitialHandlerChainWrappers()
                .get(0)
                .wrap(delegate);
        Undertow undertow = Undertow.builder()
                .addHttpListener(0, "127.0.0.1")
                .setServerOption(UndertowOptions.MAX_ENTITY_SIZE, (long) DEFAULT_ENTITY_LIMIT)
                .setHandler(guarded)
                .build();
        undertow.start();
        InetSocketAddress address = (InetSocketAddress) undertow.getListenerInfo()
                .get(0)
                .getAddress();
        return new GuardedServer(undertow, address.getPort());
    }

    private static HttpRequest request(
            URI uri,
            String method,
            byte[] body,
            boolean multipart
    ) {
        return request(uri, method, body, multipart, false);
    }

    private static HttpRequest request(
            URI uri,
            String method,
            byte[] body,
            boolean multipart,
            boolean expectContinue
    ) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(15))
                // The guard intentionally closes oversized requests without
                // draining their bodies. Negotiate headers first so this test
                // observes the early 413 rather than an OS-dependent upload reset.
                .expectContinue(expectContinue)
                .method(method, HttpRequest.BodyPublishers.ofByteArray(body));
        if (multipart) {
            builder.header("Content-Type", "multipart/form-data; boundary=test");
        }
        return builder.build();
    }

    private record GuardedServer(Undertow server, int port) implements AutoCloseable {
        URI uri(String path) {
            return URI.create("http://127.0.0.1:" + port + path);
        }

        HttpResponse<byte[]> send(HttpRequest request) throws Exception {
            return HttpClient.newHttpClient().send(
                    request, HttpResponse.BodyHandlers.ofByteArray());
        }

        @Override
        public void close() {
            server.stop();
        }
    }
}

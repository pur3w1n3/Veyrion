package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** POST /providers/detect-protocol 授权、探测结果与密钥脱敏验收。 */
public final class ProviderProtocolDetectControlPlaneAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String SECRET = "detect-control-secret-77ae";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = Files.createTempDirectory("veyrion-provider-detect");
        Path database = root.resolve("state").resolve("control-plane.db");
        String bootstrap = "provider-detect-bootstrap";
        HttpClient client = HttpClient.newHttpClient();

        try (MockProvider mock = MockProvider.openAiOnly(SECRET);
             ControlPlaneServer server = new ControlPlaneServer(
                     root, 0, bootstrap, database).start()) {
            String viewerPat = text(ok(send(client, uri(server, "/operators"), "POST",
                    "{\"username\":\"detect-viewer\",\"role\":\"VIEWER\"}", bootstrap)),
                    "personalAccessToken");

            String body = "{\"baseUrl\":\"" + mock.baseUrl() + "/v1\",\"apiKey\":\"" + SECRET + "\"}";
            check(send(client, uri(server, "/providers/detect-protocol"), "POST", body, viewerPat)
                            .statusCode() == 403,
                    "viewer cannot detect protocol");
            check(send(client, uri(server, "/providers/detect-protocol"), "POST", body,
                            server.workerToken()).statusCode() == 401,
                    "worker cannot detect protocol");

            HttpResponse<String> response = send(client,
                    uri(server, "/providers/detect-protocol"), "POST", body, bootstrap);
            Map<String, Object> detection = ok(response);
            check("MULTIPLE".equals(detection.get("status"))
                            || "UNIQUE".equals(detection.get("status")),
                    "detect returns a terminal status");
            check("OPENAI_CHAT".equals(detection.get("recommendedKind")),
                    "OpenAI Chat recommended when OpenAI wire accepts");
            check(detection.get("candidates") instanceof List<?> candidates && !candidates.isEmpty(),
                    "candidates are present");
            check(!response.body().contains(SECRET), "detect response must not leak credential");

            String savedId = text(ok(send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"Stored\",\"kind\":\"OPENAI_CHAT\",\"baseUrl\":\""
                            + mock.baseUrl() + "/v1\",\"enabled\":true,\"apiKey\":\"" + SECRET + "\"}",
                    bootstrap)), "providerId");
            HttpResponse<String> reuse = send(client, uri(server, "/providers/detect-protocol"),
                    "POST",
                    "{\"baseUrl\":\"" + mock.baseUrl() + "/v1\",\"providerId\":\"" + savedId + "\"}",
                    bootstrap);
            check(reuse.statusCode() == 200 && !reuse.body().contains(SECRET),
                    "stored credential path works and stays redacted");

            check(send(client, uri(server, "/providers/detect-protocol"), "POST",
                            "{\"baseUrl\":\"" + mock.baseUrl() + "/v1\"}", bootstrap)
                            .statusCode() == 400,
                    "missing credential fails closed");
        }

        System.out.println("ProviderProtocolDetectControlPlaneAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method,
                                             String json, String token) throws Exception {
        HttpRequest.BodyPublisher publisher = json.isEmpty()
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json);
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json");
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(request.method(method, publisher).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "unexpected response " + response.statusCode() + ": " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static String text(Map<?, ?> value, String key) {
        Object result = value.get(key);
        check(result instanceof String && !((String) result).isBlank(), key + " is required");
        return (String) result;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    private record MockProvider(HttpServer server) implements AutoCloseable {
        static MockProvider openAiOnly(String secret) throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            AtomicReference<Throwable> failure = new AtomicReference<>();
            server.createContext("/", exchange -> {
                try {
                    String auth = exchange.getRequestHeaders().getFirst("Authorization");
                    if (("Bearer " + secret).equals(auth)) {
                        json(exchange, 200, "{\"data\":[{\"id\":\"gpt-a\"}]}");
                    } else {
                        json(exchange, 401, "{\"error\":\"denied\"}");
                    }
                } catch (Throwable handlerFailure) {
                    failure.compareAndSet(null, handlerFailure);
                    exchange.close();
                }
            });
            server.start();
            return new MockProvider(server);
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
        }

        private static void json(HttpExchange exchange, int status, String body) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        }
    }
}

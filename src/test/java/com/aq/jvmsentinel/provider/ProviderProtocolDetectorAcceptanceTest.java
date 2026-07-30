package com.aq.jvmsentinel.provider;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.ProviderProtocolDetector.DetectionResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** 协议探测：按真实 auth/响应判定可用 kind；URL 只影响探测顺序。 */
public final class ProviderProtocolDetectorAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final Instant NOW = Instant.parse("2026-07-30T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String SECRET = "detect-secret-must-never-leak-41bf";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        openAiOnlyYieldsMultipleOpenAiFamilyKinds();
        anthropicOnlyIsUnique();
        bothProtocolsYieldMultiple();
        allFailuresAreNoneWithoutLeakingSecret();
        wireOrderPrefersAnthropicWhenHostHints();
        System.out.println("ProviderProtocolDetectorAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void openAiOnlyYieldsMultipleOpenAiFamilyKinds() throws Exception {
        try (MockServer mock = server(exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (("Bearer " + SECRET).equals(auth)) {
                check(exchange.getRequestURI().getRawQuery().contains("limit=1"),
                        "probe uses limit=1");
                json(exchange, 200, "{\"data\":[{\"id\":\"gpt-probe\"}]}");
                return;
            }
            json(exchange, 401, "{\"error\":\"no\"}");
        })) {
            DetectionResult result = detector().detect(mock.uri("/v1"), secret());
            check("MULTIPLE".equals(result.status()), "OpenAI wire success expands to multiple kinds");
            check(result.recommendedKind() == ProviderKind.OPENAI_CHAT, "recommend OpenAI Chat");
            check(result.candidates().stream().anyMatch(item ->
                            item.kind() == ProviderKind.OPENAI_COMPATIBLE && item.viable()),
                    "OpenAI-compatible offered as same-wire alternative");
            check(result.candidates().stream().anyMatch(item ->
                            item.kind() == ProviderKind.LOCAL && item.viable()),
                    "loopback also offers LOCAL");
            check(result.candidates().stream().noneMatch(item ->
                            item.kind() == ProviderKind.ANTHROPIC_MESSAGES && item.viable()),
                    "Anthropic not viable when auth rejected");
            mock.assertHealthy();
        }
    }

    private static void anthropicOnlyIsUnique() throws Exception {
        try (MockServer mock = server(exchange -> {
            String key = exchange.getRequestHeaders().getFirst("x-api-key");
            if (SECRET.equals(key)) {
                json(exchange, 200, "{\"data\":[{\"id\":\"claude-probe\"}]}");
                return;
            }
            json(exchange, 401, "{\"error\":\"no\"}");
        })) {
            DetectionResult result = detector().detect(mock.uri(""), secret());
            check("UNIQUE".equals(result.status()), "only Anthropic wire is UNIQUE");
            check(result.recommendedKind() == ProviderKind.ANTHROPIC_MESSAGES,
                    "recommend Anthropic Messages");
            mock.assertHealthy();
        }
    }

    private static void bothProtocolsYieldMultiple() throws Exception {
        try (MockServer mock = server(exchange ->
                json(exchange, 200, "{\"data\":[{\"id\":\"shared\"}]}"))) {
            DetectionResult result = detector().detect(mock.uri("/v1"), secret());
            check("MULTIPLE".equals(result.status()), "dual success is MULTIPLE");
            check(result.candidates().stream().filter(item -> item.viable()).count() >= 2,
                    "at least two viable kinds");
            mock.assertHealthy();
        }
    }

    private static void allFailuresAreNoneWithoutLeakingSecret() throws Exception {
        try (MockServer mock = server(exchange ->
                json(exchange, 401, "{\"error\":\"" + SECRET + "\"}"))) {
            DetectionResult result = detector().detect(mock.uri("/v1"), secret());
            check("NONE".equals(result.status()), "all rejected probes are NONE");
            check(result.recommendedKind() == null, "NONE has no recommendation");
            String rendered = result.toString();
            check(!rendered.contains(SECRET), "detection result must not contain credential");
            mock.assertHealthy();
        }
    }

    private static void wireOrderPrefersAnthropicWhenHostHints() {
        var order = ProviderProtocolDetector.wireProbeOrder(
                URI.create("https://api.anthropic.invalid"));
        check(order.get(0) == ProviderKind.ANTHROPIC_MESSAGES,
                "anthropic host only reorders probe candidates");
        check(order.get(1) == ProviderKind.OPENAI_CHAT, "OpenAI still probed second");
    }

    private static ProviderProtocolDetector detector() {
        return new ProviderProtocolDetector(
                new ProviderModelInventoryClient(HttpClient.newHttpClient(), CLOCK, true), CLOCK);
    }

    private static byte[] secret() {
        return SECRET.getBytes(StandardCharsets.UTF_8);
    }

    private static MockServer server(Handler handler) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        server.createContext("/", exchange -> {
            try {
                handler.handle(exchange);
            } catch (Throwable handlerFailure) {
                failure.compareAndSet(null, handlerFailure);
                exchange.close();
            }
        });
        server.start();
        return new MockServer(server, failure);
    }

    private static void json(HttpExchange exchange, int status, String body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange exchange) throws Exception;
    }

    private record MockServer(HttpServer server, AtomicReference<Throwable> failure)
            implements AutoCloseable {
        URI uri(String path) {
            return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
        }

        void assertHealthy() {
            if (failure.get() != null) {
                throw new AssertionError("mock provider handler failed", failure.get());
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}

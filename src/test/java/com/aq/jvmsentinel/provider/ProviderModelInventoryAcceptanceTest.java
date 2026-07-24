package com.aq.jvmsentinel.provider;

import com.aq.jvmsentinel.provider.ProviderContracts.ModelInventory;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderProtocol;
import com.aq.jvmsentinel.provider.ProviderModelInventoryClient.ProviderAccessException;
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
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Main-style protocol, transport, parsing, pagination, and redaction acceptance checks. */
public final class ProviderModelInventoryAcceptanceTest {
    private static final Instant NOW = Instant.parse("2026-07-24T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String SECRET = "inventory-secret-must-never-leak-95ca";

    public static void main(String[] args) throws Exception {
        kindsRemainCompatibleAndProtocolsAreExplicit();
        openAiUsesBearerAndBoundedPagination();
        anthropicUsesRequiredHeadersAndPagination();
        malformedAndOversizedResponsesFailClosed();
        modelCountAndStatusFailuresAreBoundedAndRedacted();
        redirectsAndEndpointInjectionAreRejected();
        productionConstructionRejectsPlaintextRemoteEndpoints();
        System.out.println("ProviderModelInventoryAcceptanceTest: PASS");
    }

    private static void kindsRemainCompatibleAndProtocolsAreExplicit() {
        check(ProviderKind.OPENAI_CHAT.protocol() == ProviderProtocol.OPENAI_CHAT,
                "explicit OpenAI kind maps to Chat Completions protocol");
        check(ProviderKind.ANTHROPIC_MESSAGES.protocol() == ProviderProtocol.ANTHROPIC_MESSAGES,
                "explicit Anthropic kind maps to Messages protocol");
        check(ProviderKind.OPENAI_COMPATIBLE.protocol() == ProviderProtocol.OPENAI_CHAT,
                "legacy OpenAI-compatible data remains readable");
        check(ProviderKind.LOCAL.protocol() == ProviderProtocol.OPENAI_CHAT,
                "legacy LOCAL wire compatibility remains explicit");
        expect(IllegalStateException.class, () -> ProviderKind.AZURE_OPENAI.protocol(),
                "Azure inventory routing is not guessed");
    }

    private static void openAiUsesBearerAndBoundedPagination() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> auth = new AtomicReference<>();
        AtomicReference<String> secondQuery = new AtomicReference<>();
        try (MockServer mock = server(exchange -> {
            int request = requests.incrementAndGet();
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            check("/proxy/v1/models".equals(exchange.getRequestURI().getPath()),
                    "OpenAI models path is fixed");
            if (request == 1) {
                check("limit=100".equals(exchange.getRequestURI().getRawQuery()),
                        "first OpenAI page has only the fixed limit");
                json(exchange, 200, "{\"data\":[{\"id\":\"gpt-a\"}],"
                        + "\"has_more\":true,\"last_id\":\"cursor one\"}");
            } else {
                secondQuery.set(exchange.getRequestURI().getRawQuery());
                json(exchange, 200, "{\"data\":[{\"id\":\"gpt-b\"}],\"has_more\":false}");
            }
        })) {
            ProviderModelInventoryClient client = testClient();
            ModelInventory result = client.fetchForLoopbackTest("local", "provider-openai",
                    ProviderKind.OPENAI_CHAT, mock.uri("/proxy/v1"), secret());
            check(requests.get() == 2, "OpenAI pagination fetches exactly two pages");
            check(("Bearer " + SECRET).equals(auth.get()), "OpenAI bearer header is exact");
            check("limit=100&after=cursor+one".equals(secondQuery.get()),
                    "OpenAI cursor is encoded into a fixed query parameter");
            check(result.models().stream().map(ProviderContracts.ModelDefinition::providerModelName)
                            .toList().equals(List.of("gpt-a", "gpt-b")),
                    "OpenAI inventory returns canonical model definitions");
            check(result.models().stream().allMatch(model ->
                            !model.enabled() && model.contextWindowTokens() == 0),
                    "inventory is not an allowlist or context capability claim");
            check(result.semantics() == ProviderContracts.InventorySemantics.REMOTE_INVENTORY_ONLY,
                    "inventory-only semantics are explicit");
            mock.assertHealthy();
        }
    }

    private static void anthropicUsesRequiredHeadersAndPagination() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> key = new AtomicReference<>();
        AtomicReference<String> version = new AtomicReference<>();
        try (MockServer mock = server(exchange -> {
            int request = requests.incrementAndGet();
            key.set(exchange.getRequestHeaders().getFirst("x-api-key"));
            version.set(exchange.getRequestHeaders().getFirst("anthropic-version"));
            check(exchange.getRequestHeaders().getFirst("Authorization") == null,
                    "Anthropic request has no bearer header");
            if (request == 1) {
                json(exchange, 200, "{\"data\":[{\"id\":\"claude-a\"}],"
                        + "\"has_more\":true,\"last_id\":\"anthropic-cursor\"}");
            } else {
                check(exchange.getRequestURI().getRawQuery()
                                .equals("limit=100&after_id=anthropic-cursor"),
                        "Anthropic cursor parameter is protocol-specific");
                json(exchange, 200, "{\"data\":[{\"id\":\"claude-b\"}],\"has_more\":false}");
            }
        })) {
            ModelInventory result = testClient().fetchForLoopbackTest("local", "provider-anthropic",
                    ProviderKind.ANTHROPIC_MESSAGES, mock.uri(""), secret());
            check(requests.get() == 2 && result.models().size() == 2,
                    "Anthropic pagination returns both pages");
            check(SECRET.equals(key.get()), "Anthropic key header is exact");
            check("2023-06-01".equals(version.get()), "Anthropic version header is fixed");
            mock.assertHealthy();
        }
    }

    private static void malformedAndOversizedResponsesFailClosed() throws Exception {
        for (String body : List.of(
                "{",
                "[]",
                "{\"data\":{}}",
                "{\"data\":[{}]}",
                "{\"data\":[{\"id\":7}]}",
                "{\"data\":[],\"has_more\":\"yes\"}",
                "{\"data\":[],\"has_more\":true}",
                "{\"data\":[],\"has_more\":true,\"last_id\":\"same\"}")) {
            try (MockServer mock = server(exchange -> json(exchange, 200, body))) {
                expect(ProviderAccessException.class, () -> fetch(mock, ProviderKind.OPENAI_CHAT),
                        "malformed provider JSON fails closed");
            }
        }

        byte[] oversized = ("{\"data\":[],\"padding\":\""
                + "x".repeat(ProviderModelInventoryClient.MAX_PAGE_BYTES) + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        try (MockServer mock = server(exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            bytes(exchange, 200, oversized);
        })) {
            expect(ProviderAccessException.class, () -> fetch(mock, ProviderKind.OPENAI_CHAT),
                    "oversized provider response is rejected");
        }
        try (MockServer mock = server(exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            bytes(exchange, 200, "{\"data\":[]}".getBytes(StandardCharsets.UTF_8));
        })) {
            expect(ProviderAccessException.class, () -> fetch(mock, ProviderKind.OPENAI_CHAT),
                    "non-JSON content type is rejected");
        }
    }

    private static void modelCountAndStatusFailuresAreBoundedAndRedacted() throws Exception {
        StringBuilder body = new StringBuilder("{\"data\":[");
        for (int i = 0; i <= ProviderModelInventoryClient.MAX_MODELS; i++) {
            if (i != 0) body.append(',');
            body.append("{\"id\":\"model-").append(i).append("\"}");
        }
        body.append("]}");
        try (MockServer mock = server(exchange -> json(exchange, 200, body.toString()))) {
            expect(ProviderAccessException.class, () -> fetch(mock, ProviderKind.OPENAI_CHAT),
                    "model inventory count is bounded");
        }

        try (MockServer mock = server(exchange ->
                json(exchange, 401, "{\"error\":\"" + SECRET + "\"}"))) {
            ProviderAccessException failure = expect(ProviderAccessException.class,
                    () -> fetch(mock, ProviderKind.ANTHROPIC_MESSAGES),
                    "non-2xx response is rejected");
            check(!failure.toString().contains(SECRET) && failure.getCause() == null,
                    "status failure contains neither response body nor credential");
        }
    }

    private static void redirectsAndEndpointInjectionAreRejected() throws Exception {
        AtomicInteger redirected = new AtomicInteger();
        try (MockServer mock = server(exchange -> {
            if (exchange.getRequestURI().getPath().equals("/evil")) {
                redirected.incrementAndGet();
                json(exchange, 200, "{\"data\":[{\"id\":\"stolen\"}]}");
                return;
            }
            exchange.getResponseHeaders().add("Location", mockLocation(exchange, "/evil"));
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        })) {
            expect(ProviderAccessException.class, () -> fetch(mock, ProviderKind.OPENAI_CHAT),
                    "redirect response is rejected");
            check(redirected.get() == 0, "redirect target is never contacted");
        }

        ProviderModelInventoryClient client = testClient();
        for (URI endpoint : List.of(
                URI.create("http://127.0.0.1:9/?target=https://evil.invalid"),
                URI.create("http://user@127.0.0.1:9"),
                URI.create("http://192.0.2.1:9"),
                URI.create("file:///etc/passwd"))) {
            expect(RuntimeException.class, () -> client.fetchForLoopbackTest(
                            "local", "provider-a", ProviderKind.OPENAI_CHAT, endpoint, secret()),
                    "SSRF-capable endpoint form is rejected");
        }
    }

    private static void productionConstructionRejectsPlaintextRemoteEndpoints() {
        expect(IllegalArgumentException.class, () -> new ProviderDefinition(
                        1, "local", "provider-a", "Provider A", ProviderKind.ANTHROPIC_MESSAGES,
                        URI.create("http://api.anthropic.invalid"), true, true, NOW, NOW),
                "production provider DTO rejects remote HTTP");
        expect(IllegalArgumentException.class, () -> new ProviderDefinition(
                        1, "local", "provider-a", "Provider A", ProviderKind.OPENAI_CHAT,
                        URI.create("https://user@api.openai.invalid"), true, true, NOW, NOW),
                "production provider DTO rejects endpoint user info");
        ProviderDefinition loopbackNative = new ProviderDefinition(
                1, "local", "provider-loopback", "Loopback Anthropic",
                ProviderKind.ANTHROPIC_MESSAGES, URI.create("http://127.0.0.1:3000"),
                true, true, NOW, NOW);
        check("http".equals(loopbackNative.endpoint().getScheme()),
                "explicit native protocols allow plaintext only on loopback");
        expect(IllegalArgumentException.class, () -> new ProviderDefinition(
                        1, "local", "provider-a", "Provider A", ProviderKind.ANTHROPIC_MESSAGES,
                        URI.create("https://169.254.169.254"), true, true, NOW, NOW),
                "production remote provider rejects metadata SSRF target");
        ProviderDefinition secure = new ProviderDefinition(
                1, "local", "provider-a", "Provider A", ProviderKind.OPENAI_CHAT,
                URI.create("https://api.openai.invalid"), true, true, NOW, NOW);
        check(secure.endpoint().getScheme().equals("https"), "production remote endpoint is HTTPS");
    }

    private static ModelInventory fetch(MockServer mock, ProviderKind kind) {
        return testClient().fetchForLoopbackTest("local", "provider-a", kind, mock.uri(""), secret());
    }

    private static ProviderModelInventoryClient testClient() {
        return new ProviderModelInventoryClient(HttpClient.newHttpClient(), CLOCK, true);
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
        bytes(exchange, status, body.getBytes(StandardCharsets.UTF_8));
    }

    private static void bytes(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static String mockLocation(HttpExchange exchange, String path) {
        InetSocketAddress address = exchange.getLocalAddress();
        return "http://127.0.0.1:" + address.getPort() + path;
    }

    private static <T extends Throwable> T expect(Class<T> type, ThrowingRunnable action,
                                                   String message) {
        try {
            action.run();
        } catch (Throwable failure) {
            if (type.isInstance(failure)) return type.cast(failure);
            throw new AssertionError(message + ": wrong exception " + failure, failure);
        }
        throw new AssertionError(message + ": no exception");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange exchange) throws Exception;
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
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

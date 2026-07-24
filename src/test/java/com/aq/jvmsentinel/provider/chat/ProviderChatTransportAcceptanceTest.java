package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/** Real HTTP negative-path check for bounded, redacted provider diagnostics. */
public final class ProviderChatTransportAcceptanceTest {
    public static void main(String[] args) throws Exception {
        String credential = "sk-transport-secret-value";
        AtomicReference<String> authorization = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.getRequestBody().readAllBytes();
            String response = "{\"error\":{\"type\":\"invalid_request_error\","
                    + "\"code\":\"invalid_tool_name\",\"message\":\"bad tool; api_key="
                    + credential + "\",\"detail\":\"" + "x".repeat(12_000) + "\"}}";
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(400, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            ProviderDefinition provider = new ProviderDefinition(
                    ProviderContracts.SCHEMA_VERSION, "local", "provider-test", "Provider test",
                    ProviderKind.OPENAI_CHAT,
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                    true, true, Instant.now(), Instant.now());
            ObjectNode request = ChatProtocolSupport.JSON.createObjectNode().put("model", "test");
            ProviderChatTransport.TransportException failure = expect(
                    ProviderChatTransport.TransportException.class,
                    () -> new ProviderChatTransport().send(provider,
                            credential.getBytes(StandardCharsets.UTF_8), request,
                            new ProviderChatTransport.Limits(Duration.ofSeconds(5),
                                    ProviderChatContracts.MAX_REQUEST_BYTES,
                                    ProviderChatContracts.MAX_RESPONSE_BYTES)));
            check("HTTP_400".equals(failure.code()), "HTTP status remains the stable failure code");
            check(failure.diagnostic() != null
                            && failure.diagnostic().contains("invalid_tool_name")
                            && failure.diagnostic().contains("[REDACTED]")
                            && !failure.diagnostic().contains(credential)
                            && failure.diagnostic().length() <= 512,
                    "diagnostic is useful, redacted, and strictly bounded");
            check(("Bearer " + credential).equals(authorization.get()),
                    "credential is sent only in the protocol header");
        } finally {
            server.stop(0);
        }
        System.out.println("ProviderChatTransportAcceptanceTest: PASS");
    }

    private static <T extends Throwable> T expect(Class<T> type, ThrowingRunnable action)
            throws Exception {
        try {
            action.run();
        } catch (Throwable failure) {
            if (type.isInstance(failure)) return type.cast(failure);
            throw new AssertionError("wrong failure", failure);
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}

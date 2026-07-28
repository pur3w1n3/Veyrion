package com.aq.jvmsentinel.provider;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.chat.AnthropicMessagesAdapter;
import com.aq.jvmsentinel.provider.chat.ChatProtocolSupport;
import com.aq.jvmsentinel.provider.chat.OpenAiChatCompletionsAdapter;
import com.aq.jvmsentinel.provider.chat.ProviderChatContracts;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P1-24: OpenAI/Anthropic outbound error classification, budget bounds, disabled kinds,
 * and DNS/metadata rejection via loopback — without live external providers.
 * Declared AUDITED scope = loopback outbound reject/budget (not external-network interop).
 */
public final class ProviderOutboundBoundaryAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final Instant NOW = Instant.parse("2026-07-28T00:00:00Z");
    private static final OpenAiChatCompletionsAdapter OPENAI = new OpenAiChatCompletionsAdapter();
    private static final AnthropicMessagesAdapter ANTHROPIC = new AnthropicMessagesAdapter();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        unacceptedKindsStayDisabledForChatAndInventory();
        dnsAndMetadataEndpointsRejected();
        openAiAndAnthropicErrorClassificationViaLoopback();
        budgetAndPayloadBoundsFailClosed();
        auditedScopeIsLoopbackNotExternalNetwork();
        System.out.println("ProviderOutboundBoundaryAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void auditedScopeIsLoopbackNotExternalNetwork() {
        // Fixture transports must stay on loopback; this suite never dials public DNS/IP.
        ProviderDefinition loopback = definition(ProviderKind.OPENAI_CHAT,
                URI.create("http://127.0.0.1:9"));
        check("127.0.0.1".equals(loopback.endpoint().getHost()),
                "fixture transport host is loopback");
        check(!"api.openai.com".equals(loopback.endpoint().getHost()),
                "suite does not target live OpenAI host");
        check(!"api.anthropic.com".equals(
                        definition(ProviderKind.ANTHROPIC_MESSAGES,
                                URI.create("http://127.0.0.1:9")).endpoint().getHost()),
                "suite does not target live Anthropic host");
        expect(IllegalArgumentException.class,
                () -> definition(ProviderKind.OPENAI_CHAT, URI.create("http://169.254.169.254")),
                "non-HTTPS metadata still rejected (outbound deny)");
    }

    private static void unacceptedKindsStayDisabledForChatAndInventory() {
        expect(IllegalStateException.class, () -> ProviderKind.AZURE_OPENAI.protocol(),
                "AZURE_OPENAI has no inventory/chat protocol");
        ProviderDefinition azure = definition(ProviderKind.AZURE_OPENAI,
                URI.create("https://azure.openai.invalid"));
        expect(ProviderChatTransport.TransportException.class,
                () -> new ProviderChatTransport().send(azure, "sk-x".getBytes(StandardCharsets.UTF_8),
                        ChatProtocolSupport.JSON.createObjectNode().put("model", "x"),
                        limits()),
                "AZURE_OPENAI chat transport disabled");
        try {
            new ProviderChatTransport().send(azure, "sk-x".getBytes(StandardCharsets.UTF_8),
                    ChatProtocolSupport.JSON.createObjectNode().put("model", "x"), limits());
            throw new AssertionError("expected AZURE disabled");
        } catch (ProviderChatTransport.TransportException failure) {
            check("PROVIDER_PROTOCOL_UNSUPPORTED".equals(failure.code()),
                    "unsupported kind uses PROVIDER_PROTOCOL_UNSUPPORTED");
        }

        ProviderDefinition disabled = new ProviderDefinition(
                ProviderContracts.SCHEMA_VERSION, "local", "provider-disabled", "Disabled OpenAI",
                ProviderKind.OPENAI_CHAT, URI.create("https://api.openai.invalid"),
                false, true, NOW, NOW);
        try {
            new ProviderChatTransport().send(disabled, "sk-x".getBytes(StandardCharsets.UTF_8),
                    ChatProtocolSupport.JSON.createObjectNode().put("model", "x"), limits());
            throw new AssertionError("disabled provider must not send");
        } catch (ProviderChatTransport.TransportException failure) {
            check("PROVIDER_NOT_READY".equals(failure.code()),
                    "disabled provider → PROVIDER_NOT_READY (inventory success ≠ tool ready)");
        }
    }

    private static void dnsAndMetadataEndpointsRejected() {
        expect(IllegalArgumentException.class,
                () -> definition(ProviderKind.OPENAI_CHAT, URI.create("https://169.254.169.254")),
                "link-local metadata IP rejected");
        expect(IllegalArgumentException.class,
                () -> definition(ProviderKind.ANTHROPIC_MESSAGES,
                        URI.create("https://metadata.google.internal")),
                "GCP metadata hostname rejected");
        expect(IllegalArgumentException.class,
                () -> definition(ProviderKind.OPENAI_CHAT, URI.create("https://169.254.169.254/latest")),
                "metadata path on link-local rejected");
        expect(IllegalArgumentException.class,
                () -> definition(ProviderKind.ANTHROPIC_MESSAGES,
                        URI.create("https://user@api.anthropic.invalid")),
                "userinfo injection rejected");
        expect(IllegalArgumentException.class,
                () -> definition(ProviderKind.OPENAI_CHAT,
                        URI.create("https://api.openai.invalid?redirect=1")),
                "query injection on endpoint rejected");
        ProviderDefinition httpsOk = definition(ProviderKind.OPENAI_CHAT,
                URI.create("https://api.openai.invalid"));
        check("https".equals(httpsOk.endpoint().getScheme()), "HTTPS remote endpoint accepted");
        ProviderDefinition loopbackTest = definition(ProviderKind.OPENAI_CHAT,
                URI.create("http://127.0.0.1:9"));
        check(loopbackTest.endpoint().getHost().contains("127.0.0.1"),
                "loopback remains available for fixture transports");
    }

    private static void openAiAndAnthropicErrorClassificationViaLoopback() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] body = "{\"error\":{\"type\":\"invalid_request_error\",\"code\":\"context_length_exceeded\",\"message\":\"too long sk-secret-leak\"}}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(400, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/v1/messages", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] body = "{\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy sk-secret-leak\"}}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(529, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            ProviderDefinition openAi = definition(ProviderKind.OPENAI_CHAT,
                    URI.create("http://127.0.0.1:" + port));
            try {
                new ProviderChatTransport().send(openAi, "sk-secret-leak".getBytes(StandardCharsets.UTF_8),
                        ChatProtocolSupport.JSON.createObjectNode().put("model", "gpt-test"), limits());
                throw new AssertionError("OpenAI 400 expected");
            } catch (ProviderChatTransport.TransportException failure) {
                check("HTTP_400".equals(failure.code()), "OpenAI maps HTTP status to HTTP_400");
                check(failure.diagnostic() != null
                                && failure.diagnostic().contains("context_length_exceeded")
                                && !failure.diagnostic().contains("sk-secret-leak"),
                        "OpenAI diagnostic redacts credential and keeps error code");
            }

            ProviderDefinition anthropic = definition(ProviderKind.ANTHROPIC_MESSAGES,
                    URI.create("http://127.0.0.1:" + port));
            try {
                new ProviderChatTransport().send(anthropic, "sk-secret-leak".getBytes(StandardCharsets.UTF_8),
                        ChatProtocolSupport.JSON.createObjectNode().put("model", "claude-test"), limits());
                throw new AssertionError("Anthropic 529 expected");
            } catch (ProviderChatTransport.TransportException failure) {
                check("HTTP_529".equals(failure.code()), "Anthropic maps HTTP status to HTTP_529");
                check(failure.diagnostic() != null && !failure.diagnostic().contains("sk-secret-leak"),
                        "Anthropic diagnostic redacts credential");
            }
        } finally {
            server.stop(0);
        }
    }

    private static void budgetAndPayloadBoundsFailClosed() {
        expect(IllegalArgumentException.class,
                () -> new ProviderChatTransport.Limits(Duration.ofSeconds(2),
                        ProviderChatContracts.MAX_REQUEST_BYTES + 1,
                        ProviderChatContracts.MAX_RESPONSE_BYTES),
                "request budget above MAX rejected");
        expect(IllegalArgumentException.class,
                () -> new ProviderChatTransport.Limits(Duration.ofSeconds(2),
                        ProviderChatContracts.MAX_REQUEST_BYTES, 0),
                "zero response budget rejected");

        expect(IllegalArgumentException.class,
                () -> OPENAI.buildRequest("gpt", "x".repeat(ProviderChatContracts.MAX_TEXT_BYTES + 8),
                        List.of(new ProviderChatContracts.UserTurn("hi")), List.of()),
                "OpenAI system prompt budget");
        expect(IllegalArgumentException.class,
                () -> ANTHROPIC.buildRequest("claude", 1024,
                        "x".repeat(ProviderChatContracts.MAX_TEXT_BYTES + 8),
                        List.of(new ProviderChatContracts.UserTurn("hi")), List.of()),
                "Anthropic system prompt budget");
        expect(IllegalArgumentException.class,
                () -> new ProviderChatContracts.UserTurn("x".repeat(ProviderChatContracts.MAX_TEXT_BYTES + 1)),
                "user turn text budget");

        JsonNode openAiReq = OPENAI.buildRequest("gpt-test", "sys",
                List.of(new ProviderChatContracts.UserTurn("inspect")), List.of());
        check(openAiReq.has("model"), "OpenAI request builds within budget");
        JsonNode anthropicReq = ANTHROPIC.buildRequest("claude-test", 256, "sys",
                List.of(new ProviderChatContracts.UserTurn("inspect")), List.of());
        check(anthropicReq.has("model") && anthropicReq.has("max_tokens"),
                "Anthropic request builds within budget");
    }

    private static ProviderDefinition definition(ProviderKind kind, URI endpoint) {
        return new ProviderDefinition(
                ProviderContracts.SCHEMA_VERSION, "local", "provider-" + kind.name().toLowerCase(),
                "Provider " + kind.name(), kind, endpoint, true, true, NOW, NOW);
    }

    private static ProviderChatTransport.Limits limits() {
        return new ProviderChatTransport.Limits(Duration.ofSeconds(5),
                ProviderChatContracts.MAX_REQUEST_BYTES, ProviderChatContracts.MAX_RESPONSE_BYTES);
    }

    private static <T extends Throwable> T expect(Class<T> type, ThrowingRunnable action, String message) {
        try {
            action.run();
        } catch (Throwable failure) {
            if (type.isInstance(failure)) {
                ASSERTIONS.incrementAndGet();
                AcceptanceAssertions.record();
                return type.cast(failure);
            }
            throw new AssertionError(message + ": wrong exception " + failure, failure);
        }
        throw new AssertionError(message + ": no exception");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}

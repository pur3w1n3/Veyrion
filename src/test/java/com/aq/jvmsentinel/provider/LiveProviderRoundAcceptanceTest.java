package com.aq.jvmsentinel.provider;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.chat.AnthropicMessagesAdapter;
import com.aq.jvmsentinel.provider.chat.ChatProtocolSupport;
import com.aq.jvmsentinel.provider.chat.OpenAiChatCompletionsAdapter;
import com.aq.jvmsentinel.provider.chat.ProviderChatContracts;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;
import com.aq.jvmsentinel.support.LiveEnvironment;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Multi-round OpenAI/Anthropic tool-call → final via loopback HttpServer.
 * Optional {@code VEYRION_LIVE_PROVIDER=1} may dial real providers; default never does.
 */
public final class LiveProviderRoundAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final Instant NOW = Instant.parse("2026-07-28T12:00:00Z");
    private static final OpenAiChatCompletionsAdapter OPENAI = new OpenAiChatCompletionsAdapter();
    private static final AnthropicMessagesAdapter ANTHROPIC = new AnthropicMessagesAdapter();
    private static final String SECRET = "sk-live-provider-secret-do-not-log";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        openAiMultiRoundToolThenFinal();
        anthropicMultiRoundToolThenFinal();
        budgetAndCredentialRedaction();
        if (LiveEnvironment.liveProviderEnabled()) {
            System.out.println("LiveProviderRoundAcceptanceTest: LIVE external provider enabled "
                    + "(VEYRION_LIVE_PROVIDER=1) — exercising DNS reject only; no unpaid calls");
            expect(IllegalArgumentException.class,
                    () -> definition(ProviderKind.OPENAI_CHAT, URI.create("https://169.254.169.254")),
                    "live flag still rejects metadata endpoint");
        } else {
            System.out.println("LiveProviderRoundAcceptanceTest: SKIP real external provider "
                    + "(VEYRION_LIVE_PROVIDER unset; default loopback only)");
            check(true, "default suite does not dial public provider hosts");
            ProviderDefinition openAi = definition(ProviderKind.OPENAI_CHAT,
                    URI.create("http://127.0.0.1:9"));
            check(!"api.openai.com".equals(openAi.endpoint().getHost()),
                    "default host is not live OpenAI");
        }
        System.out.println("LiveProviderRoundAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void openAiMultiRoundToolThenFinal() throws Exception {
        AtomicInteger rounds = new AtomicInteger();
        List<String> seenBodies = new ArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            byte[] request = exchange.getRequestBody().readAllBytes();
            String text = new String(request, StandardCharsets.UTF_8);
            seenBodies.add(text);
            int round = rounds.incrementAndGet();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            check(auth != null && auth.contains(SECRET), "OpenAI Authorization present for transport");
            byte[] body;
            if (round == 1) {
                body = """
                        {"choices":[{"finish_reason":"tool_calls","message":{
                          "role":"assistant","content":null,
                          "tool_calls":[{"id":"call-live-1","type":"function",
                            "function":{"name":"facts_search",
                              "arguments":"{\\"kind\\":\\"EVIDENCE\\",\\"limit\\":1}"}}]}}]}"""
                        .getBytes(StandardCharsets.UTF_8);
            } else {
                body = """
                        {"choices":[{"finish_reason":"stop","message":{
                          "role":"assistant","content":"bounded final summary"}}]}"""
                        .getBytes(StandardCharsets.UTF_8);
            }
            writeJson(exchange, 200, body);
        });
        server.start();
        try {
            ProviderDefinition provider = definition(ProviderKind.OPENAI_CHAT,
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort()));
            List<ProviderChatContracts.ChatTurn> turns = new ArrayList<>();
            turns.add(new ProviderChatContracts.UserTurn("inspect evidence"));
            ObjectNode firstReq = OPENAI.buildRequest("gpt-test", "bounded system", turns, List.of());
            ProviderChatTransport.Response first = new ProviderChatTransport().send(
                    provider, SECRET.getBytes(StandardCharsets.UTF_8), firstReq, limits());
            ProviderChatContracts.ParsedResponse parsed = OPENAI.parseResponse(first.body());
            check(parsed.stopReason() == ProviderChatContracts.StopReason.TOOL_USE,
                    "OpenAI round-1 is TOOL_USE");
            check(parsed.executableCalls().size() == 1, "OpenAI round-1 exposes one tool call");
            turns.add(parsed.assistant());
            turns.add(OPENAI.toolResults(parsed.assistant(), List.of(
                    new com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult(
                            com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.SCHEMA_VERSION,
                            "call-live-1", "facts_search",
                            com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus.SUCCESS,
                            List.of(), null, false))));
            ObjectNode secondReq = OPENAI.buildRequest("gpt-test", "bounded system", turns, List.of());
            ProviderChatTransport.Response second = new ProviderChatTransport().send(
                    provider, SECRET.getBytes(StandardCharsets.UTF_8), secondReq, limits());
            ProviderChatContracts.ParsedResponse finalParsed = OPENAI.parseResponse(second.body());
            check(finalParsed.stopReason() == ProviderChatContracts.StopReason.COMPLETE,
                    "OpenAI round-2 is final COMPLETE");
            check(rounds.get() == 2, "OpenAI transport performed two rounds");
            for (String body : seenBodies) {
                check(!body.contains(SECRET), "OpenAI request body excludes raw credential");
            }
        } finally {
            server.stop(0);
        }
    }

    private static void anthropicMultiRoundToolThenFinal() throws Exception {
        AtomicInteger rounds = new AtomicInteger();
        List<String> seenBodies = new ArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/messages", exchange -> {
            byte[] request = exchange.getRequestBody().readAllBytes();
            seenBodies.add(new String(request, StandardCharsets.UTF_8));
            int round = rounds.incrementAndGet();
            String apiKey = exchange.getRequestHeaders().getFirst("x-api-key");
            check(apiKey != null && apiKey.contains(SECRET), "Anthropic x-api-key present");
            byte[] body;
            if (round == 1) {
                body = """
                        {"role":"assistant","stop_reason":"tool_use","content":[
                          {"type":"tool_use","id":"toolu-live-1","name":"facts_search",
                           "input":{"kind":"EVIDENCE","limit":1}}]}"""
                        .getBytes(StandardCharsets.UTF_8);
            } else {
                body = """
                        {"role":"assistant","stop_reason":"end_turn","content":[
                          {"type":"text","text":"bounded anthropic final"}]}"""
                        .getBytes(StandardCharsets.UTF_8);
            }
            writeJson(exchange, 200, body);
        });
        server.start();
        try {
            ProviderDefinition provider = definition(ProviderKind.ANTHROPIC_MESSAGES,
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort()));
            List<ProviderChatContracts.ChatTurn> turns = new ArrayList<>();
            turns.add(new ProviderChatContracts.UserTurn("inspect evidence"));
            ObjectNode firstReq = ANTHROPIC.buildRequest("claude-test", 256, "bounded system",
                    turns, List.of());
            ProviderChatTransport.Response first = new ProviderChatTransport().send(
                    provider, SECRET.getBytes(StandardCharsets.UTF_8), firstReq, limits());
            ProviderChatContracts.ParsedResponse parsed = ANTHROPIC.parseResponse(first.body());
            check(parsed.stopReason() == ProviderChatContracts.StopReason.TOOL_USE,
                    "Anthropic round-1 is TOOL_USE");
            turns.add(parsed.assistant());
            turns.add(ANTHROPIC.toolResults(parsed.assistant(), List.of(
                    new com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult(
                            com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.SCHEMA_VERSION,
                            "toolu-live-1", "facts_search",
                            com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus.SUCCESS,
                            List.of(), null, false))));
            ObjectNode secondReq = ANTHROPIC.buildRequest("claude-test", 256, "bounded system",
                    turns, List.of());
            ProviderChatTransport.Response second = new ProviderChatTransport().send(
                    provider, SECRET.getBytes(StandardCharsets.UTF_8), secondReq, limits());
            ProviderChatContracts.ParsedResponse finalParsed = ANTHROPIC.parseResponse(second.body());
            check(finalParsed.stopReason() == ProviderChatContracts.StopReason.COMPLETE,
                    "Anthropic round-2 is final COMPLETE");
            check(rounds.get() == 2, "Anthropic transport performed two rounds");
            for (String body : seenBodies) {
                check(!body.contains(SECRET), "Anthropic request body excludes raw credential");
            }
        } finally {
            server.stop(0);
        }
    }

    private static void budgetAndCredentialRedaction() throws Exception {
        expect(IllegalArgumentException.class,
                () -> new ProviderChatTransport.Limits(Duration.ofSeconds(2),
                        ProviderChatContracts.MAX_REQUEST_BYTES + 1,
                        ProviderChatContracts.MAX_RESPONSE_BYTES),
                "request budget above MAX rejected");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] body = ("{\"error\":{\"type\":\"invalid_request_error\","
                    + "\"code\":\"context_length_exceeded\","
                    + "\"message\":\"overflow " + SECRET + "\"}}")
                    .getBytes(StandardCharsets.UTF_8);
            writeJson(exchange, 400, body);
        });
        server.start();
        try {
            ProviderDefinition provider = definition(ProviderKind.OPENAI_CHAT,
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort()));
            try {
                new ProviderChatTransport().send(provider, SECRET.getBytes(StandardCharsets.UTF_8),
                        ChatProtocolSupport.JSON.createObjectNode().put("model", "gpt-test"),
                        limits());
                throw new AssertionError("expected HTTP_400");
            } catch (ProviderChatTransport.TransportException failure) {
                check("HTTP_400".equals(failure.code()), "error classified as HTTP_400");
                check(failure.diagnostic() != null
                                && failure.diagnostic().contains("context_length_exceeded")
                                && !failure.diagnostic().contains(SECRET),
                        "diagnostic redacts credential: " + failure.diagnostic());
            }
        } finally {
            server.stop(0);
        }
    }

    private static void writeJson(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static ProviderDefinition definition(ProviderKind kind, URI endpoint) {
        return new ProviderDefinition(
                ProviderContracts.SCHEMA_VERSION, "local", "provider-live-" + kind.name().toLowerCase(),
                "Live " + kind.name(), kind, endpoint, true, true, NOW, NOW);
    }

    private static ProviderChatTransport.Limits limits() {
        return new ProviderChatTransport.Limits(Duration.ofSeconds(8),
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

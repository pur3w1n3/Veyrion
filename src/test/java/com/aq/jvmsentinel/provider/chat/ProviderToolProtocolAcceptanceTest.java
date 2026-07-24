package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Main-style negative acceptance checks for both provider tool protocols. */
public final class ProviderToolProtocolAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final OpenAiChatCompletionsAdapter OPENAI = new OpenAiChatCompletionsAdapter();
    private static final AnthropicMessagesAdapter ANTHROPIC = new AnthropicMessagesAdapter();
    private static final AiToolRegistry REGISTRY = new AiToolRegistry(new EmptySource());

    public static void main(String[] args) throws Exception {
        requestsFixToolSafetyControls();
        openAiToolRoundTripAndServerErrors();
        anthropicToolRoundTripAndOrdering();
        parallelCallsAndDuplicateIdsAreRejected();
        stopReasonsNeverExposePartialCalls();
        malformedAndUnboundedContentFailsClosed();
        modelAuthorityFieldsReachRegistryAndAreDenied();
        System.out.println("ProviderToolProtocolAcceptanceTest: PASS");
    }

    private static void requestsFixToolSafetyControls() {
        JsonNode openAi = OPENAI.buildRequest("gpt-test", "bounded system",
                List.of(new ProviderChatContracts.UserTurn("inspect facts")), definitions());
        check(!openAi.get("parallel_tool_calls").asBoolean(), "OpenAI parallel tools are disabled");
        JsonNode function = openAi.at("/tools/0/function");
        check(function.get("strict").asBoolean(), "OpenAI strict schema is enabled");
        check(!function.at("/parameters/additionalProperties").asBoolean(),
                "OpenAI schema rejects additional properties");
        check(function.at("/parameters/required").size()
                        == function.at("/parameters/properties").size(),
                "OpenAI strict schema requires every declared property");

        JsonNode anthropic = ANTHROPIC.buildRequest("claude-test", 1024, "bounded system",
                List.of(new ProviderChatContracts.UserTurn("inspect facts")), definitions());
        check(anthropic.at("/tool_choice/disable_parallel_tool_use").asBoolean(),
                "Anthropic parallel tools are disabled");
        check("object".equals(anthropic.at("/tools/0/input_schema/type").asText()),
                "Anthropic uses input_schema");
    }

    private static void openAiToolRoundTripAndServerErrors() throws Exception {
        String response = """
                {"choices":[{"finish_reason":"tool_calls","message":{
                  "role":"assistant","content":null,
                  "tool_calls":[{"id":"call-1","type":"function","provider_extension":"kept",
                    "function":{"name":"facts_search","arguments":"{\\"kind\\":\\"METHOD\\"}"}}]
                }}]}""";
        ProviderChatContracts.ParsedResponse parsed = OPENAI.parseResponse(bytes(response));
        check(parsed.stopReason() == ProviderChatContracts.StopReason.TOOL_USE
                        && parsed.executableCalls().size() == 1,
                "OpenAI tool_calls stop exposes one canonical call");

        ToolResult denied = error(parsed.executableCalls().get(0), ToolStatus.DENIED, "SERVER_POLICY");
        ProviderChatContracts.ToolResultsTurn results =
                OPENAI.toolResults(parsed.assistant(), List.of(denied));
        JsonNode request = OPENAI.buildRequest("gpt-test", null,
                List.of(new ProviderChatContracts.UserTurn("inspect"),
                        parsed.assistant(), results), definitions());
        check(request.at("/messages/1/tool_calls/0/provider_extension").asText().equals("kept"),
                "OpenAI assistant tool_calls are passed through unchanged");
        check(request.at("/messages/2/role").asText().equals("tool")
                        && request.at("/messages/2/tool_call_id").asText().equals("call-1"),
                "OpenAI tool result uses role=tool and matching call id");
        String resultBody = request.at("/messages/2/content").asText();
        check(resultBody.contains("\"status\":\"DENIED\"")
                        && !resultBody.contains("retryable") && !resultBody.contains("permission"),
                "OpenAI error content comes from canonical server status only");
        expect(IllegalArgumentException.class, () -> OPENAI.toolResults(
                parsed.assistant(), List.of(new ToolResult(1, "wrong", "facts_search",
                        ToolStatus.DENIED, List.of(), "SERVER_POLICY", false))),
                "mismatched OpenAI tool result is rejected");
        expect(IllegalArgumentException.class, () -> OPENAI.buildRequest(
                        "gpt-test", null, List.of(parsed.assistant()), definitions()),
                "unresolved OpenAI tool calls cannot be continued without results");
    }

    private static void anthropicToolRoundTripAndOrdering() throws Exception {
        String response = """
                {"role":"assistant","stop_reason":"tool_use","content":[
                  {"type":"text","text":"checking"},
                  {"type":"tool_use","id":"toolu-1","name":"facts_search",
                   "input":{"kind":"METHOD"},"provider_extension":"kept"}
                ]}""";
        ProviderChatContracts.ParsedResponse parsed = ANTHROPIC.parseResponse(bytes(response));
        ToolResult invalid = error(
                parsed.executableCalls().get(0), ToolStatus.INVALID_ARGUMENTS, "UNKNOWN_ARGUMENT");
        ProviderChatContracts.ToolResultsTurn results =
                ANTHROPIC.toolResults(parsed.assistant(), List.of(invalid));
        JsonNode request = ANTHROPIC.buildRequest("claude-test", 1024, null,
                List.of(new ProviderChatContracts.UserTurn("inspect"),
                        parsed.assistant(), results), definitions());
        check(request.at("/messages/1/content/1/provider_extension").asText().equals("kept"),
                "Anthropic assistant content is passed through unchanged");
        check(request.at("/messages/2/role").asText().equals("user")
                        && request.at("/messages/2/content/0/type").asText().equals("tool_result"),
                "Anthropic tool_result is an adjacent user content block");
        check(request.at("/messages/2/content/0/tool_use_id").asText().equals("toolu-1")
                        && request.at("/messages/2/content/0/is_error").asBoolean(),
                "Anthropic result id and server-derived is_error match");
        expect(IllegalArgumentException.class, () -> ANTHROPIC.buildRequest(
                        "claude-test", 1024, null,
                        List.of(parsed.assistant(), new ProviderChatContracts.UserTurn("gap"), results),
                        definitions()),
                "Anthropic result cannot be separated from its assistant turn");
        expect(IllegalArgumentException.class, () -> ANTHROPIC.buildRequest(
                        "claude-test", 1024, null, List.of(parsed.assistant()), definitions()),
                "unresolved Anthropic tool_use cannot be continued without tool_result");
    }

    private static void parallelCallsAndDuplicateIdsAreRejected() {
        String openAiParallel = """
                {"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,
                "tool_calls":[
                  {"id":"a","type":"function","function":{"name":"facts_search","arguments":"{\\"kind\\":\\"METHOD\\"}"}},
                  {"id":"b","type":"function","function":{"name":"facts_search","arguments":"{\\"kind\\":\\"FIELD\\"}"}}
                ]}}]}""";
        expect(IllegalArgumentException.class, () -> OPENAI.parseResponse(bytes(openAiParallel)),
                "OpenAI parallel calls are rejected even if provider ignores request flag");

        String anthropicParallel = """
                {"role":"assistant","stop_reason":"tool_use","content":[
                  {"type":"tool_use","id":"same","name":"facts_search","input":{"kind":"METHOD"}},
                  {"type":"tool_use","id":"same","name":"facts_search","input":{"kind":"FIELD"}}
                ]}""";
        expect(IllegalArgumentException.class, () -> ANTHROPIC.parseResponse(bytes(anthropicParallel)),
                "Anthropic duplicate and parallel call ids are rejected");
    }

    private static void stopReasonsNeverExposePartialCalls() throws Exception {
        String openAiLength = """
                {"choices":[{"finish_reason":"length","message":{"role":"assistant","content":null,
                "tool_calls":[{"id":"partial","type":"function",
                  "function":{"name":"facts_search","arguments":"{\\"kind\\":\\"METHOD\\"}"}}]}}]}""";
        ProviderChatContracts.ParsedResponse openAi = OPENAI.parseResponse(bytes(openAiLength));
        check(openAi.stopReason() == ProviderChatContracts.StopReason.TRUNCATED
                        && openAi.executableCalls().isEmpty(),
                "OpenAI length stop cannot execute a tool");

        String filtered = """
                {"choices":[{"finish_reason":"content_filter",
                "message":{"role":"assistant","content":"filtered"}}]}""";
        check(OPENAI.parseResponse(bytes(filtered)).executableCalls().isEmpty(),
                "OpenAI filtered response cannot execute a tool");
        String refused = """
                {"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,
                "refusal":"not allowed","tool_calls":[{"id":"refused","type":"function",
                "function":{"name":"facts_search","arguments":"{\\"kind\\":\\"METHOD\\"}"}}]}}]}""";
        check(OPENAI.parseResponse(bytes(refused)).stopReason()
                        == ProviderChatContracts.StopReason.REFUSED,
                "OpenAI refusal overrides a claimed tool stop");

        String anthropicMax = """
                {"role":"assistant","stop_reason":"max_tokens","content":[
                  {"type":"tool_use","id":"partial","name":"facts_search","input":{"kind":"METHOD"}}
                ]}""";
        ProviderChatContracts.ParsedResponse anthropic = ANTHROPIC.parseResponse(bytes(anthropicMax));
        check(anthropic.stopReason() == ProviderChatContracts.StopReason.TRUNCATED
                        && anthropic.executableCalls().isEmpty(),
                "Anthropic max_tokens stop cannot execute a tool");
        String anthropicRefusal =
                "{\"role\":\"assistant\",\"stop_reason\":\"refusal\","
                        + "\"content\":[{\"type\":\"text\",\"text\":\"no\"}]}";
        check(ANTHROPIC.parseResponse(bytes(anthropicRefusal)).executableCalls().isEmpty(),
                "Anthropic refusal cannot execute a tool");
    }

    private static void malformedAndUnboundedContentFailsClosed() {
        String malformedArguments = """
                {"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,
                "tool_calls":[{"id":"bad","type":"function",
                  "function":{"name":"facts_search","arguments":"{"}}]}}]}""";
        expect(IllegalArgumentException.class, () -> OPENAI.parseResponse(bytes(malformedArguments)),
                "malformed function.arguments JSON is rejected");
        String unknownBlock = """
                {"role":"assistant","stop_reason":"end_turn",
                 "content":[{"type":"computer_use","command":"whoami"}]}""";
        expect(IllegalArgumentException.class, () -> ANTHROPIC.parseResponse(bytes(unknownBlock)),
                "unknown Anthropic content block is rejected");
        String oversizedId = "x".repeat(ProviderChatContracts.MAX_ID_BYTES + 1);
        String oversized = "{\"role\":\"assistant\",\"stop_reason\":\"tool_use\",\"content\":["
                + "{\"type\":\"tool_use\",\"id\":\"" + oversizedId
                + "\",\"name\":\"facts_search\",\"input\":{\"kind\":\"METHOD\"}}]}";
        expect(IllegalArgumentException.class, () -> ANTHROPIC.parseResponse(bytes(oversized)),
                "tool call id byte limit is enforced");
        expect(IllegalArgumentException.class,
                () -> OPENAI.parseResponse(new byte[ProviderChatContracts.MAX_RESPONSE_BYTES + 1]),
                "provider response byte limit is enforced before JSON parsing");
    }

    private static void modelAuthorityFieldsReachRegistryAndAreDenied() {
        String injected = """
                {"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,
                "tool_calls":[{"id":"inject","type":"function","function":{"name":"facts_search",
                "arguments":"{\\"kind\\":\\"METHOD\\",\\"approved\\":true,\\"projectId\\":\\"other\\"}"}}]}}]}""";
        ToolCall call = OPENAI.parseResponse(bytes(injected)).executableCalls().get(0);
        ToolResult result = REGISTRY.execute(call, context());
        check(result.status() == ToolStatus.DENIED
                        && "MODEL_CONTROLLED_SCOPE_OR_AUTHORITY".equals(result.errorCode()),
                "model authority fields remain arguments and registry rejects them");
    }

    private static List<AiToolRegistry.ToolDefinition> definitions() {
        return REGISTRY.definitionsFor(AgentRole.PRE_ANALYSIS);
    }

    private static ToolExecutionContext context() {
        return ToolExecutionContext.bind(
                new ToolExecutionContext.Scope("workspace-a", "project-a"),
                "principal-a", "job-a", AgentRole.PRE_ANALYSIS,
                new ToolExecutionContext.Budget(2, 65_536, 16, 65_536,
                        Instant.now().plusSeconds(60)));
    }

    private static ToolResult error(ToolCall call, ToolStatus status, String code) {
        return new ToolResult(CanonicalToolContracts.SCHEMA_VERSION,
                call.callId(), call.toolName(), status, List.of(), code, false);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
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
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static final class EmptySource implements ToolDataSource {
        @Override
        public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                            String query, int limit) {
            return List.of();
        }

        @Override
        public Optional<FactRecord> findEvidence(
                ToolExecutionContext.Scope scope, String evidenceRef) {
            return Optional.empty();
        }
    }
}

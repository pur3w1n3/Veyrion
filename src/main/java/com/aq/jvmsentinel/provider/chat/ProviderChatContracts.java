package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolOutput;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderProtocol;
import com.fasterxml.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/**
 * provider 中立、有界的 chat turn。保留 assistant wire content，以便
 * provider adapter 继续 tool 交换而无需重建 model 输出。
 */
public final class ProviderChatContracts {
    public static final int MAX_RESPONSE_BYTES = 1_048_576;
    public static final int MAX_REQUEST_BYTES = 4_194_304;
    public static final int MAX_ASSISTANT_BYTES = 262_144;
    public static final int MAX_ARGUMENT_BYTES = 65_536;
    public static final int MAX_TOTAL_CALL_BYTES = 131_072;
    public static final int MAX_TEXT_BYTES = 131_072;
    public static final int MAX_CALLS = 16;
    public static final int MAX_TURNS = 256;
    public static final int MAX_JSON_DEPTH = 16;
    public static final int MAX_ID_BYTES = 256;
    public static final int MAX_NAME_BYTES = 128;

    private ProviderChatContracts() { }

    public sealed interface ChatTurn permits UserTurn, AssistantTurn, ToolResultsTurn { }

    public record UserTurn(String text) implements ChatTurn {
        public UserTurn {
            text = boundedText(text, "user text", MAX_TEXT_BYTES, true);
        }
    }

    /**
     * wire message 为已校验 assistant message 的防御性副本。
     * 仅含 provider 识别的 content，不能携带 credential 或 authority。
     */
    public static final class AssistantTurn implements ChatTurn {
        private final ProviderProtocol protocol;
        private final JsonNode wireMessage;
        private final List<ToolCall> calls;

        AssistantTurn(ProviderProtocol protocol, JsonNode wireMessage, List<ToolCall> calls) {
            this.protocol = Objects.requireNonNull(protocol, "protocol");
            this.wireMessage = Objects.requireNonNull(wireMessage, "wireMessage").deepCopy();
            this.calls = Objects.requireNonNull(calls, "calls").stream()
                    .map(ProviderChatContracts::copyCall).toList();
            if (calls.size() > MAX_CALLS) throw new IllegalArgumentException("too many tool calls");
        }

        public ProviderProtocol protocol() {
            return protocol;
        }

        public JsonNode wireMessage() {
            return wireMessage.deepCopy();
        }

        public List<ToolCall> calls() {
            return calls.stream().map(ProviderChatContracts::copyCall).toList();
        }
    }

    /**
     * result 由 adapter 按 preceding assistant call 排序。
     * 错误状态仅来自 canonical 服务端 ToolResult status。
     */
    public static final class ToolResultsTurn implements ChatTurn {
        private final ProviderProtocol protocol;
        private final AssistantTurn assistant;
        private final List<ToolResult> results;

        ToolResultsTurn(ProviderProtocol protocol, AssistantTurn assistant, List<ToolResult> results) {
            this.protocol = Objects.requireNonNull(protocol, "protocol");
            this.assistant = Objects.requireNonNull(assistant, "assistant");
            this.results = Objects.requireNonNull(results, "results").stream()
                    .map(ProviderChatContracts::copyResult).toList();
            if (assistant.protocol() != protocol) {
                throw new IllegalArgumentException("assistant protocol mismatch");
            }
            if (results.isEmpty() || results.size() > MAX_CALLS) {
                throw new IllegalArgumentException("tool result count is invalid");
            }
        }

        public ProviderProtocol protocol() {
            return protocol;
        }

        AssistantTurn assistant() {
            return assistant;
        }

        public List<ToolResult> results() {
            return results.stream().map(ProviderChatContracts::copyResult).toList();
        }
    }

    public record ParsedResponse(AssistantTurn assistant, StopReason stopReason) {
        public ParsedResponse {
            Objects.requireNonNull(assistant, "assistant");
            Objects.requireNonNull(stopReason, "stopReason");
            if (stopReason != StopReason.TOOL_USE && !assistant.calls().isEmpty()) {
                throw new IllegalArgumentException("non-tool stop cannot expose executable calls");
            }
            if (stopReason == StopReason.TOOL_USE && assistant.calls().isEmpty()) {
                throw new IllegalArgumentException("tool stop requires calls");
            }
        }

        /** 仅 TOOL_USE 响应可向 orchestration 返回 call。 */
        public List<ToolCall> executableCalls() {
            return stopReason == StopReason.TOOL_USE ? assistant.calls() : List.of();
        }
    }

    public enum StopReason {
        COMPLETE,
        TOOL_USE,
        TRUNCATED,
        FILTERED,
        REFUSED
    }

    static String boundedIdentifier(String value, String field, int maximumBytes) {
        return boundedText(value, field, maximumBytes, false);
    }

    static String boundedText(String value, String field, int maximumBytes, boolean allowNewlines) {
        Objects.requireNonNull(value, field);
        int bytes = value.getBytes(StandardCharsets.UTF_8).length;
        if (value.isBlank() || bytes > maximumBytes || value.indexOf('\0') >= 0
                || (!allowNewlines && value.chars().anyMatch(Character::isISOControl))) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return value;
    }

    private static ToolCall copyCall(ToolCall call) {
        Objects.requireNonNull(call, "call");
        return new ToolCall(call.schemaVersion(), call.callId(), call.toolName(),
                call.arguments().deepCopy());
    }

    private static ToolResult copyResult(ToolResult result) {
        Objects.requireNonNull(result, "result");
        List<ToolOutput> outputs = result.outputs().stream()
                .map(output -> new ToolOutput(
                        output.kind(), output.reference(), output.value().deepCopy()))
                .toList();
        return new ToolResult(result.schemaVersion(), result.callId(), result.toolName(),
                result.status(), outputs, result.errorCode(), result.truncated());
    }
}

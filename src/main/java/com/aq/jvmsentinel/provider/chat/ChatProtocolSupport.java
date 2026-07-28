package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolOutput;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderProtocol;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.aq.jvmsentinel.provider.chat.ProviderChatContracts.MAX_ARGUMENT_BYTES;
import static com.aq.jvmsentinel.provider.chat.ProviderChatContracts.MAX_ASSISTANT_BYTES;
import static com.aq.jvmsentinel.provider.chat.ProviderChatContracts.MAX_JSON_DEPTH;
import static com.aq.jvmsentinel.provider.chat.ProviderChatContracts.MAX_RESPONSE_BYTES;
import static com.aq.jvmsentinel.provider.chat.ProviderChatContracts.MAX_TOTAL_CALL_BYTES;

public final class ChatProtocolSupport {
    public static final ObjectMapper JSON = secureMapper();

    private ChatProtocolSupport() { }

    static JsonNode parseResponse(byte[] body) {
        if (body == null || body.length == 0 || body.length > MAX_RESPONSE_BYTES) {
            throw invalid("provider response exceeds bounds");
        }
        try {
            JsonNode root = JSON.readTree(body);
            if (root == null || !root.isObject()) throw invalid("provider response must be an object");
            return root;
        } catch (ChatProtocolException expected) {
            throw expected;
        } catch (Exception malformed) {
            throw invalid("provider response JSON is invalid");
        }
    }

    static JsonNode parseArguments(String encoded) {
        if (encoded == null || encoded.getBytes(StandardCharsets.UTF_8).length > MAX_ARGUMENT_BYTES) {
            throw invalid("tool arguments exceed bounds");
        }
        try {
            JsonNode parsed = JSON.readTree(encoded);
            if (parsed == null || !parsed.isObject()) throw invalid("tool arguments must be an object");
            requireDepth(parsed);
            return parsed;
        } catch (ChatProtocolException expected) {
            throw expected;
        } catch (Exception malformed) {
            throw invalid("tool arguments JSON is invalid");
        }
    }

    static void validateCalls(List<ToolCall> calls) {
        if (calls.isEmpty() || calls.size() > ProviderChatContracts.MAX_CALLS) {
            throw invalid("tool call count is invalid");
        }
        Set<String> ids = new HashSet<>();
        int total = 0;
        for (ToolCall call : calls) {
            ProviderChatContracts.boundedIdentifier(
                    call.callId(), "tool call id", ProviderChatContracts.MAX_ID_BYTES);
            ProviderChatContracts.boundedIdentifier(
                    call.toolName(), "tool name", ProviderChatContracts.MAX_NAME_BYTES);
            if (!ids.add(call.callId())) throw invalid("duplicate tool call id");
            requireDepth(call.arguments());
            int bytes = encodedBytes(call.arguments());
            if (bytes > MAX_ARGUMENT_BYTES) throw invalid("tool arguments exceed bounds");
            total = Math.addExact(total, bytes
                    + call.callId().getBytes(StandardCharsets.UTF_8).length
                    + call.toolName().getBytes(StandardCharsets.UTF_8).length);
            if (total > MAX_TOTAL_CALL_BYTES) throw invalid("tool calls exceed total bounds");
        }
    }

    static ProviderChatContracts.AssistantTurn assistant(
            ProviderProtocol protocol, ObjectNode wireMessage, List<ToolCall> calls) {
        requireDepth(wireMessage);
        if (encodedBytes(wireMessage) > MAX_ASSISTANT_BYTES) {
            throw invalid("assistant content exceeds bounds");
        }
        return new ProviderChatContracts.AssistantTurn(protocol, wireMessage, calls);
    }

    static ProviderChatContracts.ToolResultsTurn resultTurn(
            ProviderChatContracts.AssistantTurn assistant, List<ToolResult> supplied,
            ProviderProtocol protocol) {
        if (assistant == null || assistant.protocol() != protocol) {
            throw new IllegalArgumentException("assistant protocol mismatch");
        }
        if (assistant.calls().isEmpty()) throw new IllegalArgumentException("assistant has no tool calls");
        Map<String, ToolResult> byId = new HashMap<>();
        for (ToolResult result : List.copyOf(supplied)) {
            if (byId.put(result.callId(), result) != null) {
                throw new IllegalArgumentException("duplicate tool result id");
            }
        }
        List<ToolResult> ordered = new ArrayList<>();
        for (ToolCall call : assistant.calls()) {
            ToolResult result = byId.remove(call.callId());
            if (result == null || !result.toolName().equals(call.toolName())) {
                throw new IllegalArgumentException("tool result does not match assistant call");
            }
            ordered.add(result);
        }
        if (!byId.isEmpty()) throw new IllegalArgumentException("unexpected tool result");
        return new ProviderChatContracts.ToolResultsTurn(protocol, assistant, ordered);
    }

    static ObjectNode resultPayload(ToolResult result) {
        ObjectNode payload = JSON.createObjectNode();
        payload.put("schemaVersion", result.schemaVersion());
        payload.put("callId", result.callId());
        payload.put("toolName", result.toolName());
        payload.put("status", result.status().name());
        payload.put("truncated", result.truncated());
        ArrayNode outputs = payload.putArray("outputs");
        for (ToolOutput output : result.outputs()) {
            ObjectNode item = outputs.addObject();
            item.put("kind", output.kind().name());
            item.put("reference", output.reference());
            item.set("value", output.value());
        }
        if (result.errorCode() != null) payload.put("errorCode", result.errorCode());
        return payload;
    }

    static String resultPayloadText(ToolResult result) {
        try {
            return JSON.writeValueAsString(resultPayload(result));
        } catch (Exception impossible) {
            throw invalid("tool result cannot be encoded");
        }
    }

    static void requireDepth(JsonNode root) {
        ArrayDeque<NodeDepth> pending = new ArrayDeque<>();
        pending.push(new NodeDepth(root, 1));
        while (!pending.isEmpty()) {
            NodeDepth current = pending.pop();
            if (current.depth() > MAX_JSON_DEPTH) throw invalid("JSON nesting exceeds bounds");
            if (current.node() != null && current.node().isContainerNode()) {
                for (JsonNode child : current.node()) {
                    pending.push(new NodeDepth(child, current.depth() + 1));
                }
            }
        }
    }

    static int encodedBytes(JsonNode node) {
        try {
            return JSON.writeValueAsBytes(node).length;
        } catch (Exception malformed) {
            throw invalid("JSON cannot be encoded");
        }
    }

    static ObjectNode boundedRequest(ObjectNode request) {
        requireDepth(request);
        if (encodedBytes(request) > ProviderChatContracts.MAX_REQUEST_BYTES) {
            throw new IllegalArgumentException("provider request exceeds bounds");
        }
        return request;
    }

    static ChatProtocolException invalid(String message) {
        return new ChatProtocolException(message);
    }

    private static ObjectMapper secureMapper() {
        StreamReadConstraints constraints = StreamReadConstraints.builder()
                .maxNestingDepth(MAX_JSON_DEPTH)
                .maxStringLength(MAX_RESPONSE_BYTES)
                .maxNumberLength(64)
                .maxNameLength(256)
                .build();
        return new ObjectMapper(JsonFactory.builder().streamReadConstraints(constraints).build());
    }

    private record NodeDepth(JsonNode node, int depth) { }

    static final class ChatProtocolException extends IllegalArgumentException {
        ChatProtocolException(String message) {
            super(message, null);
        }
    }
}

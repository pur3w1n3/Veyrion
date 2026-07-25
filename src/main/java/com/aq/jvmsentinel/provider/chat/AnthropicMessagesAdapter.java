package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.ai.tool.AiToolRegistry.ToolDefinition;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderProtocol;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static com.aq.jvmsentinel.provider.chat.ProviderChatContracts.StopReason;

/** Pure, bounded adapter for Anthropic Messages tool-use JSON. */
public final class AnthropicMessagesAdapter {
    public ObjectNode buildRequest(String model, int maxTokens, String systemPrompt,
                                   List<ProviderChatContracts.ChatTurn> turns,
                                   List<ToolDefinition> definitions) {
        model = ProviderChatContracts.boundedIdentifier(model, "model", 512);
        if (maxTokens <= 0 || maxTokens > 1_000_000) {
            throw new IllegalArgumentException("maxTokens is outside bounds");
        }
        ObjectNode request = ChatProtocolSupport.JSON.createObjectNode();
        request.put("model", model);
        request.put("max_tokens", maxTokens);
        if (systemPrompt != null && !systemPrompt.isBlank()) {
            request.put("system", ProviderChatContracts.boundedText(
                    systemPrompt, "system prompt", ProviderChatContracts.MAX_TEXT_BYTES, true));
        }
        appendTurns(request.putArray("messages"),
                List.copyOf(Objects.requireNonNull(turns, "turns")));
        Objects.requireNonNull(definitions, "definitions");
        if (!definitions.isEmpty()) {
            appendTools(request.putArray("tools"), definitions);
            ObjectNode toolChoice = request.putObject("tool_choice");
            toolChoice.put("type", "auto");
            toolChoice.put("disable_parallel_tool_use", true);
        }
        return ChatProtocolSupport.boundedRequest(request);
    }

    public ProviderChatContracts.ParsedResponse parseResponse(byte[] body) {
        JsonNode root = ChatProtocolSupport.parseResponse(body);
        JsonNode role = root.get("role");
        if (role == null || !role.isTextual() || !"assistant".equals(role.textValue())) {
            throw ChatProtocolSupport.invalid("Anthropic message role is invalid");
        }
        JsonNode stopNode = root.get("stop_reason");
        if (stopNode == null || !stopNode.isTextual()) {
            throw ChatProtocolSupport.invalid("Anthropic stop_reason is missing");
        }
        StopReason stop = switch (stopNode.textValue()) {
            case "end_turn", "stop_sequence" -> StopReason.COMPLETE;
            case "tool_use" -> StopReason.TOOL_USE;
            case "max_tokens" -> StopReason.TRUNCATED;
            case "refusal" -> StopReason.REFUSED;
            default -> throw ChatProtocolSupport.invalid("Anthropic stop_reason is unsupported");
        };
        JsonNode content = root.get("content");
        if (content == null || !content.isArray()) {
            throw ChatProtocolSupport.invalid("Anthropic content must be an array");
        }
        ObjectNode wire = ChatProtocolSupport.JSON.createObjectNode();
        wire.put("role", "assistant");
        wire.set("content", content.deepCopy());

        List<ToolCall> parsedCalls = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (JsonNode block : content) {
            if (!block.isObject()) throw ChatProtocolSupport.invalid("Anthropic content block is invalid");
            String type = text(block, "type");
            if ("text".equals(type)) {
                String value = text(block, "text");
                if (value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
                        > ProviderChatContracts.MAX_TEXT_BYTES || value.indexOf('\0') >= 0) {
                    throw ChatProtocolSupport.invalid("Anthropic text exceeds bounds");
                }
            } else if ("tool_use".equals(type)) {
                String id = bounded(text(block, "id"), "tool call id",
                        ProviderChatContracts.MAX_ID_BYTES);
                if (!ids.add(id)) throw ChatProtocolSupport.invalid("duplicate tool call id");
                String name = bounded(text(block, "name"), "tool name",
                        ProviderChatContracts.MAX_NAME_BYTES);
                JsonNode input = block.get("input");
                if (input == null || !input.isObject()) {
                    throw ChatProtocolSupport.invalid("Anthropic tool input must be an object");
                }
                ChatProtocolSupport.requireDepth(input);
                if (ChatProtocolSupport.encodedBytes(input) > ProviderChatContracts.MAX_ARGUMENT_BYTES) {
                    throw ChatProtocolSupport.invalid("Anthropic tool input exceeds bounds");
                }
                parsedCalls.add(new ToolCall(
                        CanonicalToolContracts.SCHEMA_VERSION, id, name, input.deepCopy()));
                if (parsedCalls.size() > 1) {
                    throw ChatProtocolSupport.invalid("parallel Anthropic tool calls are disabled");
                }
            } else {
                throw ChatProtocolSupport.invalid("unknown Anthropic content block");
            }
        }
        if (!parsedCalls.isEmpty()) ChatProtocolSupport.validateCalls(parsedCalls);
        if (stop == StopReason.TOOL_USE && parsedCalls.isEmpty()) {
            throw ChatProtocolSupport.invalid("Anthropic tool stop has no calls");
        }
        if (stop != StopReason.TOOL_USE) parsedCalls = List.of();
        ProviderChatContracts.AssistantTurn assistant =
                ChatProtocolSupport.assistant(ProviderProtocol.ANTHROPIC_MESSAGES, wire, parsedCalls);
        return new ProviderChatContracts.ParsedResponse(assistant, stop);
    }

    public ProviderChatContracts.ToolResultsTurn toolResults(
            ProviderChatContracts.AssistantTurn assistant, List<ToolResult> results) {
        return ChatProtocolSupport.resultTurn(
                assistant, results, ProviderProtocol.ANTHROPIC_MESSAGES);
    }

    private static void appendTurns(ArrayNode messages,
                                    List<ProviderChatContracts.ChatTurn> turns) {
        if (turns.size() > ProviderChatContracts.MAX_TURNS) {
            throw new IllegalArgumentException("too many chat turns");
        }
        ProviderChatContracts.AssistantTurn precedingAssistant = null;
        for (ProviderChatContracts.ChatTurn turn : turns) {
            if (turn instanceof ProviderChatContracts.UserTurn user) {
                if (precedingAssistant != null && !precedingAssistant.calls().isEmpty()) {
                    throw new IllegalArgumentException(
                            "Anthropic tool_use requires immediate tool_result");
                }
                ObjectNode message = messages.addObject();
                message.put("role", "user");
                message.put("content", user.text());
                precedingAssistant = null;
            } else if (turn instanceof ProviderChatContracts.AssistantTurn assistant) {
                if (assistant.protocol() != ProviderProtocol.ANTHROPIC_MESSAGES) {
                    throw new IllegalArgumentException("assistant protocol mismatch");
                }
                messages.add(assistant.wireMessage());
                precedingAssistant = assistant;
            } else if (turn instanceof ProviderChatContracts.ToolResultsTurn results) {
                if (results.protocol() != ProviderProtocol.ANTHROPIC_MESSAGES
                        || precedingAssistant != results.assistant()
                        || precedingAssistant.calls().isEmpty()) {
                    throw new IllegalArgumentException(
                            "Anthropic tool results must immediately follow their assistant");
                }
                ObjectNode message = messages.addObject();
                message.put("role", "user");
                ArrayNode blocks = message.putArray("content");
                for (ToolResult result : results.results()) {
                    ObjectNode block = blocks.addObject();
                    block.put("type", "tool_result");
                    block.put("tool_use_id", result.callId());
                    block.put("content", ChatProtocolSupport.resultPayloadText(result));
                    block.put("is_error", result.status() != ToolStatus.SUCCESS);
                }
                precedingAssistant = null;
            }
        }
        if (precedingAssistant != null && !precedingAssistant.calls().isEmpty()) {
            throw new IllegalArgumentException(
                    "Anthropic tool_use requires immediate tool_result");
        }
    }

    private static void appendTools(ArrayNode target, List<ToolDefinition> definitions) {
        Objects.requireNonNull(definitions, "definitions");
        if (definitions.isEmpty() || definitions.size() > 64) {
            throw new IllegalArgumentException("tool definition count is invalid");
        }
        Set<String> names = new HashSet<>();
        for (ToolDefinition definition : definitions) {
            String name = ProviderChatContracts.boundedIdentifier(
                    definition.name(), "tool name", ProviderChatContracts.MAX_NAME_BYTES);
            if (!names.add(name)) throw new IllegalArgumentException("duplicate tool definition");
            ChatProtocolSupport.requireDepth(definition.inputSchema());
            ObjectNode tool = target.addObject();
            tool.put("name", name);
            tool.put("description", ProviderChatContracts.boundedText(
                    definition.description(), "tool description", 4096, true));
            tool.set("input_schema", definition.inputSchema().deepCopy());
        }
    }

    private static String text(JsonNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isTextual()) {
            throw ChatProtocolSupport.invalid("Anthropic " + field + " is invalid");
        }
        return value.textValue();
    }

    private static String bounded(String value, String field, int bytes) {
        try {
            return ProviderChatContracts.boundedIdentifier(value, field, bytes);
        } catch (IllegalArgumentException invalid) {
            throw ChatProtocolSupport.invalid(field + " is invalid");
        }
    }
}

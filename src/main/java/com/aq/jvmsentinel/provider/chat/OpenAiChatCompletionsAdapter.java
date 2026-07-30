package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.ai.tool.AiToolRegistry.ToolDefinition;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderProtocol;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static com.aq.jvmsentinel.provider.chat.ProviderChatContracts.StopReason;

/** 纯、有界的 OpenAI Chat Completions tool-use JSON adapter。 */
public final class OpenAiChatCompletionsAdapter {
    public ObjectNode buildRequest(String model, String systemPrompt,
                                   List<ProviderChatContracts.ChatTurn> turns,
                                   List<ToolDefinition> definitions) {
        model = ProviderChatContracts.boundedIdentifier(model, "model", 512);
        ObjectNode request = ChatProtocolSupport.JSON.createObjectNode();
        request.put("model", model);
        ArrayNode messages = request.putArray("messages");
        if (systemPrompt != null && !systemPrompt.isBlank()) {
            ObjectNode system = messages.addObject();
            system.put("role", "system");
            system.put("content", ProviderChatContracts.boundedText(
                    systemPrompt, "system prompt", ProviderChatContracts.MAX_TEXT_BYTES, true));
        }
        appendTurns(messages, List.copyOf(Objects.requireNonNull(turns, "turns")));
        Objects.requireNonNull(definitions, "definitions");
        if (!definitions.isEmpty()) {
            appendTools(request.putArray("tools"), definitions);
            request.put("parallel_tool_calls", false);
        }
        return ChatProtocolSupport.boundedRequest(request);
    }

    public ProviderChatContracts.ParsedResponse parseResponse(byte[] body) {
        JsonNode root = ChatProtocolSupport.parseResponse(body);
        JsonNode choices = root.get("choices");
        if (choices == null || !choices.isArray() || choices.size() != 1
                || !choices.get(0).isObject()) {
            throw ChatProtocolSupport.invalid("OpenAI response must contain exactly one choice");
        }
        JsonNode choice = choices.get(0);
        JsonNode finishNode = choice.get("finish_reason");
        if (finishNode == null || !finishNode.isTextual()) {
            throw ChatProtocolSupport.invalid("OpenAI finish_reason is missing");
        }
        StopReason stop = switch (finishNode.textValue()) {
            case "stop" -> StopReason.COMPLETE;
            case "tool_calls" -> StopReason.TOOL_USE;
            case "length" -> StopReason.TRUNCATED;
            case "content_filter" -> StopReason.FILTERED;
            default -> throw ChatProtocolSupport.invalid("OpenAI finish_reason is unsupported");
        };
        JsonNode message = choice.get("message");
        if (message == null || !message.isObject()) {
            throw ChatProtocolSupport.invalid("OpenAI assistant message is missing");
        }
        JsonNode role = message.get("role");
        if (role == null || !role.isTextual() || !"assistant".equals(role.textValue())) {
            throw ChatProtocolSupport.invalid("OpenAI message role is invalid");
        }
        ObjectNode wire = ChatProtocolSupport.JSON.createObjectNode();
        wire.put("role", "assistant");
        JsonNode content = message.get("content");
        if (content == null || content.isNull()) {
            wire.putNull("content");
        } else if (content.isTextual()) {
            if (content.textValue().getBytes(StandardCharsets.UTF_8).length
                    > ProviderChatContracts.MAX_TEXT_BYTES || content.textValue().indexOf('\0') >= 0) {
                throw ChatProtocolSupport.invalid("OpenAI assistant text exceeds bounds");
            }
            wire.set("content", content.deepCopy());
        } else {
            throw ChatProtocolSupport.invalid("unknown OpenAI assistant content block");
        }

        // DeepSeek 风格 thinking model 要求 opaque reasoning token
        // 字段在下一轮 request 中与 assistant tool-call message 一并回显。
        // 仅保留在本有界 in-memory wire turn：不作为 canonical text 暴露、
        // 不持久化、不审计、不发给 tool。
        JsonNode reasoningContent = message.get("reasoning_content");
        if (reasoningContent != null && !reasoningContent.isNull()) {
            if (!reasoningContent.isTextual()
                    || reasoningContent.textValue().getBytes(StandardCharsets.UTF_8).length
                    > ProviderChatContracts.MAX_TEXT_BYTES
                    || reasoningContent.textValue().indexOf('\0') >= 0) {
                throw ChatProtocolSupport.invalid("OpenAI reasoning_content exceeds bounds");
            }
            wire.set("reasoning_content", reasoningContent.deepCopy());
        }

        boolean refused = false;
        JsonNode refusal = message.get("refusal");
        if (refusal != null && !refusal.isNull()) {
            if (!refusal.isTextual()) throw ChatProtocolSupport.invalid("OpenAI refusal is invalid");
            ProviderChatContracts.boundedText(
                    refusal.textValue(), "assistant refusal", ProviderChatContracts.MAX_TEXT_BYTES, true);
            wire.set("refusal", refusal.deepCopy());
            refused = true;
        }

        List<ToolCall> parsedCalls = new ArrayList<>();
        JsonNode toolCalls = message.get("tool_calls");
        if (toolCalls != null) {
            if (!toolCalls.isArray() || toolCalls.size() > ProviderChatContracts.MAX_CALLS) {
                throw ChatProtocolSupport.invalid("OpenAI tool_calls is invalid");
            }
            wire.set("tool_calls", toolCalls.deepCopy());
            parsedCalls = parseCalls(toolCalls);
        }
        if (stop == StopReason.TOOL_USE && parsedCalls.isEmpty()) {
            throw ChatProtocolSupport.invalid("OpenAI tool stop has no calls");
        }
        if (stop != StopReason.TOOL_USE || refused) parsedCalls = List.of();
        if (refused) stop = StopReason.REFUSED;
        ProviderChatContracts.AssistantTurn assistant =
                ChatProtocolSupport.assistant(ProviderProtocol.OPENAI_CHAT, wire, parsedCalls);
        return new ProviderChatContracts.ParsedResponse(assistant, stop);
    }

    public ProviderChatContracts.ToolResultsTurn toolResults(
            ProviderChatContracts.AssistantTurn assistant, List<ToolResult> results) {
        return ChatProtocolSupport.resultTurn(
                assistant, results, ProviderProtocol.OPENAI_CHAT);
    }

    private static List<ToolCall> parseCalls(JsonNode toolCalls) {
        List<ToolCall> calls = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (JsonNode item : toolCalls) {
            if (!item.isObject() || !text(item, "type").equals("function")) {
                throw ChatProtocolSupport.invalid("OpenAI tool call type is invalid");
            }
            String id = bounded(text(item, "id"), "tool call id", ProviderChatContracts.MAX_ID_BYTES);
            if (!ids.add(id)) throw ChatProtocolSupport.invalid("duplicate tool call id");
            JsonNode function = item.get("function");
            if (function == null || !function.isObject()) {
                throw ChatProtocolSupport.invalid("OpenAI function call is missing");
            }
            String name = bounded(text(function, "name"), "tool name", ProviderChatContracts.MAX_NAME_BYTES);
            String arguments = text(function, "arguments");
            JsonNode parsed = ChatProtocolSupport.parseArguments(arguments);
            calls.add(new ToolCall(CanonicalToolContracts.SCHEMA_VERSION, id, name, parsed));
        }
        ChatProtocolSupport.validateCalls(calls);
        return List.copyOf(calls);
    }

    private static String text(JsonNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isTextual()) {
            throw ChatProtocolSupport.invalid("OpenAI " + field + " is invalid");
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
                            "OpenAI tool calls require immediate tool results");
                }
                ObjectNode message = messages.addObject();
                message.put("role", "user");
                message.put("content", user.text());
                precedingAssistant = null;
            } else if (turn instanceof ProviderChatContracts.AssistantTurn assistant) {
                if (assistant.protocol() != ProviderProtocol.OPENAI_CHAT) {
                    throw new IllegalArgumentException("assistant protocol mismatch");
                }
                messages.add(assistant.wireMessage());
                precedingAssistant = assistant;
            } else if (turn instanceof ProviderChatContracts.ToolResultsTurn results) {
                if (results.protocol() != ProviderProtocol.OPENAI_CHAT
                        || precedingAssistant != results.assistant()) {
                    throw new IllegalArgumentException(
                            "OpenAI tool results must immediately follow their assistant");
                }
                for (ToolResult result : results.results()) {
                    ObjectNode message = messages.addObject();
                    message.put("role", "tool");
                    message.put("tool_call_id", result.callId());
                    message.put("content", ChatProtocolSupport.resultPayloadText(result));
                }
                precedingAssistant = null;
            }
        }
        if (precedingAssistant != null && !precedingAssistant.calls().isEmpty()) {
            throw new IllegalArgumentException("OpenAI tool calls require immediate tool results");
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
            ObjectNode wrapper = target.addObject();
            wrapper.put("type", "function");
            ObjectNode function = wrapper.putObject("function");
            function.put("name", name);
            function.put("description", ProviderChatContracts.boundedText(
                    definition.description(), "tool description", 4096, true));
            function.set("parameters", strictSchema(definition.inputSchema()));
            function.put("strict", true);
        }
    }

    private static JsonNode strictSchema(JsonNode source) {
        if (!source.isObject() || !"object".equals(source.path("type").asText())
                || !source.path("properties").isObject()
                || source.path("additionalProperties").asBoolean(true)) {
            throw new IllegalArgumentException("OpenAI strict tool schema is invalid");
        }
        ObjectNode schema = source.deepCopy();
        ArrayNode required = schema.putArray("required");
        List<String> names = new ArrayList<>();
        schema.path("properties").propertyStream().forEach(property -> names.add(property.getKey()));
        names.stream().sorted().forEach(required::add);
        return schema;
    }
}

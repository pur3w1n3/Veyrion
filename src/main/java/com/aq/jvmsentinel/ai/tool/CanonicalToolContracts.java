package com.aq.jvmsentinel.ai.tool;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Objects;

/**
 * Provider 中立工具协议。故意不含授权：call
 * 仅含模型输出，授权位于服务端 context。
 */
public final class CanonicalToolContracts {
    public static final int SCHEMA_VERSION = 1;

    private CanonicalToolContracts() { }

    public record ToolCall(int schemaVersion, String callId, String toolName, JsonNode arguments) {
        public ToolCall {
            version(schemaVersion);
            callId = identifier(callId, "callId", 256);
            toolName = identifier(toolName, "toolName", 128);
            Objects.requireNonNull(arguments, "arguments");
        }
    }

    public record ToolResult(int schemaVersion, String callId, String toolName, ToolStatus status,
                             List<ToolOutput> outputs, String errorCode, boolean truncated) {
        public ToolResult {
            version(schemaVersion);
            callId = identifier(callId, "callId", 256);
            toolName = identifier(toolName, "toolName", 128);
            Objects.requireNonNull(status, "status");
            outputs = List.copyOf(Objects.requireNonNull(outputs, "outputs"));
            if (outputs.size() > 4096) throw new IllegalArgumentException("too many outputs");
            if (status != ToolStatus.SUCCESS && !outputs.isEmpty()) {
                throw new IllegalArgumentException("non-success result cannot carry outputs");
            }
            errorCode = errorCode == null ? null : identifier(errorCode, "errorCode", 128);
            if (status == ToolStatus.SUCCESS && errorCode != null) {
                throw new IllegalArgumentException("successful result cannot carry an error");
            }
            if (status != ToolStatus.SUCCESS && errorCode == null) {
                throw new IllegalArgumentException("unsuccessful result requires an error code");
            }
            if (truncated && status != ToolStatus.SUCCESS) {
                throw new IllegalArgumentException("only successful results can be truncated");
            }
        }
    }

    /** No VERIFIED member exists: model/tool output can only cite facts or inference. */
    public record ToolOutput(OutputKind kind, String reference, JsonNode value) {
        public ToolOutput {
            Objects.requireNonNull(kind, "kind");
            reference = identifier(reference, "reference", 1024);
            Objects.requireNonNull(value, "value");
        }
    }

    public enum OutputKind {
        FACT,
        INFERENCE
    }

    public enum ToolStatus {
        SUCCESS,
        DENIED,
        INVALID_ARGUMENTS,
        NOT_FOUND,
        TIMEOUT,
        FAILED,
        CANCELLED,
        NOT_EXECUTED
    }

    static ToolResult error(ToolCall call, ToolStatus status, String code) {
        return new ToolResult(SCHEMA_VERSION, call.callId(), call.toolName(), status, List.of(), code, false);
    }

    private static void version(int value) {
        if (value != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
    }

    private static String identifier(String value, String name, int maximum) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > maximum
                || value.chars().anyMatch(c -> c == 0 || c == '\r' || c == '\n')) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }
}

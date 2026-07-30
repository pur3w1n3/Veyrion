package com.aq.jvmsentinel.analysis.executor;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * 通用运行时回调 / Executor 入口候选（非典型 Spring MVC 业务页，但进程内有
 * HTTP/RPC 回调面）。由 {@link ExecutorEntryAdapter} 产出，经 discoverer
 * 投影为 {@link com.aq.jvmsentinel.model.Entrypoint}。
 */
public record RuntimeCallbackEntry(
        String adapterId,
        String frameworkId,
        String protocol,
        String operation,
        String address,
        String declaringSymbol,
        List<String> inputs,
        List<String> preconditions,
        String evidenceSource,
        String evidenceSummary,
        String provenanceKind,
        double confidence
) {
    public RuntimeCallbackEntry {
        Objects.requireNonNull(adapterId, "adapterId");
        Objects.requireNonNull(frameworkId, "frameworkId");
        if (adapterId.isBlank() || frameworkId.isBlank()) {
            throw new IllegalArgumentException("adapterId/frameworkId must not be blank");
        }
        protocol = protocol == null || protocol.isBlank() ? "HTTP" : protocol.trim().toUpperCase(Locale.ROOT);
        operation = operation == null || operation.isBlank() ? "POST" : operation.trim().toUpperCase(Locale.ROOT);
        address = normalizeAddress(address);
        declaringSymbol = declaringSymbol == null ? "" : declaringSymbol.trim();
        inputs = List.copyOf(inputs == null ? List.of() : inputs);
        preconditions = List.copyOf(preconditions == null ? List.of() : preconditions);
        evidenceSource = evidenceSource == null ? "executor-adapter:" + adapterId : evidenceSource;
        evidenceSummary = evidenceSummary == null ? "" : evidenceSummary;
        provenanceKind = provenanceKind == null || provenanceKind.isBlank()
                ? "INFERENCE" : provenanceKind.trim().toUpperCase(Locale.ROOT);
        if (!Double.isFinite(confidence) || confidence < 0 || confidence > 1) {
            throw new IllegalArgumentException("confidence must be between 0 and 1");
        }
    }

    private static String normalizeAddress(String raw) {
        if (raw == null || raw.isBlank()) {
            return "/";
        }
        String value = raw.trim();
        if (!value.startsWith("/")) {
            value = "/" + value;
        }
        if (value.length() > 1 && value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value.replaceAll("/+", "/");
    }
}

package com.aq.jvmsentinel.cli;

import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.model.*;
import com.aq.jvmsentinel.policy.ScanPolicy;

import java.util.stream.Collectors;

final class JsonRenderer {
    private JsonRenderer() { }

    static String render(ArtifactDescriptor a, ScanPolicy p, PreAnalysisResult r, VersionedEvent e) {
        String entries = r.entryCatalog().entries().stream().map(x -> "{\"id\":\"" + q(x.id()) + "\",\"protocol\":\"" + q(x.protocol()) + "\",\"route\":\"" + q(x.route()) + "\",\"class\":\"" + q(x.declaringClass()) + "\",\"status\":\"" + x.status() + "\",\"confidence\":" + x.confidence() + "}").collect(Collectors.joining(","));
        String deps = r.dependencyMap().accesses().stream().map(x -> "{\"kind\":\"" + q(x.kind()) + "\",\"target\":\"" + q(x.target()) + "\",\"mode\":\"" + q(x.mode()) + "\",\"status\":\"" + x.status() + "}").collect(Collectors.joining(","));
        String sinks = r.sinkCatalog().sinks().stream().map(x -> "{\"category\":\"" + q(x.category()) + "\",\"symbol\":\"" + q(x.symbol()) + "\",\"status\":\"" + x.status() + "\",\"confidence\":" + x.confidence() + "}").collect(Collectors.joining(","));
        String context = e.context() == null ? "null" : "{\"projectId\":\"" + q(e.context().projectId())
                + "\",\"artifactDigest\":\"" + q(e.context().artifactDigest())
                + "\",\"scanId\":\"" + q(e.context().scanId())
                + "\",\"taskId\":\"" + q(e.context().taskId()) + "\"}";
        return "{\n" +
                "  \"artifact\":{\"id\":\"" + q(a.artifactId()) + "\",\"type\":\"" + a.type() + "\",\"sha256\":\"" + a.sha256() + "\",\"sizeBytes\":" + a.sizeBytes() + ",\"staticOnly\":" + a.staticOnly() + "},\n" +
                "  \"policy\":{\"authorized\":" + p.authorized() + ",\"network\":\"" + p.networkMode() + "\",\"dangerousActions\":\"" + p.dangerousActionMode() + "\"},\n" +
                "  \"entryCatalog\":[" + entries + "],\n  \"dependencyMap\":[" + deps + "],\n  \"sinkCatalog\":[" + sinks + "],\n" +
                "  \"event\":{\"type\":\"" + q(e.eventType()) + "\",\"schemaVersion\":" + e.schemaVersion() + ",\"context\":" + context + ",\"idempotencyScope\":\"" + q(e.idempotencyKey().scope()) + "\",\"idempotencyValue\":\"" + q(e.idempotencyKey().value()) + "\"}\n}";
    }

    private static String q(String value) {
        if (value == null) return "";
        StringBuilder escaped = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> escaped.append("\\\\");
                case '"' -> escaped.append("\\\"");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (c < 0x20) escaped.append(String.format("\\u%04x", (int) c));
                    else escaped.append(c);
                }
            }
        }
        return escaped.toString();
    }
}

package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Read-only projection of an already persisted scan. It never reads artifact
 * bytes and has no execution, decompiler, network, or shell capability.
 */
public final class ControlPlaneToolDataSource implements ToolDataSource {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final String scanId;

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId) {
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
    }

    @Override
    public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                        String query, int limit) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        String requested = kind.toUpperCase(Locale.ROOT);
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT);
        List<FactRecord> result = new ArrayList<>();
        if ("ENTRY".equals(requested) || "ENTRYPOINT".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.EntryDto value : scan.dto().entries()) {
                addIfMatching(result, scope, "entry:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("DEPENDENCY".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.DependencyDto value : scan.dto().dependencies()) {
                addIfMatching(result, scope, "dependency:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("SINK".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.SinkDto value : scan.dto().sinks()) {
                addIfMatching(result, scope, "sink:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("EVIDENCE".equals(requested) || "FACT".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.EvidenceDto value : scan.evidence().values()) {
                addIfMatching(result, scope, value.evidenceId(), safeEvidence(value), needle, limit);
            }
        }
        return List.copyOf(result);
    }

    @Override
    public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        ApiDtos.EvidenceDto value = scan.evidence().get(evidenceRef);
        if (value != null) {
            return Optional.of(new FactRecord(scope, value.evidenceId(), safeEvidence(value)));
        }
        if (evidenceRef.startsWith("entry:")) {
            String id = evidenceRef.substring("entry:".length());
            return scan.dto().entries().stream().filter(entry -> entry.id().equals(id)).findFirst()
                    .map(entry -> new FactRecord(scope, evidenceRef, JSON.valueToTree(entry)));
        }
        return Optional.empty();
    }

    private ControlPlaneStore.ScanRecord scopedScan(ToolExecutionContext.Scope scope) {
        if (!"local".equals(scope.workspaceId())) throw new SecurityException("workspace scope mismatch");
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        if (!scope.projectId().equals(scan.dto().projectId())) {
            throw new SecurityException("project scope mismatch");
        }
        return scan;
    }

    private static JsonNode safeEvidence(ApiDtos.EvidenceDto value) {
        // Only the bounded evidence summary and provenance metadata cross the tool boundary.
        return JSON.createObjectNode()
                .put("evidenceId", value.evidenceId())
                .put("provenanceKind", value.provenanceKind())
                .put("source", value.source())
                .put("summary", value.summary())
                .put("verificationStatus", value.verificationStatus())
                .put("dependencyMode", value.dependencyMode());
    }

    private static void addIfMatching(List<FactRecord> result, ToolExecutionContext.Scope scope,
                                      String reference, JsonNode value, String needle, int limit) {
        if (result.size() >= limit) return;
        String searchable = value.toString().toLowerCase(Locale.ROOT);
        if (needle.isEmpty() || searchable.contains(needle)) {
            result.add(new FactRecord(scope, reference, value));
        }
    }
}

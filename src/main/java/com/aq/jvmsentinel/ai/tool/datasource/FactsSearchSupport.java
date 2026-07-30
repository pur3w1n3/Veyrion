package com.aq.jvmsentinel.ai.tool.datasource;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.experiment.RuntimePostureOrchestrator;
import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.model.StaticContrastRow;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * facts_search / evidence_get 事实检索与匹配辅助。
 */
public final class FactsSearchSupport {
    private final DatasourceScope datasourceScope;
    private final ControlPlaneStore store;
    private final String scanId;

    public FactsSearchSupport(DatasourceScope datasourceScope, ControlPlaneStore store, String scanId) {
        this.datasourceScope = Objects.requireNonNull(datasourceScope, "datasourceScope");
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
    }

    public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                        String query, int limit) {
        rejectPathTracePolicyOverrides(query);
        ControlPlaneStore.ScanRecord scan = datasourceScope.scopedScan(scope);
        String requested = kind.toUpperCase(Locale.ROOT);
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT);
        List<FactRecord> result = new ArrayList<>();
        if ("SCAN".equals(requested) || "METADATA".equals(requested) || "ANY".equals(requested)) {
            addIfMatching(result, scope, "scan:" + scan.dto().scanId(),
                    DatasourceJson.JSON.valueToTree(scan.dto()), needle, limit);
        }
        if ("ENTRY".equals(requested) || "ENTRYPOINT".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.EntryDto value : scan.dto().entries()) {
                addIfMatching(result, scope, "entry:" + value.id(),
                        DatasourceJson.JSON.valueToTree(value), needle, limit);
            }
        }
        if ("DEPENDENCY".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.DependencyDto value : scan.dto().dependencies()) {
                addIfMatching(result, scope, "dependency:" + value.id(),
                        DatasourceJson.JSON.valueToTree(value), needle, limit);
            }
        }
        if ("SINK".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.SinkDto value : scan.dto().sinks()) {
                addIfMatching(result, scope, "sink:" + value.id(),
                        DatasourceJson.JSON.valueToTree(value), needle, limit);
            }
        }
        if ("PATH_RUN".equals(requested) || "PATHRUN".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.PathRunDto value : datasourceScope.pathRuns(scan)) {
                addIfMatching(result, scope, "pathrun:" + value.pathRunId(),
                        PathRunFactSupport.pathRunFact(value), needle, limit);
            }
        }
        if ("PATH_TRACE".equals(requested) || "PATHTRACE".equals(requested) || "ANY".equals(requested)) {
            for (PathTrace trace : datasourceScope.pathTraces(scan)) {
                addIfMatching(result, scope, "pathtrace:" + trace.pathTraceId(),
                        PathRunFactSupport.pathTraceFact(trace), needle, limit);
            }
        }
        if ("STATIC_CONTRAST".equals(requested) || "CONTRAST".equals(requested) || "ANY".equals(requested)) {
            ContrastLedger.Ledger ledger = ContrastLedger.build(
                    scan.dto().entries(), scan.dto().sinks(), scan.evidence(), datasourceScope.pathRuns(scan),
                    StaticFactSnapshot.resolveContrastTaintPaths(
                            store.staticFacts(scanId), scan.dto().sinks()));
            for (StaticContrastRow row : ledger.rows()) {
                addIfMatching(result, scope, "contrast:" + row.rowId(),
                        ContrastLedger.toFactNode(row), needle, limit);
            }
        }
        if ("EVIDENCE".equals(requested) || "FACT".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.EvidenceDto value : scan.evidence().values()) {
                addIfMatching(result, scope, value.evidenceId(),
                        PathRunFactSupport.safeEvidence(value), needle, limit);
            }
            for (ApiDtos.EvidenceDto value : datasourceScope.dynamicEvidence(scan)) {
                addIfMatching(result, scope, value.evidenceId(),
                        PathRunFactSupport.safeEvidence(value), needle, limit);
            }
        }
        if ("DYNAMIC_EVIDENCE".equals(requested) || "RUNTIME_EVIDENCE".equals(requested)) {
            for (ApiDtos.EvidenceDto value : datasourceScope.dynamicEvidence(scan)) {
                addIfMatching(result, scope, value.evidenceId(),
                        PathRunFactSupport.safeEvidence(value), needle, limit);
            }
        }
        return List.copyOf(result);
    }

    public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
        ControlPlaneStore.ScanRecord scan = datasourceScope.scopedScan(scope);
        ApiDtos.EvidenceDto value = scan.evidence().get(evidenceRef);
        if (value != null) {
            return Optional.of(new FactRecord(scope, value.evidenceId(), PathRunFactSupport.safeEvidence(value)));
        }
        Optional<ApiDtos.EvidenceDto> dynamic = datasourceScope.dynamicEvidence(scan).stream()
                .filter(item -> item.evidenceId().equals(evidenceRef)).findFirst();
        if (dynamic.isPresent()) {
            return Optional.of(new FactRecord(scope, evidenceRef, PathRunFactSupport.safeEvidence(dynamic.get())));
        }
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), evidenceRef);
        if (resolution.resolved()) {
            return Optional.of(new FactRecord(scope, resolution.canonicalRef(),
                    DatasourceJson.JSON.valueToTree(resolution.entry())));
        }
        if (evidenceRef != null && evidenceRef.startsWith("pathrun:")) {
            String id = evidenceRef.substring("pathrun:".length());
            return datasourceScope.pathRuns(scan).stream().filter(run -> run.pathRunId().equals(id)).findFirst()
                    .map(run -> new FactRecord(scope, evidenceRef, PathRunFactSupport.pathRunFact(run)));
        }
        if (evidenceRef != null && evidenceRef.startsWith("pathtrace:")) {
            String id = evidenceRef.substring("pathtrace:".length());
            return datasourceScope.pathTraces(scan).stream().filter(trace -> trace.pathTraceId().equals(id)).findFirst()
                    .map(trace -> new FactRecord(scope, evidenceRef, PathRunFactSupport.pathTraceFact(trace)));
        }
        return Optional.empty();
    }

    /** 拒绝客户端通过 query 参数覆盖 path trace / 沙箱策略。 */
    static void rejectPathTracePolicyOverrides(String query) {
        if (query == null || query.isBlank()) {
            return;
        }
        Map<String, String> probe = new LinkedHashMap<>();
        for (String token : query.split("[;&]")) {
            int eq = token.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            probe.put(token.substring(0, eq).trim(), token.substring(eq + 1).trim());
        }
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(true, false, probe);
        } catch (SecurityException denied) {
            throw denied;
        }
        String lower = query.toLowerCase(Locale.ROOT);
        for (String forbidden : List.of("forcedreachability", "forcedguardrefs", "command=", "image=",
                "mount=", "network=", "uid=", "budget=")) {
            if (lower.contains(forbidden)) {
                throw new SecurityException("CLIENT_POLICY_OVERRIDE_DENIED:" + forbidden);
            }
        }
    }

    private static void addIfMatching(List<FactRecord> result, ToolExecutionContext.Scope scope,
                                      String reference, JsonNode value, String needle, int limit) {
        if (result.size() >= limit) {
            return;
        }
        String searchable = value.toString().toLowerCase(Locale.ROOT);
        if (needle.isEmpty() || searchable.contains(needle)) {
            result.add(new FactRecord(scope, reference, value));
        }
    }
}

package com.aq.jvmsentinel.ai.tool.datasource;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.experiment.RuntimePostureOrchestrator;
import com.aq.jvmsentinel.analysis.hypothesis.FindingRuntimeEnricher;
import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord;
import com.aq.jvmsentinel.ai.tool.ToolDataSource.FactSearchPage;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.model.StaticContrastRow;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

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
    /** kind=ANY 时按桶采样，避免 ENTRY 等前序种类吃满 limit 后 PATH_RUN/SINK 静默为 0。 */
    private static final List<String> ANY_KIND_BUCKETS = List.of(
            "SCAN", "ENTRY", "DEPENDENCY", "SINK", "FINDING", "PATH_RUN", "PATH_TRACE",
            "STATIC_CONTRAST", "EVIDENCE");
    /** 单次扫描匹配上限；触顶时 totalCapped=true，模型须收窄 query。 */
    private static final int MAX_MATCH_SCAN = 2_000;

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
        return searchFactsPage(scope, kind, query, limit, 0).records();
    }

    public FactSearchPage searchFactsPage(ToolExecutionContext.Scope scope, String kind,
                                          String query, int limit, int offset) {
        rejectPathTracePolicyOverrides(query);
        ControlPlaneStore.ScanRecord scan = datasourceScope.scopedScan(scope);
        String requested = kind == null ? "" : kind.toUpperCase(Locale.ROOT);
        QueryOptions options = QueryOptions.parse(query);
        int cappedLimit = Math.max(1, Math.min(100, limit));
        int cappedOffset = Math.max(0, Math.min(100_000, offset));
        List<FactRecord> matched = new ArrayList<>();
        if ("ANY".equals(requested)) {
            matched.addAll(searchAny(scope, scan, options,
                    Math.min(MAX_MATCH_SCAN, cappedOffset + cappedLimit)));
        } else {
            appendKind(matched, scope, scan, requested, options, MAX_MATCH_SCAN);
        }
        boolean totalCapped = matched.size() >= MAX_MATCH_SCAN;
        int total = matched.size();
        int from = Math.min(cappedOffset, total);
        int to = Math.min(from + cappedLimit, total);
        return new FactSearchPage(matched.subList(from, to), total, cappedOffset, cappedLimit, totalCapped);
    }

    /**
     * 跨种类采样：每桶最多 ceil(limit/buckets) 条，再按桶顺序合并至 limit。
     * 保证在有数据时 SINK / PATH_RUN 等不会被前序 ENTRY 挤出。
     */
    private List<FactRecord> searchAny(ToolExecutionContext.Scope scope,
                                       ControlPlaneStore.ScanRecord scan,
                                       QueryOptions options,
                                       int limit) {
        int perKind = Math.max(1, (limit + ANY_KIND_BUCKETS.size() - 1) / ANY_KIND_BUCKETS.size());
        List<FactRecord> merged = new ArrayList<>();
        for (String bucket : ANY_KIND_BUCKETS) {
            if (merged.size() >= limit) {
                break;
            }
            List<FactRecord> bucketHits = new ArrayList<>();
            appendKind(bucketHits, scope, scan, bucket, options, perKind);
            for (FactRecord hit : bucketHits) {
                if (merged.size() >= limit) {
                    break;
                }
                merged.add(hit);
            }
        }
        if (merged.size() < limit) {
            List<FactRecord> refill = new ArrayList<>();
            for (String bucket : ANY_KIND_BUCKETS) {
                appendKind(refill, scope, scan, bucket, options, limit);
            }
            for (FactRecord hit : refill) {
                if (merged.size() >= limit) {
                    break;
                }
                boolean exists = false;
                for (FactRecord already : merged) {
                    if (already.reference().equals(hit.reference())) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    merged.add(hit);
                }
            }
        }
        return List.copyOf(merged);
    }

    private void appendKind(List<FactRecord> result, ToolExecutionContext.Scope scope,
                            ControlPlaneStore.ScanRecord scan, String requested,
                            QueryOptions options, int limit) {
        String needle = options.needle();
        if ("SCAN".equals(requested) || "METADATA".equals(requested)) {
            addIfMatching(result, scope, "scan:" + scan.dto().scanId(),
                    DatasourceJson.JSON.valueToTree(scan.dto()), needle, limit);
        }
        if ("ENTRY".equals(requested) || "ENTRYPOINT".equals(requested)) {
            for (ApiDtos.EntryDto value : scan.dto().entries()) {
                addIfMatching(result, scope, "entry:" + value.id(),
                        DatasourceJson.JSON.valueToTree(value), needle, limit);
            }
        }
        if ("DEPENDENCY".equals(requested)) {
            for (ApiDtos.DependencyDto value : scan.dto().dependencies()) {
                addIfMatching(result, scope, "dependency:" + value.id(),
                        DatasourceJson.JSON.valueToTree(value), needle, limit);
            }
        }
        if ("SINK".equals(requested)) {
            for (ApiDtos.SinkDto value : scan.dto().sinks()) {
                addIfMatching(result, scope, "sink:" + value.id(),
                        DatasourceJson.JSON.valueToTree(value), needle, limit);
            }
        }
        if ("FINDING".equals(requested) || "FINDINGS".equals(requested)) {
            List<ApiDtos.PathRunDto> runs = datasourceScope.pathRuns(scan);
            Map<String, PathTrace> traces = tracesByPathRunId(scan);
            for (ApiDtos.FindingDto value : scan.dto().findings()) {
                addIfMatching(result, scope, "finding:" + value.findingId(),
                        findingFact(value, scan.dto().entries(), runs, traces), needle, limit);
            }
        }
        if ("PATH_RUN".equals(requested) || "PATHRUN".equals(requested)) {
            for (ApiDtos.PathRunDto value : datasourceScope.pathRuns(scan)) {
                addIfMatching(result, scope, "pathrun:" + value.pathRunId(),
                        PathRunFactSupport.pathRunFact(value), needle, limit);
            }
        }
        if ("PATH_TRACE".equals(requested) || "PATHTRACE".equals(requested)) {
            for (PathTrace trace : datasourceScope.pathTraces(scan)) {
                addIfMatching(result, scope, "pathtrace:" + trace.pathTraceId(),
                        PathRunFactSupport.pathTraceFact(trace, options.eventsOffset(), options.eventsLimit()),
                        needle, limit);
            }
        }
        if ("STATIC_CONTRAST".equals(requested) || "CONTRAST".equals(requested)) {
            ContrastLedger.Ledger ledger = ContrastLedger.build(
                    scan.dto().entries(), scan.dto().sinks(), scan.evidence(), datasourceScope.pathRuns(scan),
                    StaticFactSnapshot.resolveContrastTaintPaths(
                            store.staticFacts(scanId), scan.dto().sinks()));
            for (StaticContrastRow row : ledger.rows()) {
                addIfMatching(result, scope, "contrast:" + row.rowId(),
                        ContrastLedger.toFactNode(row), needle, limit);
            }
        }
        if ("EVIDENCE".equals(requested) || "FACT".equals(requested)) {
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
            int q = id.indexOf('?');
            QueryOptions options = QueryOptions.parse(q >= 0 ? id.substring(q + 1) : "");
            String traceId = q >= 0 ? id.substring(0, q) : id;
            return datasourceScope.pathTraces(scan).stream()
                    .filter(trace -> trace.pathTraceId().equals(traceId)).findFirst()
                    .map(trace -> new FactRecord(scope, "pathtrace:" + traceId,
                            PathRunFactSupport.pathTraceFact(trace, options.eventsOffset(), options.eventsLimit())));
        }
        if (evidenceRef != null && evidenceRef.startsWith("finding:")) {
            String id = evidenceRef.substring("finding:".length());
            List<ApiDtos.PathRunDto> runs = datasourceScope.pathRuns(scan);
            Map<String, PathTrace> traces = tracesByPathRunId(scan);
            return scan.dto().findings().stream()
                    .filter(finding -> finding.findingId().equals(id))
                    .findFirst()
                    .map(finding -> new FactRecord(scope, evidenceRef,
                            findingFact(finding, scan.dto().entries(), runs, traces)));
        }
        return Optional.empty();
    }

    private Map<String, PathTrace> tracesByPathRunId(ControlPlaneStore.ScanRecord scan) {
        LinkedHashMap<String, PathTrace> out = new LinkedHashMap<>();
        for (PathTrace trace : datasourceScope.pathTraces(scan)) {
            if (trace == null || trace.pathRunId() == null || trace.pathRunId().isBlank()) continue;
            out.putIfAbsent(trace.pathRunId(), trace);
        }
        return out;
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

    /**
     * FINDING 事实附带 enricher 投影（pathRunRefs / 验证态），避免 AI 只见 DB 静态快照
     * 而与 PATH_RUN CONFIRMED 材料脱节。
     */
    static JsonNode findingFact(
            ApiDtos.FindingDto value,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.PathRunDto> pathRuns,
            Map<String, PathTrace> tracesByPathRunId) {
        ObjectNode node = DatasourceJson.JSON.createObjectNode();
        node.put("kind", "FINDING");
        node.put("findingId", value.findingId());
        node.put("title", value.title() == null ? "" : value.title());
        node.put("severity", value.severity() == null ? "" : value.severity());
        String dbStatus = value.verificationStatus() == null ? "" : value.verificationStatus();
        node.put("verificationStatus", dbStatus);
        node.put("dbVerificationStatus", dbStatus);
        node.put("entrypointId", value.entrypointId() == null ? "" : value.entrypointId());
        node.put("entry", value.entry() == null ? "" : value.entry());
        node.put("sinkId", value.sinkId() == null ? "" : value.sinkId());
        node.put("sink", value.sink() == null ? "" : value.sink());
        node.put("hypothesisId", value.hypothesisId() == null ? "" : value.hypothesisId());
        node.put("securityProperty", value.securityProperty() == null ? "" : value.securityProperty());
        node.put("confidence", value.confidence());
        node.put("dependencyMode", value.dependencyMode() == null ? "" : value.dependencyMode());
        try {
            FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                    value,
                    entries == null ? List.of() : entries,
                    pathRuns == null ? List.of() : pathRuns,
                    tracesByPathRunId == null ? Map.of() : tracesByPathRunId,
                    property -> property);
            if (enrichment != null) {
                if (!enrichment.title().isBlank()) {
                    node.put("title", enrichment.title());
                }
                if (!enrichment.verificationStatus().isBlank()) {
                    node.put("verificationStatus", enrichment.verificationStatus());
                    node.put("enrichedVerificationStatus", enrichment.verificationStatus());
                }
                if (!enrichment.pathRunRefs().isEmpty()) {
                    ArrayNode refs = node.putArray("pathRunRefs");
                    enrichment.pathRunRefs().forEach(refs::add);
                }
                if (!enrichment.postureKind().isBlank()) {
                    node.put("postureKind", enrichment.postureKind());
                }
                if (!enrichment.requiredPrivilege().isBlank()) {
                    node.put("requiredPrivilege", enrichment.requiredPrivilege());
                }
            }
        } catch (RuntimeException ignored) {
            // 投影失败时仍返回 DB 字段，不阻断 facts_search。
        }
        return node;
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

    /** 从 query 剥离续取参数，剩余部分作子串 needle。 */
    record QueryOptions(String needle, int eventsOffset, int eventsLimit) {
        static QueryOptions parse(String query) {
            if (query == null || query.isBlank()) {
                return new QueryOptions("", 0, PathRunFactSupport.DEFAULT_EVENTS_LIMIT);
            }
            int eventsOffset = 0;
            int eventsLimit = PathRunFactSupport.DEFAULT_EVENTS_LIMIT;
            StringBuilder needleParts = new StringBuilder();
            for (String token : query.split("[\\s;&]+")) {
                if (token.isBlank()) {
                    continue;
                }
                int eq = token.indexOf('=');
                if (eq > 0) {
                    String key = token.substring(0, eq).trim().toLowerCase(Locale.ROOT);
                    String raw = token.substring(eq + 1).trim();
                    if ("eventsoffset".equals(key) || "events_offset".equals(key)) {
                        eventsOffset = parseNonNegative(raw, 0);
                        continue;
                    }
                    if ("eventslimit".equals(key) || "events_limit".equals(key)) {
                        eventsLimit = Math.max(1, Math.min(PathRunFactSupport.MAX_EVENTS_LIMIT,
                                parseNonNegative(raw, PathRunFactSupport.DEFAULT_EVENTS_LIMIT)));
                        continue;
                    }
                }
                if (needleParts.length() > 0) {
                    needleParts.append(' ');
                }
                needleParts.append(token);
            }
            return new QueryOptions(needleParts.toString().toLowerCase(Locale.ROOT), eventsOffset, eventsLimit);
        }

        private static int parseNonNegative(String raw, int fallback) {
            try {
                return Math.max(0, Integer.parseInt(raw));
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
    }
}

package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.analysis.FindingRanker;
import com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector;
import com.aq.jvmsentinel.analysis.experiment.PathDebugWireHelper;
import com.aq.jvmsentinel.analysis.hypothesis.FindingRuntimeEnricher;
import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.analysis.ir.EvidenceGraphProjector;
import com.aq.jvmsentinel.analysis.pack.AnalysisPack;
import com.aq.jvmsentinel.analysis.pack.AnalysisPackRegistry;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.control.service.DashboardService;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.SqlExperimentCard;
import com.aq.jvmsentinel.worker.ProbeBudgetExplainer;
import com.aq.jvmsentinel.worker.SqlExperimentCardBuilder;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** 从 ControlPlaneRouteHandlers 拆出的 HTTP 处理器：PathFindings 域。 */
final class PathFindingsHttpHandlers extends ControlPlaneHandlerSupport {

    PathFindingsHttpHandlers(ControlPlaneHandlerHost host) {
        super(host);
    }

    public void sendScanCoverage(HttpExchange exchange, String scanId) throws IOException {
        Map<String, Object> body = host.scanQueryHttp.coverageBody(scanId)
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found"));
        ControlPlaneHttpSupport.sendJson(exchange, 200, body);
    }
    public void sendScanEvidenceGraph(HttpExchange exchange, String scanId) throws IOException {
        Map<String, Object> body = host.scanQueryHttp.evidenceGraphBody(scanId)
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found"));
        ControlPlaneHttpSupport.sendJson(exchange, 200, body);
    }
    public void sendScanHypotheses(HttpExchange exchange, String scanId) throws IOException {
        if (!host.scanQueryPort.exists(scanId)) {
            throw new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found");
        }
        Map<String, Object> body = host.scanQueryHttp.hypothesesBody(scanId)
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found"));
        ControlPlaneHttpSupport.sendJson(exchange, 200, body);
    }
    public void sendScanAiMemory(HttpExchange exchange, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        String section = ControlPlaneHttpSupport.query(exchange.getRequestURI(), "section");
        if (section == null || section.isBlank()) {
            section = "FULL";
        }
        List<ApiDtos.PathRunDto> runs = mergedPathRunsForScan(
                scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
        Map<String, String> priors = new LinkedHashMap<>();
        for (var job : host.store.aiJobs(scan.dto().projectId())) {
            if (job == null || !scanId.equals(job.scanId()) || !"COMPLETED".equals(job.status())
                    || job.conclusionJson() == null) {
                continue;
            }
            try {
                Object summaryObj = JsonCodec.parseObject(job.conclusionJson()).get("summary");
                String summary = summaryObj == null ? "" : String.valueOf(summaryObj).trim();
                if (!summary.isBlank()) {
                    priors.putIfAbsent(job.role().name(),
                            summary.length() > 800 ? summary.substring(0, 800) : summary);
                }
            } catch (RuntimeException ignored) {
                // 跳过
            }
        }
        Map<String, Object> full = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.build(
                host.store, scanId, runs, priors);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        body.put("section", section.trim().toUpperCase(Locale.ROOT));
        body.put("memory", com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.section(full, section));
        ControlPlaneHttpSupport.sendJson(exchange, 200, body);
    }

    /** 只读 coverage 矩阵投影；SUCCESS 永不映射为 safe/secure。 */
    CoverageMatrix coverageMatrixForScan(String scanId) {
        return coverageMatrixForScan(scanId, CoverageMatrixProjector.SuppressMode.NONE);
    }

    CoverageMatrix coverageMatrixForScan(String scanId, CoverageMatrixProjector.SuppressMode suppressMode) {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathRunDto> pathRuns = mergedPathRunsForScan(
                dto.projectId(), dto.artifactDigest(), scanId);
        return CoverageMatrixProjector.project(
                scanId,
                host.store.staticFacts(scanId),
                dto.entries(),
                dto.dependencies(),
                dto.sinks(),
                host.store.hypotheses(scanId),
                pathRuns,
                suppressMode);
    }

    /**
     * 不含 analyzer 叠加层的基础 Evidence Graph 投影（P1-02 / P1-08）。
     * 公共查询路径经 {@link #evidenceGraphQueryPort()}。
     */
    EvidenceGraph projectEvidenceGraphBase(String scanId) {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        ApiDtos.ScanDto dto = scan.dto();
        Optional<StaticFactSnapshot> facts = host.store.staticFacts(scanId);
        // P1-02：优先使用 StaticFactSnapshot 中持久化的权威图（schema v4）。
        if (facts.isPresent() && facts.get().hasPersistedEvidenceGraph()) {
            return facts.get().evidenceGraph().orElseThrow();
        }
        List<ApiDtos.PathRunDto> pathRuns = mergedPathRunsForScan(
                dto.projectId(), dto.artifactDigest(), scanId);
        return EvidenceGraphProjector.fromScan(
                scanId,
                facts,
                dto.entries(),
                dto.sinks(),
                dto.dependencies(),
                host.store.hypotheses(scanId),
                dto.findings(),
                pathRuns);
    }

    /** 含 analyzer ProgramNode 叠加层的只读 Evidence Graph（P1-08）。 */
    EvidenceGraph evidenceGraphForScan(String scanId) {
        return host.evidenceGraphQueryPort.evidenceGraph(scanId)
                .orElseThrow(() -> new ControlPlaneStore.MissingRecordException("scan not found: " + scanId));
    }
    List<Map<String, Object>> pathRunViewsForPort(String scanId) {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathRunDto> pathRuns = mergedPathRunsForScan(
                dto.projectId(), dto.artifactDigest(), scanId);
        Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> tracesByRun = pathTracesByPathRunId(
                dto.projectId(), dto.artifactDigest(), scanId);
        List<Map<String, Object>> maps = new ArrayList<>(pathRuns.size());
        for (ApiDtos.PathRunDto run : pathRuns) {
            maps.add(PathDebugWireHelper.enrichPathRunMap(
                    PathDebugWireHelper.basePathRunMap(run),
                    tracesByRun.get(run.pathRunId())));
        }
        return maps;
    }
    Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> pathTracesByPathRunId(
            String projectId, String artifactDigest, String scanId) {
        Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> byRun = new LinkedHashMap<>();
        for (SQLiteControlPlanePersistence.PathTraceData row : host.store.loadPathTracesForScan(
                projectId, artifactDigest, scanId)) {
            com.aq.jvmsentinel.domain.pathdebug.PathTrace cached = host.store.pathTraceForPathRun(row.pathRunId());
            if (cached != null) {
                byRun.put(row.pathRunId(), cached);
                continue;
            }
            try {
                byRun.put(row.pathRunId(), com.aq.jvmsentinel.domain.pathdebug.PathTrace.fromMap(
                        JsonCodec.parseObject(row.payloadJson())));
            } catch (RuntimeException ignored) {
                // 跳过格式错误的持久化 trace
            }
        }
        return byRun;
    }
    List<ApiDtos.PathRunDto> mergedPathRunsForScan(String projectId, String artifactDigest, String scanId) {
        Map<String, ApiDtos.PathRunDto> byId = new LinkedHashMap<>();
        for (ApiDtos.PathRunDto run : host.store.loadPathRunsForScan(projectId, artifactDigest, scanId)) {
            byId.put(run.pathRunId(), run);
        }
        for (ApiDtos.PathRunDto run : host.traceProjectionService.pathRunsForScan(projectId, artifactDigest, scanId)) {
            byId.put(run.pathRunId(), run);
        }
        return List.copyOf(byId.values());
    }
    List<ApiDtos.PathRunDto> mergedPathRunsForTask(TaskScope scope) {
        Map<String, ApiDtos.PathRunDto> byId = new LinkedHashMap<>();
        for (ApiDtos.PathRunDto run : host.store.loadPathRunsForTask(scope.taskId())) {
            byId.put(run.pathRunId(), run);
        }
        for (ApiDtos.PathRunDto run : host.traceProjectionService.pathRunsForTask(scope)) {
            byId.put(run.pathRunId(), run);
        }
        return List.copyOf(byId.values());
    }
    List<ApiDtos.PathDto> dynamicPaths(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathDto> projected = new ArrayList<>(host.traceProjectionService.pathsForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId()));
        List<ApiDtos.PathDto> unreached = host.unreachedDynamicPaths.getOrDefault(dto.scanId(), List.of());
        if (!unreached.isEmpty()) projected.addAll(unreached);
        return List.copyOf(projected);
    }
    List<ApiDtos.EvidenceDto> dynamicEvidence(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        return host.traceProjectionService.evidenceForScan(dto.projectId(), dto.artifactDigest(), dto.scanId());
    }
    static boolean isAuthGapFinding(ApiDtos.FindingDto finding) {
        if (finding == null) return false;
        String sinkId = finding.sinkId() == null ? "" : finding.sinkId().toLowerCase(Locale.ROOT);
        String sink = finding.sink() == null ? "" : finding.sink().toLowerCase(Locale.ROOT);
        String property = finding.securityProperty() == null ? "" : finding.securityProperty().toUpperCase(Locale.ROOT);
        String title = finding.title() == null ? "" : finding.title();
        return sinkId.startsWith("sink-auth-gap")
                || sinkId.startsWith("guard:")
                || sinkId.startsWith("hypothesis:")
                || SecurityHypothesisProjector.GUARD_COVERAGE_SINK_LABEL.equalsIgnoreCase(sink)
                || "AUTH_GAP".equals(property)
                || "GUARD_COVERAGE".equals(property)
                || title.contains("鉴权缺口")
                || title.toLowerCase(Locale.ROOT).contains("auth gap");
    }
    public void mergeRuntimeLoadedClasses(String scanId, List<String> loadedClassNames, String actorId) {
        Objects.requireNonNull(scanId, "scanId");
        // audit_events.operator_id FK 需要真实 operators 行（bootstrap local-admin）。
        String requestedOperatorId = (actorId == null || actorId.isBlank()) ? "local-admin" : actorId;
        String operatorId = requestedOperatorId;
        if (!"local-admin".equals(requestedOperatorId)
                && host.store.operators().stream().noneMatch(op -> requestedOperatorId.equals(op.operatorId()))) {
            operatorId = "local-admin";
        }
        StaticFactSnapshot prior = host.store.staticFacts(scanId)
                .orElseThrow(() -> new ControlPlaneStore.MissingRecordException("static facts missing"));
        host.store.saveStaticFacts(scanId, prior.withRuntimeLoadedClasses(loadedClassNames), operatorId);
    }

    /**
     * P1-03 薄合并：provider 独有的 entry/effect/guard 贡献在
     * PreAnalysis 尚未表示时写入 scan DTO（保留兼容）。
     */
    public void streamEvents(HttpExchange exchange, String scanId) throws IOException {
        host.store.requireScan(scanId);
        host.sseHub.open(exchange, scanId, exchange.getRequestHeaders().getFirst("Last-Event-ID"));
    }
    public void listPaths(HttpExchange exchange, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        List<Object> paths = new ArrayList<>();
        for (ApiDtos.PathDto path : scan.dto().paths()) paths.add(pathMap(path));
        for (ApiDtos.PathDto path : dynamicPaths(scan)) paths.add(pathMap(path));
        ControlPlaneHttpSupport.sendJson(exchange, 200, envelope(scan, "paths", paths));
    }
    public void sendPath(HttpExchange exchange, String scanId, String pathId) throws IOException {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        for (ApiDtos.PathDto path : scan.dto().paths()) {
            if (path.pathId().equals(pathId)) { ControlPlaneHttpSupport.sendJson(exchange, 200, pathMap(path)); return; }
        }
        for (ApiDtos.PathDto path : dynamicPaths(scan)) {
            if (path.pathId().equals(pathId)) { ControlPlaneHttpSupport.sendJson(exchange, 200, pathMap(path)); return; }
        }
        throw new ControlPlaneHttpSupport.ApiException(404, "PATH_NOT_FOUND", "path not found");
    }
    public void listScanEvidence(HttpExchange exchange, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        List<Object> items = new ArrayList<>();
        for (ApiDtos.EvidenceDto item : scan.evidence().values()) items.add(evidenceMap(item));
        for (ApiDtos.EvidenceDto item : dynamicEvidence(scan)) items.add(evidenceMap(item));
        ControlPlaneHttpSupport.sendJson(exchange, 200, envelope(scan, "evidence", items));
    }
    public void listScanFindings(HttpExchange exchange, String scanId) throws IOException {
        List<Map<String, Object>> views = host.findingQueryPort.findingsForScan(scanId)
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found"));
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        List<Object> items = new ArrayList<>(views);
        ControlPlaneHttpSupport.sendJson(exchange, 200, envelope(scan, "findings", items));
    }
    public void sendFinding(HttpExchange exchange, String findingId) throws IOException {
        Map<String, Object> view = host.findingQueryPort.findingView(findingId)
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "FINDING_NOT_FOUND", "finding not found"));
        ControlPlaneHttpSupport.sendJson(exchange, 200, view);
    }
    public void sendEvidence(HttpExchange exchange, String evidenceId) throws IOException {
        ApiDtos.EvidenceDto item = host.store.evidence(evidenceId);
        if (item == null) item = host.traceProjectionService.evidence(evidenceId);
        if (item == null) throw new ControlPlaneHttpSupport.ApiException(404, "EVIDENCE_NOT_FOUND", "evidence not found");
        ControlPlaneHttpSupport.sendJson(exchange, 200, evidenceMap(item));
    }
    public void listEvidence(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(projectId);
        String scanId = ControlPlaneHttpSupport.query(exchange.getRequestURI(), "scanId");
        ControlPlaneStore.ScanRecord scan = scanId == null ? latestScan(project) : host.store.scan(scanId);
        if (scan == null || !projectId.equals(scan.dto().projectId())) {
            Map<String, Object> result = envelope(projectId, List.of());
            result.put("evidence", List.of());
            result.put("verificationStatus", "UNREACHED");
            result.put("artifactDigest", "unscanned");
            result.put("scanId", "unscanned");
            ControlPlaneHttpSupport.sendJson(exchange, 200, result);
            return;
        }
        List<Object> items = new ArrayList<>();
        for (ApiDtos.EvidenceDto item : scan.evidence().values()) items.add(evidenceMap(item));
        for (ApiDtos.EvidenceDto item : dynamicEvidence(scan)) items.add(evidenceMap(item));
        ControlPlaneHttpSupport.sendJson(exchange, 200, envelope(scan, "evidence", items));
    }
    public void listChains(HttpExchange exchange) throws IOException {
        String projectId = ControlPlaneHttpSupport.query(exchange.getRequestURI(), "projectId");
        List<Object> items = new ArrayList<>();
        for (ApiDtos.AttackChainDto chain : host.store.attackChains(projectId)) items.add(chainMap(chain));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        body.put("projectId", projectId == null ? "all" : projectId);
        body.put("attackChains", items);
        body.put("dependencyMode", ApiDtos.MOCK);
        body.put("verificationStatus", ApiDtos.STATIC_INFERRED);
        body.put("evidenceRefs", List.of());
        if (!items.isEmpty() && items.get(0) instanceof Map<?, ?> first) {
            body.put("artifactDigest", first.get("artifactDigest"));
            body.put("scanId", first.get("scanId"));
        } else {
            body.put("artifactDigest", "unscoped");
            body.put("scanId", "unscoped");
        }
        ControlPlaneHttpSupport.sendJson(exchange, 200, body);
    }
    Map<String, Object> enrichedFindingMap(ApiDtos.FindingDto dto) {
        Map<String, Object> base = findingMap(dto);
        if (dto == null || dto.scanId() == null || dto.scanId().isBlank()) {
            return base;
        }
        ControlPlaneStore.ScanRecord scan = host.store.scan(dto.scanId());
        if (scan == null) {
            return base;
        }
        List<ApiDtos.PathRunDto> pathRuns = host.store.loadPathRunsForScan(
                scan.dto().projectId(), scan.dto().artifactDigest(), scan.dto().scanId());
        Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> traces = pathTracesByPathRunId(
                scan.dto().projectId(), scan.dto().artifactDigest(), scan.dto().scanId());
        FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                dto, scan.dto().entries(), pathRuns, traces, ControlPlaneHandlerSupport::sinkCategoryLabel);
        return FindingRuntimeEnricher.applyToWire(base, enrichment);
    }
    static Map<String, Object> sqlExperimentCardMap(SqlExperimentCard card) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("cardId", card.cardId());
        result.put("scanId", card.scanId());
        result.put("entrypointRef", card.entrypointRef());
        result.put("track", card.track().name());
        if (card.experimentPlanId() != null && !card.experimentPlanId().isBlank()) {
            result.put("experimentPlanId", card.experimentPlanId());
        }
        result.put("benignInput", card.benignInput());
        result.put("metaInput", card.metaInput());
        result.put("sqlBefore", card.sqlBefore());
        result.put("sqlAfter", card.sqlAfter());
        result.put("structureInfluenced", card.structureInfluenced());
        result.put("stopCondition", card.stopCondition());
        result.put("dependencyMode", card.dependencyMode());
        result.put("verificationStatus", card.verificationStatus());
        result.put("pathRunRefs", card.pathRunRefs());
        result.put("evidenceRefs", card.evidenceRefs());
        result.put("replayable", true);
        return result;
    }
    static Map<String, Object> experimentPlanMap(ExperimentPlan plan) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("planId", plan.planId());
        result.put("entrypointRef", plan.entrypointRef());
        result.put("track", plan.track().name());
        result.put("method", plan.method());
        result.put("contentType", plan.contentType());
        result.put("requiredParameters", plan.requiredParameters());
        result.put("authRequired", plan.authRequired());
        result.put("successHttpHint", plan.successHttpHint());
        result.put("successJsonPath", plan.successJsonPath());
        result.put("maxAttempts", plan.maxAttempts());
        result.put("candidateInputs", plan.candidateInputs());
        result.put("stopCondition", plan.stopCondition());
        if (plan.packId() != null && !plan.packId().isBlank()) {
            result.put("packId", plan.packId());
        }
        if (plan.fuzzStrategyJson() != null && !plan.fuzzStrategyJson().isBlank()) {
            result.put("fuzzStrategyJson", plan.fuzzStrategyJson());
        }
        result.put("boundForExecution", true);
        result.put("serverGated", true);
        return result;
    }
}

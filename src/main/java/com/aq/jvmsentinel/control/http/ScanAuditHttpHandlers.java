package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.detector.DetectorContext;
import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.experiment.PathDebugWireHelper;
import com.aq.jvmsentinel.analysis.hypothesis.FindingRuntimeEnricher;
import com.aq.jvmsentinel.analysis.pack.AnalysisPack;
import com.aq.jvmsentinel.analysis.pack.AnalysisPackRegistry;
import com.aq.jvmsentinel.analysis.ir.EvidenceGraphProjector;
import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderRegistry;
import com.aq.jvmsentinel.analysis.universe.ArtifactUniverseBuilder;
import com.aq.jvmsentinel.artifact.ArtifactValidationException;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.event.EventFactory;
import com.aq.jvmsentinel.event.IdempotencyKey;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.DependencyAccess;
import com.aq.jvmsentinel.model.Entrypoint;
import com.aq.jvmsentinel.model.Evidence;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.SqlExperimentCard;
import com.aq.jvmsentinel.security.auth.Permission;
import com.aq.jvmsentinel.worker.ExperimentShapeView;
import com.aq.jvmsentinel.worker.SqlExperimentCardBuilder;
import com.aq.jvmsentinel.model.Sink;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.policy.DangerousActionMode;
import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.policy.PolicyValidator;
import com.aq.jvmsentinel.policy.ScanPolicy;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
import com.aq.jvmsentinel.worker.ProbeBudgetExplainer;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** 从 ControlPlaneRouteHandlers 拆出的 HTTP 处理器：ScanAudit 域。 */
final class ScanAuditHttpHandlers extends ControlPlaneHandlerSupport {
private final OperatorProviderHttpHandlers operators;
private final AiJobHttpHandlers aiJobs;
private final SandboxProbeHttpHandlers sandboxProbe;
private final PathFindingsHttpHandlers pathFindings;
private final ScanBuildHttpHandlers scanBuild;

    ScanAuditHttpHandlers(ControlPlaneHandlerHost host, OperatorProviderHttpHandlers operators, AiJobHttpHandlers aiJobs, SandboxProbeHttpHandlers sandboxProbe, PathFindingsHttpHandlers pathFindings, ScanBuildHttpHandlers scanBuild) {
        super(host);
        this.operators = operators;
        this.aiJobs = aiJobs;
        this.sandboxProbe = sandboxProbe;
        this.pathFindings = pathFindings;
        this.scanBuild = scanBuild;
    }

    public void listScans(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(projectId);
        List<ControlPlaneStore.ScanRecord> records = host.store.scansForProject(projectId);
        List<Object> scans = new ArrayList<>(records.size());
        for (ControlPlaneStore.ScanRecord record : records) {
            scans.add(scanMap(record.dto()));
        }
        Map<String, Object> result = envelope(projectId, scans);
        result.put("scans", scans);
        String latest = project.latestScanId();
        ControlPlaneStore.ScanRecord latestRecord = latest == null ? null : host.store.scan(latest);
        result.put("artifactDigest", latestRecord == null ? "unscanned" : latestRecord.dto().artifactDigest());
        result.put("scanId", latestRecord == null ? "unscanned" : latestRecord.dto().scanId());
        result.put("latestScanId", latestRecord == null ? "unscanned" : latestRecord.dto().scanId());
        ControlPlaneHttpSupport.sendJson(exchange, 200, result);
    }
    public void deleteScan(HttpExchange exchange, String projectId, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord existing = host.store.requireScan(scanId);
        String scopedProjectId = projectId == null ? existing.dto().projectId() : projectId;
        if (projectId != null) {
            host.store.requireProject(projectId);
        }
        if (!scopedProjectId.equals(existing.dto().projectId())) {
            throw new ControlPlaneStore.MissingRecordException("scan not found");
        }
        // 审计历史删除：取消该 scan 在途工作，然后硬删除。
        // 卡住的 QUEUED dynamic task（如 restore 跳过 / 无 Worker）不得永久 409。
        String operatorId = operators.actor(exchange).operatorId();
        String now = Instant.now(host.clock).toString();
        invalidateArmedPipelineForRetry(scanId, operatorId);
        if ("SQLITE".equals(host.store.persistenceMode())) {
            for (var job : List.copyOf(host.store.aiJobs(scopedProjectId))) {
                if (!scanId.equals(job.scanId())) continue;
                if (!"QUEUED".equals(job.status()) && !"RUNNING".equals(job.status())) continue;
                var cancelled = host.store.cancelAiJob(job.aiJobId(), operatorId, now);
                host.aiJobOrchestrator.cancel(job.aiJobId());
                host.auditPipeline.onAiJobFinished(cancelled);
            }
        }
        host.workerApi.cancelActiveDynamicTasks(scopedProjectId, scanId);
        if ("SQLITE".equals(host.store.persistenceMode())) {
            for (var job : host.store.aiJobs(scopedProjectId)) {
                if (scanId.equals(job.scanId())
                        && ("QUEUED".equals(job.status()) || "RUNNING".equals(job.status()))) {
                    throw new ControlPlaneHttpSupport.ApiException(409, "SCAN_ACTIVE",
                            "active AI jobs could not be cancelled before deleting this scan");
                }
            }
        }
        if (host.workerApi.hasActiveDynamicTask(scopedProjectId, scanId)) {
            throw new ControlPlaneHttpSupport.ApiException(409, "SCAN_ACTIVE",
                    "active dynamic tasks could not be cancelled before deleting this scan");
        }
        releaseRetainedSandboxForScan(scanId);
        try {
            host.store.deleteScan(scanId, scopedProjectId, operatorId, now);
        } catch (IllegalStateException active) {
            throw new ControlPlaneHttpSupport.ApiException(409, "SCAN_ACTIVE", active.getMessage());
        }
        host.workerApi.forgetScanHistory(scopedProjectId, scanId);
        host.unreachedDynamicPaths.remove(scanId);
        ControlPlaneHttpSupport.sendEmpty(exchange, 204);
    }
    public synchronized void startAudit(HttpExchange exchange, String projectId) throws IOException {
        String key = ControlPlaneHttpSupport.requireIdempotencyKey(exchange);
        String replayKey = projectId + ":" + key;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.idempotentAuditRuns, replayKey);
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        Set<String> allowed = Set.of(
                "artifactDigest", "artifactId", "artifact", "authorized", "aiAuthorized", "dependencyMode",
                "outputLanguage",
                "networkMode", "dangerousActionMode", "networkAllowlist",
                "maxWallClockSeconds", "maxMemoryBytes", "maxDiskBytes");
        for (String field : body.keySet()) {
            if (!allowed.contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "AUDIT_RUN_FIELD_REJECTED",
                        "audit run body contains an unsupported field");
            }
        }
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit scan authorization is required");
        }
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "aiAuthorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AI_AUTHORIZATION_REQUIRED",
                    "explicit PRE_ANALYSIS authorization is required");
        }
        String payload = JsonCodec.stringify(body);
        String durableScope = "audit-run:create:" + projectId;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency, ControlPlaneHttpSupport.idempotencyMapKey(durableScope, key));
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, payload);
        ControlPlaneHandlerRecords.AuditRunReplay replay = host.idempotentAuditRuns.get(replayKey);
        if (replay == null && durable != null && durable.resultJson() != null) {
            Map<String, Object> stored = JsonCodec.parseObject(durable.resultJson());
            replay = new ControlPlaneHandlerRecords.AuditRunReplay(payload, ControlPlaneHttpSupport.textValue(stored, "scanId"),
                    ControlPlaneHttpSupport.textValue(stored, "preAnalysisJobId"));
            host.idempotentAuditRuns.putIfAbsent(replayKey, replay);
        }
        if (replay != null) {
            if (!replay.payload().equals(payload)) {
                throw new ControlPlaneHttpSupport.ApiException(409, "IDEMPOTENCY_CONFLICT",
                        "Idempotency-Key was already used with a different audit request");
            }
            ControlPlaneStore.ScanRecord scan = host.store.requireScan(replay.scanId());
            var job = host.store.requireAiJob(replay.preAnalysisJobId());
            ControlPlaneHttpSupport.sendJson(exchange, 200, auditRunMap(scan.dto(), job));
            return;
        }

        String operatorId = operators.actor(exchange).operatorId();
        AiOutputLanguage outputLanguage = aiJobs.outputLanguage(ControlPlaneHttpSupport.optionalText(
                body, "outputLanguage", AiOutputLanguage.ZH_CN.name()));
        Map<String, Object> scanBody = new LinkedHashMap<>(body);
        scanBody.remove("aiAuthorized");
        scanBody.remove("outputLanguage");
        ControlPlaneHandlerRecords.ScanStart started = scanBuild.createOrReplayScan(projectId, scanBody, "audit-run-" + key, operatorId);
        var job = host.store.createAiJob(projectId, AgentRole.PRE_ANALYSIS,
                started.scan().dto().scanId(), outputLanguage, true, operatorId,
                Instant.now(host.clock).toString());
        host.auditPipeline.armForJob(started.scan().dto().scanId(), projectId, operatorId, outputLanguage,
                AuditPipelineCoordinator.PipelineStage.PRE_ANALYSIS, job.aiJobId());
        if ("BLOCKED".equals(job.status()) || "FAILED".equals(job.status())
                || "CANCELLED".equals(job.status())) {
            host.auditPipeline.onAiJobFinished(job);
        } else {
            host.aiJobOrchestrator.submit(job, operatorId);
        }
        host.idempotentAuditRuns.put(replayKey,
                new ControlPlaneHandlerRecords.AuditRunReplay(payload, started.scan().dto().scanId(), job.aiJobId()));
        rememberDurableIdempotency(durableScope, key, payload, started.scan().dto().scanId(),
                JsonCodec.stringify(Map.of("scanId", started.scan().dto().scanId(),
                        "preAnalysisJobId", job.aiJobId())));
        ControlPlaneHttpSupport.sendJson(exchange, 202, auditRunMap(started.scan().dto(), job));
    }

    /**
     * 重新 arm scan 流水线并重入队一个失败阶段。创建新的已授权
     * AI job / dynamic task；永不将失败记录变异为成功。
     */
    public synchronized void retryAuditStage(HttpExchange exchange, String projectId) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        for (String field : body.keySet()) {
            if (!Set.of("scanId", "stage", "authorized", "aiAuthorized", "outputLanguage").contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "RETRY_FIELD_REJECTED",
                        "audit stage retry body contains an unsupported field");
            }
        }
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit authorization is required to retry an audit stage");
        }
        String scanId = ControlPlaneHttpSupport.optionalText(body, "scanId", null);
        String stageRaw = ControlPlaneHttpSupport.optionalText(body, "stage", null);
        if (scanId == null || scanId.isBlank() || stageRaw == null || stageRaw.isBlank()) {
            throw new ControlPlaneHttpSupport.ApiException(400, "RETRY_FIELD_REQUIRED", "scanId and stage are required");
        }
        String stage = stageRaw.toUpperCase(Locale.ROOT);
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        if (!scan.dto().projectId().equals(projectId)) {
            throw new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found for project");
        }
        String key = ControlPlaneHttpSupport.requireIdempotencyKey(exchange);
        String payload = JsonCodec.stringify(body);
        String durableScope = "audit-stage-retry:" + projectId + ":" + scanId + ":" + stage;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency, ControlPlaneHttpSupport.idempotencyMapKey(durableScope, key));
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, payload);
        if (durable != null && durable.resultJson() != null) {
            ControlPlaneHttpSupport.sendJson(exchange, 202, JsonCodec.parseObject(durable.resultJson()));
            return;
        }
        requireRetryPrerequisite(projectId, scanId, stage);
        invalidateArmedPipelineForRetry(scanId, operators.actor(exchange).operatorId());
        String operatorId = operators.actor(exchange).operatorId();
        AiOutputLanguage language = aiJobs.outputLanguage(ControlPlaneHttpSupport.optionalText(
                body, "outputLanguage", AiOutputLanguage.ZH_CN.name()));
        boolean aiAuthorized = Set.of("DYNAMIC_OBSERVATION", "TRUSTED_DOCKER", "DYNAMIC").contains(stage)
                || ControlPlaneHttpSupport.requiredBoolean(body, "aiAuthorized");
        Map<String, Object> result = enqueueAuditStage(projectId, scanId, stage, operatorId,
                language, aiAuthorized);
        rememberDurableIdempotency(durableScope, key, payload, scanId, JsonCodec.stringify(result));
        ControlPlaneHttpSupport.sendJson(exchange, 202, result);
    }

    /**
     * 操作员流水线控制：pause / resume / cancel 某 scan 上已 arm 的 audit run。
     * Pause 持久化 {@code OPERATOR_PAUSED} 且不虚构 verification status；resume
     * 从 paused 阶段重新 arm（与 stage retry 相同入队路径）。
     */
    public synchronized void updateScan(HttpExchange exchange, String scanId) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        for (String field : body.keySet()) {
            if (!Set.of("action", "authorized", "aiAuthorized", "outputLanguage").contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "SCAN_CONTROL_FIELD_REJECTED",
                        "scan control body contains an unsupported field");
            }
        }
        String action = ControlPlaneHttpSupport.optionalText(body, "action", null);
        if (action == null || action.isBlank()) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_ACTION", "action must be pause, resume, or cancel");
        }
        action = action.toLowerCase(Locale.ROOT);
        if (!Set.of("pause", "resume", "cancel").contains(action)) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_ACTION", "action must be pause, resume, or cancel");
        }
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit authorization is required to control an audit pipeline");
        }
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        String projectId = scan.dto().projectId();
        String operatorId = operators.actor(exchange).operatorId();
        String now = Instant.now(host.clock).toString();
        switch (action) {
            case "pause" -> pauseAuditPipeline(projectId, scanId, operatorId, now);
            case "cancel" -> cancelAuditPipeline(projectId, scanId, operatorId, now);
            case "resume" -> {
                operators.requirePermission(exchange, Permission.RUN_AI_JOBS);
                if (!ControlPlaneHttpSupport.requiredBoolean(body, "aiAuthorized")) {
                    throw new ControlPlaneHttpSupport.ApiException(403, "AI_AUTHORIZATION_REQUIRED",
                            "explicit AI authorization is required to resume an audit pipeline");
                }
                AiOutputLanguage language = aiJobs.outputLanguage(ControlPlaneHttpSupport.optionalText(
                        body, "outputLanguage", AiOutputLanguage.ZH_CN.name()));
                resumeAuditPipeline(projectId, scanId, operatorId, language, now);
            }
            default -> throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_ACTION", "action must be pause, resume, or cancel");
        }
        Map<String, Object> response = host.scanQueryPort.scanView(scanId)
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(500, "SCAN_PROJECTION_FAILED",
                        "scan projection missing after pipeline control"));
        ControlPlaneHttpSupport.sendJson(exchange, 200, response);
    }
    public synchronized void createScan(HttpExchange exchange, String projectId) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        ControlPlaneHandlerRecords.ScanStart started = scanBuild.createOrReplayScan(projectId, body, ControlPlaneHttpSupport.requestIdempotencyKey(exchange),
                operators.actor(exchange).operatorId());
        String scanId = started.scan().dto().scanId();
        // Create 响应经 ScanQueryPort 投影（hypotheses + coverage），非临时 store 读取。
        Map<String, Object> response = host.scanQueryPort.scanView(scanId)
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(500, "SCAN_PROJECTION_FAILED",
                        "scan projection missing after create"));
        ControlPlaneHttpSupport.sendJson(exchange, started.replayed() ? 200 : 202, response);
    }
    public void sendScan(HttpExchange exchange, String scanId) throws IOException {
        Map<String, Object> body = host.scanQueryPort.scanView(scanId)
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found"));
        ControlPlaneHttpSupport.sendJson(exchange, 200, body);
    }
    public void dashboard(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(projectId);
        String requestedScanId = ControlPlaneHttpSupport.query(exchange.getRequestURI(), "scanId");
        ControlPlaneStore.ScanRecord scan = requestedScanId == null || requestedScanId.isBlank()
                ? latestScan(project)
                : host.store.scan(requestedScanId);
        if (scan != null && !scan.dto().projectId().equals(projectId)) {
            throw new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found for project");
        }
        if (scan == null && requestedScanId != null && !requestedScanId.isBlank()) {
            throw new ControlPlaneHttpSupport.ApiException(404, "SCAN_NOT_FOUND", "scan not found for project");
        }
        if (scan == null) {
            ControlPlaneHttpSupport.sendJson(exchange, 200,
                    com.aq.jvmsentinel.control.service.DashboardService.emptyProjectDashboard(projectId));
            return;
        }
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathDto> dynamicPaths = pathFindings.dynamicPaths(scan);
        List<ApiDtos.PathRunDto> pathRuns = pathFindings.mergedPathRunsForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId());
        List<ApiDtos.PathStepDto> flattened = !dynamicPaths.isEmpty()
                ? dynamicPaths.get(dynamicPaths.size() - 1).steps()
                : dto.paths().isEmpty() ? List.of() : dto.paths().get(0).steps();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        body.put("projectId", dto.projectId());
        body.put("artifactDigest", dto.artifactDigest());
        body.put("scanId", dto.scanId());
        boolean confirmed = pathRuns.stream()
                .anyMatch(run -> ApiDtos.DYNAMIC_CONFIRMED.equals(run.verificationStatus()));
        boolean suspected = pathRuns.stream()
                .anyMatch(run -> ApiDtos.DYNAMIC_SUSPECTED.equals(run.verificationStatus()));
        // P0-20：不得仅因存在 dynamic paths/tasks 就提升 scan 状态。
        body.put("verificationStatus", confirmed ? ApiDtos.DYNAMIC_CONFIRMED
                : suspected ? ApiDtos.DYNAMIC_SUSPECTED : dto.verificationStatus());
        long dynamicFailedPathRuns = pathRuns.stream()
                .filter(run -> ApiDtos.UNREACHED.equals(run.verificationStatus())
                        || run.httpStatus() < 0
                        || "UNKNOWN".equalsIgnoreCase(run.outcomeClass()))
                .count();
        body.put("dynamicSupportedPathRuns", pathRuns.stream()
                .filter(run -> ApiDtos.DYNAMIC_CONFIRMED.equals(run.verificationStatus())
                        || ApiDtos.DYNAMIC_SUSPECTED.equals(run.verificationStatus()))
                .count());
        body.put("dynamicFailedPathRuns", dynamicFailedPathRuns);
        body.put("dependencyMode", dto.dependencyMode());
        List<String> dashboardEvidence = new ArrayList<>(dto.evidenceRefs());
        for (ApiDtos.PathDto pathDto : dynamicPaths) dashboardEvidence.addAll(pathDto.evidenceRefs());
        body.put("evidenceRefs", List.copyOf(dashboardEvidence));
        List<Object> entries = new ArrayList<>();
        for (ApiDtos.EntryDto entry : dto.entries()) entries.add(entryMap(entry));
        List<ApiDtos.FindingDto> primaryFindings = new ArrayList<>();
        int authGapFindingCount = 0;
        for (ApiDtos.FindingDto finding : dto.findings()) {
            if (pathFindings.isAuthGapFinding(finding)) {
                authGapFindingCount++;
                continue;
            }
            primaryFindings.add(finding);
        }
        Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> findingTraceIndex =
                pathFindings.pathTracesByPathRunId(dto.projectId(), dto.artifactDigest(), dto.scanId());
        List<Object> findings = new ArrayList<>();
        for (ApiDtos.FindingDto finding : com.aq.jvmsentinel.analysis.FindingRanker.rank(primaryFindings)) {
            FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                    finding, dto.entries(), pathRuns, findingTraceIndex,
                    ControlPlaneHandlerSupport::sinkCategoryLabel);
            findings.add(FindingRuntimeEnricher.applyToWire(findingMap(finding), enrichment));
        }
        int authGapSinkCount = 0;
        for (ApiDtos.SinkDto sink : dto.sinks()) {
            if (sink.category() != null && "AUTH_GAP".equalsIgnoreCase(sink.category())) {
                authGapSinkCount++;
            }
        }
        List<Object> paths = new ArrayList<>();
        for (ApiDtos.PathDto path : dto.paths()) paths.add(pathMap(path));
        for (ApiDtos.PathDto dynamic : dynamicPaths) paths.add(pathMap(dynamic));
        // PathRun 线格式映射经 PathRunQueryPort（P1-08）；DTO 仍驱动 cards/gates。
        List<Object> pathRunMaps = new ArrayList<>(host.pathRunQueryPort.pathRunsForScan(dto.scanId())
                .orElse(List.of()));
        List<Object> path = new ArrayList<>();
        for (ApiDtos.PathStepDto step : flattened) path.add(pathStepMap(step));
        List<SqlExperimentCard> cards = SqlExperimentCardBuilder.fromPathRuns(dto.scanId(), pathRuns);
        List<Object> cardMaps = new ArrayList<>();
        for (SqlExperimentCard card : cards) cardMaps.add(pathFindings.sqlExperimentCardMap(card));
        List<Object> planMaps = new ArrayList<>();
        for (ExperimentPlan plan : host.scanExperimentPlans.getOrDefault(dto.scanId(), List.of())) {
            planMaps.add(pathFindings.experimentPlanMap(plan));
        }
        List<String> routes = dto.entries().stream()
                .map(ApiDtos.EntryDto::route)
                .filter(Objects::nonNull)
                .toList();
        Path artifactPath = null;
        try {
            ArtifactDescriptor artifact = host.store.artifact(project, dto.artifactDigest());
            if (artifact != null) artifactPath = artifact.normalizedPath();
        } catch (RuntimeException ignored) {
            // 无 path 时 pack 匹配仍使用 route 启发式。
        }
        List<Object> packMaps = new ArrayList<>();
        for (AnalysisPack pack : AnalysisPackRegistry.matching(artifactPath, routes)) {
            Map<String, Object> packRow = new LinkedHashMap<>();
            packRow.put("packId", pack.id());
            packRow.put("destructive", false);
            packRow.put("jwtSecretHint", pack.suggestJwtSecret(artifactPath).orElse(""));
            List<Object> templates = new ArrayList<>();
            for (ExperimentPlan template : pack.experimentTemplates(
                    "entry:pack-template", IdentityTrack.UNAUTH)) {
                templates.add(pathFindings.experimentPlanMap(template));
            }
            packRow.put("templates", templates);
            packMaps.add(packRow);
        }
        ProbeBudgetExplainer.TrackBudgetSummary budget = ProbeBudgetExplainer.explain(
                dto.entries(),
                ProbePlanService.MAX_DYNAMIC_PROBES,
                host.scanExpandedProbes.getOrDefault(dto.scanId(), List.of()),
                host.unreachedDynamicPaths.getOrDefault(dto.scanId(), List.of()));
        Map<String, Object> budgetMap = new LinkedHashMap<>();
        budgetMap.put("maxProbes", budget.maxProbes());
        budgetMap.put("plannedProbes", budget.plannedProbes());
        budgetMap.put("unreachedEntries", budget.unreachedEntries());
        budgetMap.put("strategy", budget.strategy());
        budgetMap.put("entryTrackPlans", budget.entryTrackPlans());
        body.put("entries", entries);
        body.put("findings", findings);
        // authGapFindingCount = GuardCoverage / AUTH_GAP finding 行，从主 findings[] 降级。
        // authGapSinkCount = AUTH_GAP sink 信号（legacy wire）；hypotheses[] 对 GUARD_COVERAGE 具权威性。
        body.put("authGapFindingCount", authGapFindingCount);
        body.put("authGapSinkCount", authGapSinkCount);
        body.put("hypotheses", hypothesisMaps(host.store.hypotheses(dto.scanId())));
        body.put("paths", paths);
        body.put("pathRuns", pathRunMaps);
        List<Object> pathDebugSummaries = new ArrayList<>();
        Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> traceIndex = findingTraceIndex;
        for (ApiDtos.EntryDto entry : dto.entries()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("entryId", entry.id());
            row.put("route", entry.route());
            List<Map<String, Object>> tracks = new ArrayList<>();
            for (ApiDtos.PathRunDto run : pathRuns) {
                if (!EntryRefResolver.refsEquivalent(dto.entries(), EntryRefResolver.canonicalRef(entry),
                        run.entrypointRef())
                        && !EntryRefResolver.refsEquivalent(dto.entries(),
                        EntryRefResolver.methodRouteRef(entry), run.entrypointRef())) {
                    continue;
                }
                com.aq.jvmsentinel.domain.pathdebug.PathTrace trace = traceIndex.get(run.pathRunId());
                Map<String, Object> trackRow = new LinkedHashMap<>(PathDebugWireHelper.pathDebugSummary(trace));
                trackRow.put("track", run.track());
                trackRow.put("httpStatus", run.httpStatus());
                trackRow.put("verificationStatus", run.verificationStatus());
                tracks.add(trackRow);
            }
            if (tracks.isEmpty()) {
                tracks.add(PathDebugWireHelper.pathDebugSummary(null));
            }
            row.put("tracks", tracks);
            pathDebugSummaries.add(row);
        }
        body.put("pathDebugSummaries", pathDebugSummaries);
        body.put("path", path);
        List<Object> shapeMaps = new ArrayList<>();
        for (ExperimentShapeView.Shape shape : ExperimentShapeView.fromPathRuns(pathRuns)) {
            shapeMaps.add(ExperimentShapeView.toMap(shape));
        }
        body.put("sqlExperimentCards", cardMaps);
        body.put("experimentPlans", planMaps);
        body.put("experimentShapes", shapeMaps);
        body.put("analysisPacks", packMaps);
        body.put("probeBudget", budgetMap);
        ContrastLedger.Ledger ledger = ContrastLedger.build(
                dto.entries(), dto.sinks(), scan.evidence(), pathRuns,
                StaticFactSnapshot.resolveTaintPaths(host.store.staticFacts(scan.dto().scanId()), dto.sinks()));
        body.put("rankedSinks", com.aq.jvmsentinel.control.service.DashboardService.rankedSinkMaps(
                dto.sinks(),
                StaticFactSnapshot.resolveTaintPaths(host.store.staticFacts(scan.dto().scanId()), dto.sinks()),
                dto.entries(), ledger.rows()));
        body.put("contrastSnapshotId", ledger.snapshotId());
        body.put("contrastRoundIndex", ledger.roundIndex());
        List<ApiDtos.PathRunDto> priorRuns = pathRuns.stream()
                .map(run -> new ApiDtos.PathRunDto(
                        run.schemaVersion(), run.pathRunId(), run.scanId(), run.entrypointRef(),
                        run.track(), run.attemptId(), run.experimentPlanId(), run.method(),
                        run.contentType(), run.requestSummary(), run.outcomeClass(),
                        run.httpStatus(), run.entryHit(), run.parameterBound(),
                        run.sqlEvents(), run.stopReason(), run.verificationStatus(),
                        run.evidenceRefs(), run.identityProvenance(), run.identityPrecondition(),
                        Map.of()))
                .toList();
        ContrastLedger.Ledger previous = ContrastLedger.build(
                dto.entries(), dto.sinks(), scan.evidence(), priorRuns,
                StaticFactSnapshot.resolveTaintPaths(host.store.staticFacts(scan.dto().scanId()), dto.sinks()));
        body.put("ledgerDiff",
                com.aq.jvmsentinel.control.service.DashboardService.ledgerDiffMap(previous, ledger));
        body.put("verifiedFindings", List.of());
        // PathRun 合格时应用动态 feedback evidence（进程内；非 VERIFIED）。
        try {
            var feedback = com.aq.jvmsentinel.analysis.DynamicFeedbackApplier.apply(
                    dto.projectId(), dto.artifactDigest(), dto.scanId(), pathRuns,
                    Instant.now(host.clock).toString());
            if (feedback.upgradedCount() > 0) {
                host.store.appendScanEvidence(dto.scanId(), feedback.evidence());
            }
        } catch (RuntimeException ignored) {
            // Feedback 尽力而为；dashboard 仍返回。
        }
        ControlPlaneHttpSupport.sendJson(exchange, 200, body);
    }
    void pauseAuditPipeline(String projectId, String scanId, String operatorId, String now) {
        AuditPipelineCoordinator.Cursor live = host.auditPipeline.cursor(scanId);
        if (live == null) {
            SQLiteControlPlanePersistence.PipelineRunData existing = pipelineRunForScan(scanId);
            if (existing != null
                    && AuditPipelineCoordinator.STOP_OPERATOR_PAUSED.equals(existing.stopReason())) {
                throw new ControlPlaneHttpSupport.ApiException(409, "PIPELINE_ALREADY_PAUSED",
                        "audit pipeline is already paused");
            }
            throw new ControlPlaneHttpSupport.ApiException(409, "PIPELINE_NOT_ARMED",
                    "no armed audit pipeline to pause for this scan");
        }
        String expectedJobId = live.expectedJobId();
        String expectedTaskId = live.expectedTaskId();
        AuditPipelineCoordinator.Cursor paused = host.auditPipeline.operatorPause(scanId);
        if (paused == null) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PIPELINE_NOT_ARMED",
                    "no armed audit pipeline to pause for this scan");
        }
        if (expectedJobId != null) {
            try {
                // Cursor 已移除 — onAiJobFinished 为 no-op；避免重复 disarm。
                host.store.cancelAiJob(expectedJobId, operatorId, now);
                host.aiJobOrchestrator.cancel(expectedJobId);
            } catch (ControlPlaneStore.MissingRecordException ignored) {
                // 预期 job 可能已终态。
            }
        }
        if (expectedTaskId != null) {
            host.workerApi.cancelActiveDynamicTasks(projectId, scanId);
        }
        host.store.auditChange(projectId, operatorId, "audit-pipeline.pause", "scan", scanId,
                "{\"reason\":\"OPERATOR_PAUSED\",\"pipelineRunId\":\""
                        + paused.arm().pipelineRunId()
                        + "\",\"stageAttemptId\":\"" + paused.stageAttemptId()
                        + "\",\"stage\":\"" + paused.stage().name() + "\"}",
                now);
    }
    void cancelAuditPipeline(String projectId, String scanId, String operatorId, String now) {
        AuditPipelineCoordinator.Cursor live = host.auditPipeline.cursor(scanId);
        String expectedJobId = live == null ? null : live.expectedJobId();
        if (live != null) {
            host.auditPipeline.operatorCancel(scanId);
        } else {
            SQLiteControlPlanePersistence.PipelineRunData existing = pipelineRunForScan(scanId);
            if (existing != null
                    && AuditPipelineCoordinator.STOP_OPERATOR_PAUSED.equals(existing.stopReason())) {
                host.store.persistPipelineRun(new SQLiteControlPlanePersistence.PipelineRunData(
                        existing.scanId(), existing.projectId(), existing.actorId(),
                        existing.outputLanguage(), false, existing.nextStage(), now,
                        existing.pipelineRunId(), existing.stageAttemptId(),
                        null, null, AuditPipelineCoordinator.STOP_OPERATOR_CANCELLED));
            }
        }
        if (expectedJobId != null) {
            try {
                host.store.cancelAiJob(expectedJobId, operatorId, now);
                host.aiJobOrchestrator.cancel(expectedJobId);
            } catch (ControlPlaneStore.MissingRecordException ignored) {
                // 已终态
            }
        }
        for (var job : List.copyOf(host.store.aiJobs(projectId))) {
            if (!scanId.equals(job.scanId())) continue;
            if (!"QUEUED".equals(job.status()) && !"RUNNING".equals(job.status())) continue;
            try {
                host.store.cancelAiJob(job.aiJobId(), operatorId, now);
                host.aiJobOrchestrator.cancel(job.aiJobId());
            } catch (ControlPlaneStore.MissingRecordException ignored) {
                // 与终态化竞态
            }
        }
        host.workerApi.cancelActiveDynamicTasks(projectId, scanId);
        host.store.auditChange(projectId, operatorId, "audit-pipeline.cancel", "scan", scanId,
                "{\"reason\":\"OPERATOR_CANCELLED\"}", now);
    }
    void resumeAuditPipeline(String projectId, String scanId, String operatorId,
                                     AiOutputLanguage language, String now) {
        if (host.auditPipeline.cursor(scanId) != null) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PIPELINE_ALREADY_ARMED",
                    "audit pipeline is already running; pause or cancel before resume");
        }
        SQLiteControlPlanePersistence.PipelineRunData paused = pipelineRunForScan(scanId);
        if (paused == null
                || !AuditPipelineCoordinator.STOP_OPERATOR_PAUSED.equals(paused.stopReason())) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PIPELINE_NOT_PAUSED",
                    "audit pipeline is not paused; nothing to resume");
        }
        String stage = paused.nextStage() == null ? "" : paused.nextStage().toUpperCase(Locale.ROOT);
        if (stage.isBlank() || "COMPLETE".equals(stage)) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PIPELINE_RESUME_STAGE_INVALID",
                    "paused pipeline stage cannot be resumed");
        }
        requireRetryPrerequisite(projectId, scanId, stage);
        Map<String, Object> enqueued = enqueueAuditStage(projectId, scanId, stage, operatorId,
                language, true);
        host.store.auditChange(projectId, operatorId, "audit-pipeline.resume", "scan", scanId,
                "{\"reason\":\"OPERATOR_RESUME\",\"stage\":\"" + stage
                        + "\",\"pipelineArmed\":" + enqueued.get("pipelineArmed") + "}",
                now);
    }

    /**
     * stage retry 与 pause-resume 共用的入队。创建新的已授权 job/task
     * 并 arm 流水线；永不将先前终态记录变异为成功。
     */
    Map<String, Object> enqueueAuditStage(String projectId, String scanId, String stage,
                                                  String operatorId, AiOutputLanguage language,
                                                  boolean aiAuthorized) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("projectId", projectId);
        result.put("scanId", scanId);
        result.put("stage", stage);
        switch (stage) {
            case "PRE_ANALYSIS", "AUTH_ANALYSIS", "AUTH_BYPASS_CONFIRM", "PATH_EXPLORATION",
                    "DYNAMIC_VERIFICATION", "VULNERABILITY_TRIAGE", "REPORT_GENERATION" -> {
                String pipelineStageName = stage;
                String roleName = "AUTH_BYPASS_CONFIRM".equals(stage) ? "AUTH_ANALYSIS" : stage;
                if (!aiAuthorized) {
                    throw new ControlPlaneHttpSupport.ApiException(403, "AI_AUTHORIZATION_REQUIRED",
                            "explicit AI authorization is required to retry a model stage");
                }
                AgentRole role = AgentRole.valueOf(roleName);
                var job = host.store.createAiJob(projectId, role, scanId, language, true, operatorId,
                        Instant.now(host.clock).toString());
                AuditPipelineCoordinator.PipelineStage pipelineStage =
                        AuditPipelineCoordinator.PipelineStage.valueOf(pipelineStageName);
                AuditPipelineCoordinator.Arm armed = host.auditPipeline.armForJob(
                        scanId, projectId, operatorId, language, pipelineStage, job.aiJobId());
                result.put("pipelineArmed", !"BLOCKED".equals(job.status())
                        && !"FAILED".equals(job.status())
                        && !"CANCELLED".equals(job.status()));
                if ("BLOCKED".equals(job.status()) || "FAILED".equals(job.status())
                        || "CANCELLED".equals(job.status())) {
                    host.auditPipeline.onAiJobFinished(job);
                } else {
                    host.aiJobOrchestrator.submit(job, operatorId);
                }
                host.store.auditChange(projectId, operatorId, "audit-stage.retry", "ai-job", job.aiJobId(),
                        "{\"stage\":\"" + pipelineStageName + "\",\"scanId\":\"" + scanId
                                + "\",\"pipelineRunId\":\"" + armed.pipelineRunId() + "\"}",
                        Instant.now(host.clock).toString());
                result.put("aiJob", aiJobs.aiJobMap(job));
            }
            case "DYNAMIC_OBSERVATION", "TRUSTED_DOCKER", "DYNAMIC" -> {
                List<TaskSnapshot> superseded = host.workerApi.cancelActiveDynamicTasks(projectId, scanId);
                if (host.workerApi.hasActiveDynamicTask(projectId, scanId)) {
                    throw new ControlPlaneHttpSupport.ApiException(409, "DYNAMIC_TASK_BUSY",
                            "a dynamic task is already active for this scan; stop it before retrying");
                }
                TaskSnapshot snapshot = sandboxProbe.enqueueDynamicForPipeline(scanId, operatorId);
                AuditPipelineCoordinator.Arm armed = host.auditPipeline.armForTask(
                        scanId, projectId, operatorId, language,
                        AuditPipelineCoordinator.PipelineStage.DYNAMIC_OBSERVATION,
                        snapshot.scope().taskId());
                result.put("pipelineArmed", true);
                host.store.auditChange(projectId, operatorId, "audit-stage.retry", "worker-task",
                        snapshot.scope().taskId(),
                        "{\"stage\":\"DYNAMIC_OBSERVATION\",\"scanId\":\"" + scanId
                                + "\",\"supersededCount\":" + superseded.size()
                                + "\",\"pipelineRunId\":\"" + armed.pipelineRunId() + "\"}",
                        Instant.now(host.clock).toString());
                result.put("dynamicTask", DynamicWorkerHttpHandlers.dynamicTaskMap(snapshot));
                result.put("supersededCount", superseded.size());
            }
            default -> throw new ControlPlaneHttpSupport.ApiException(400, "RETRY_STAGE_UNKNOWN",
                    "unsupported retry stage");
        }
        return result;
    }
    SQLiteControlPlanePersistence.PipelineRunData pipelineRunForScan(String scanId) {
        for (SQLiteControlPlanePersistence.PipelineRunData run : host.store.loadPipelineRuns()) {
            if (scanId.equals(run.scanId())) {
                return run;
            }
        }
        return null;
    }
    void invalidateArmedPipelineForRetry(String scanId, String operatorId) {
        AuditPipelineCoordinator.Cursor existing = host.auditPipeline.cursor(scanId);
        if (existing == null) {
            return;
        }
        if (existing.expectedJobId() != null) {
            var cancelled = host.store.cancelAiJob(existing.expectedJobId(), operatorId,
                    Instant.now(host.clock).toString());
            host.aiJobOrchestrator.cancel(existing.expectedJobId());
            host.auditPipeline.onAiJobFinished(cancelled);
        }
        if (existing.expectedTaskId() != null) {
            host.workerApi.cancelActiveDynamicTasks(existing.arm().projectId(), scanId);
        }
        host.store.auditChange(existing.arm().projectId(), operatorId, "audit-pipeline.invalidate", "scan",
                scanId, "{\"reason\":\"STAGE_RETRY\",\"pipelineRunId\":\""
                        + existing.arm().pipelineRunId()
                        + "\",\"stageAttemptId\":\"" + existing.stageAttemptId() + "\"}",
                Instant.now(host.clock).toString());
    }
    void requireRetryPrerequisite(String projectId, String scanId, String stage) {
        List<SQLiteControlPlanePersistence.AiJobData> jobs = host.store.aiJobs(projectId).stream()
                .filter(job -> scanId.equals(job.scanId()))
                .toList();
        List<TaskSnapshot> tasks = host.workerApi.snapshots(projectId, scanId);
        switch (stage) {
            case "PRE_ANALYSIS" -> { }
            case "AUTH_ANALYSIS" -> requireCompletedRole(jobs, AgentRole.PRE_ANALYSIS,
                    "AUTH_ANALYSIS retry requires a completed PRE_ANALYSIS job");
            case "DYNAMIC_OBSERVATION", "TRUSTED_DOCKER", "DYNAMIC" -> requireCompletedRole(jobs,
                    AgentRole.AUTH_ANALYSIS,
                    "DYNAMIC_OBSERVATION retry requires a completed AUTH_ANALYSIS job");
            case "AUTH_BYPASS_CONFIRM" -> {
                if (tasks.stream().noneMatch(task -> task.lifecycle() == TaskLifecycle.COMPLETED)) {
                    throw new ControlPlaneHttpSupport.ApiException(409, "RETRY_PREREQUISITE_MISSING",
                            "AUTH_BYPASS_CONFIRM retry requires a completed dynamic observation task");
                }
            }
            case "DYNAMIC_VERIFICATION" -> {
                if (tasks.stream().noneMatch(task -> task.lifecycle() == TaskLifecycle.COMPLETED)) {
                    throw new ControlPlaneHttpSupport.ApiException(409, "RETRY_PREREQUISITE_MISSING",
                            "DYNAMIC_VERIFICATION retry requires a completed dynamic observation task");
                }
                requireCompletedRole(jobs, AgentRole.AUTH_ANALYSIS,
                        "DYNAMIC_VERIFICATION retry requires a completed AUTH_ANALYSIS job");
            }
            case "PATH_EXPLORATION" -> requireCompletedRole(jobs, AgentRole.DYNAMIC_VERIFICATION,
                    "PATH_EXPLORATION retry requires a completed DYNAMIC_VERIFICATION job");
            case "VULNERABILITY_TRIAGE" -> requireCompletedRole(jobs, AgentRole.PATH_EXPLORATION,
                    "VULNERABILITY_TRIAGE retry requires a completed PATH_EXPLORATION job");
            case "REPORT_GENERATION" -> requireCompletedRole(jobs, AgentRole.VULNERABILITY_TRIAGE,
                    "REPORT_GENERATION retry requires a completed VULNERABILITY_TRIAGE job");
            default -> { }
        }
    }
    static void requireCompletedRole(List<SQLiteControlPlanePersistence.AiJobData> jobs,
                                             AgentRole role, String message) {
        boolean completed = jobs.stream()
                .anyMatch(job -> job.role() == role && "COMPLETED".equals(job.status()));
        if (!completed) {
            throw new ControlPlaneHttpSupport.ApiException(409, "RETRY_PREREQUISITE_MISSING", message);
        }
    }
    static Map<String, Object> auditRunMap(
            ApiDtos.ScanDto scan,
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData job) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("auditRunId", "audit-" + scan.scanId().substring("scan-".length()));
        result.put("projectId", scan.projectId());
        result.put("artifactDigest", scan.artifactDigest());
        result.put("scanId", scan.scanId());
        result.put("status", "COMPLETED".equals(job.status())
                ? "PRE_ANALYSIS_COMPLETED"
                : "BLOCKED".equals(job.status()) ? "PRE_ANALYSIS_BLOCKED" : "PRE_ANALYSIS_QUEUED");
        result.put("scan", scanMap(scan));
        result.put("preAnalysisJob", AiJobHttpHandlers.aiJobMap(job));
        return result;
    }
    Map<String, Object> scanViewForPort(String scanId) {
        Map<String, Object> body = scanMap(host.store.requireScan(scanId).dto());
        body.put("hypotheses", hypothesisMaps(host.hypothesisQueryPort.hypotheses(scanId)));
        host.coverageQueryPort.coverage(scanId).ifPresent(matrix -> body.put("coverage", matrix.toMap()));
        attachPipelineProjection(body, scanId);
        return body;
    }

    /** 操作员可见的流水线游标投影（armed / paused / stopped）。 */
    void attachPipelineProjection(Map<String, Object> body, String scanId) {
        AuditPipelineCoordinator.Cursor live = host.auditPipeline.cursor(scanId);
        if (live != null) {
            body.put("pipelineArmed", true);
            body.put("pipelineStage", live.stage().name());
            body.put("pipelineStopReason", null);
            body.put("pipelineStatus", "RUNNING");
            return;
        }
        SQLiteControlPlanePersistence.PipelineRunData run = pipelineRunForScan(scanId);
        if (run == null) {
            body.put("pipelineArmed", false);
            body.put("pipelineStage", null);
            body.put("pipelineStopReason", null);
            body.put("pipelineStatus", "NONE");
            return;
        }
        body.put("pipelineArmed", run.armed());
        body.put("pipelineStage", run.nextStage());
        body.put("pipelineStopReason", run.stopReason());
        if (run.armed()) {
            body.put("pipelineStatus", "RUNNING");
        } else if (AuditPipelineCoordinator.STOP_OPERATOR_PAUSED.equals(run.stopReason())) {
            body.put("pipelineStatus", "PAUSED");
        } else if (run.stopReason() != null && run.stopReason().contains("COMPLETE")) {
            body.put("pipelineStatus", "COMPLETE");
        } else if (run.stopReason() != null) {
            body.put("pipelineStatus", "STOPPED");
        } else {
            body.put("pipelineStatus", "IDLE");
        }
    }

    /** 供 {@link PathRunQueryPort} 使用的 PathRun 映射；MOCK 来源仍可见。 */
}

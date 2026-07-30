package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords;
import com.aq.jvmsentinel.control.persistence.PayloadSchemaGuard;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.worker.ExperimentPlanValidator;
import com.aq.jvmsentinel.model.SqlExperimentCard;
import com.aq.jvmsentinel.worker.SqlExperimentCardBuilder;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** 从 ControlPlaneRouteHandlers 拆出的 HTTP 处理器：DynamicWorker 域。 */
final class DynamicWorkerHttpHandlers extends ControlPlaneHandlerSupport {
private final OperatorProviderHttpHandlers operators;
private final PathFindingsHttpHandlers pathFindings;
private final SandboxProbeHttpHandlers sandboxProbe;

    DynamicWorkerHttpHandlers(ControlPlaneHandlerHost host, OperatorProviderHttpHandlers operators, PathFindingsHttpHandlers pathFindings, SandboxProbeHttpHandlers sandboxProbe) {
        super(host);
        this.operators = operators;
        this.pathFindings = pathFindings;
        this.sandboxProbe = sandboxProbe;
    }

    public synchronized void createDynamicTask(HttpExchange exchange, String scanId) throws IOException {
        String key = ControlPlaneHttpSupport.requireIdempotencyKey(exchange);
        String replayKey = scanId + ":" + key;
        if (!host.idempotentDynamicTasks.containsKey(replayKey)
                && host.idempotentDynamicTasks.size() >= ControlPlaneHttpLimits.MAX_IDEMPOTENCY_KEYS) {
            throw new ControlPlaneHttpSupport.ApiException(429, "IDEMPOTENCY_LIMIT", "idempotency key store is full");
        }

        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String requestPayload = JsonCodec.stringify(body);
        String durableScope = "dynamic-task:create:" + scanId;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency, ControlPlaneHttpSupport.idempotencyMapKey(durableScope, key));
        for (String field : body.keySet()) {
            if (!Set.of("authorized").contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "RUNTIME_FIELD_REJECTED",
                        "dynamic task body only accepts authorized");
            }
        }
        if (!body.containsKey("authorized") || !ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED", "dynamic task authorization is required");
        }
        String operatorId = operators.actor(exchange).operatorId();
        ControlPlaneHandlerRecords.DynamicTaskReplay existing = host.idempotentDynamicTasks.get(replayKey);
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, requestPayload);
        if (existing == null && durable != null) {
            TaskSnapshot restored = host.workerApi.snapshots(host.store.requireScan(scanId).dto().projectId(), scanId).stream()
                    .filter(value -> value.scope().taskId().equals(durable.resultRef())).findFirst().orElse(null);
            if (restored != null) {
                existing = new ControlPlaneHandlerRecords.DynamicTaskReplay(new ControlPlaneHandlerRecords.DynamicTaskPayload(
                        scanId, restored.spec().artifactDigest(), restored.spec().targetEntryId()), restored);
                host.idempotentDynamicTasks.putIfAbsent(replayKey, existing);
            }
        }
        TaskSnapshot snapshot;
        if (existing != null) {
            snapshot = existing.snapshot();
            ControlPlaneHttpSupport.sendJson(exchange, 200, dynamicTaskMap(snapshot));
            return;
        }
        snapshot = sandboxProbe.enqueueDynamicForPipeline(scanId, operatorId);
        ControlPlaneHandlerRecords.DynamicTaskPayload payload = new ControlPlaneHandlerRecords.DynamicTaskPayload(
                scanId, snapshot.spec().artifactDigest(), snapshot.spec().targetEntryId());
        ControlPlaneHandlerRecords.DynamicTaskReplay conflict = host.idempotentDynamicTasks.putIfAbsent(
                replayKey, new ControlPlaneHandlerRecords.DynamicTaskReplay(payload, snapshot));
        if (conflict != null) {
            ControlPlaneHttpSupport.sendJson(exchange, 200, dynamicTaskMap(conflict.snapshot()));
            return;
        }
        rememberDurableIdempotency(durableScope, key, requestPayload, snapshot.scope().taskId(), null);
        ControlPlaneHttpSupport.sendJson(exchange, 202, dynamicTaskMap(snapshot));
    }
    public void listDynamicTasks(HttpExchange exchange, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        List<Object> tasks = host.workerApi.snapshots(scan.dto().projectId(), scanId).stream()
                .map(this::dynamicTaskWithDiagnostic).map(value -> (Object) value).toList();
        ControlPlaneHttpSupport.sendJson(exchange, 200, stringEnvelope("dynamicTasks", tasks));
    }
    Map<String, Object> dynamicTaskWithDiagnostic(TaskSnapshot snapshot) {
        Map<String, Object> result = dynamicTaskMap(snapshot);
        String diagnostic = host.workerApi.failureDiagnostic(snapshot.scope());
        if (diagnostic != null) result.put("failureDiagnostic", diagnostic);
        String progress = host.workerApi.progressDetail(snapshot.scope());
        if (progress != null) result.put("progressDetail", progress);
        return result;
    }

    /**
     * 仅为进程内 Docker worker 解析不可变的后端托管副本。
     * 此方法不通过 HTTP 暴露路径。
     */
    static Map<String, Object> dynamicTaskMap(TaskSnapshot snapshot) {
        WorkerTaskSpec spec = snapshot.spec();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", spec.projectId());
        result.put("artifactDigest", spec.artifactDigest());
        result.put("scanId", spec.scanId());
        result.put("taskId", spec.taskId());
        result.put("targetEntryId", spec.targetEntryId());
        result.put("status", snapshot.lifecycle().name());
        result.put("verificationStatus", "DYNAMIC_SUSPECTED");
        result.put("requiredCapability", spec.requiredCapability().name());
        result.put("fixtureOnly", false);
        result.put("networkMode", "DENY");
        result.put("networkAllowlist", List.of());
        result.put("dynamicExecutionMode", "TRUSTED_DOCKER_NETWORK_NONE");
        result.put("maxWallClockSeconds", spec.resourceBudget().maxWallClockSeconds());
        result.put("maxCpuMillis", spec.resourceBudget().maxCpuMillis());
        result.put("maxMemoryBytes", spec.resourceBudget().maxMemoryBytes());
        result.put("maxDiskBytes", spec.resourceBudget().maxDiskBytes());
        result.put("maxTraceBytes", spec.resourceBudget().maxTraceBytes());
        result.put("stopReason", snapshot.stopReason() == null ? null : snapshot.stopReason().name());
        result.put("failureCode", snapshot.failureCode());
        result.put("updatedAt", snapshot.updatedAt().toString());
        return result;
    }
    public synchronized void replayFinding(HttpExchange exchange, String findingId) throws IOException {
        ApiDtos.FindingDto finding = host.store.finding(findingId);
        if (finding == null) throw new ControlPlaneHttpSupport.ApiException(404, "FINDING_NOT_FOUND", "finding not found");
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String requestPayload = JsonCodec.stringify(body);
        String durableScope = "finding:replay:" + findingId;
        for (String field : body.keySet()) {
            if (!Set.of("authorized").contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "REPLAY_FIELD_REJECTED", "finding replay body contains an unsupported field");
            }
        }
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED", "explicit authorization is required to replay a finding");
        }
        String key = ControlPlaneHttpSupport.requireIdempotencyKey(exchange);
        String replayKey = finding.projectId() + ":" + findingId + ":" + key;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.idempotentFindingReplays, replayKey);
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency, ControlPlaneHttpSupport.idempotencyMapKey(durableScope, key));
        ControlPlaneHandlerRecords.FindingReplay existing = host.idempotentFindingReplays.get(replayKey);
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, requestPayload);
        if (existing == null && durable != null) {
            TaskSnapshot restored = host.workerApi.snapshots(finding.projectId(), finding.scanId()).stream()
                    .filter(value -> value.scope().taskId().equals(durable.resultRef())).findFirst().orElse(null);
            if (restored != null) {
                existing = new ControlPlaneHandlerRecords.FindingReplay(finding.scanId(), restored);
                host.idempotentFindingReplays.putIfAbsent(replayKey, existing);
            }
        }
        if (existing != null) {
            ControlPlaneStore.ScanRecord scan = host.store.requireScan(existing.scanId());
            ControlPlaneHttpSupport.sendJson(exchange, 200, findingReplayMap(finding, scan, existing.snapshot(), true));
            return;
        }
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(finding.scanId());
        if (!finding.projectId().equals(scan.dto().projectId())
                || !finding.artifactDigest().equals(scan.dto().artifactDigest())) {
            throw new ControlPlaneHttpSupport.ApiException(409, "FINDING_SCOPE_INVALID", "finding is not bound to its scan");
        }
        if (scan.dto().entries().stream().noneMatch(entry -> entry.id().equals(finding.entrypointId()))) {
            throw new ControlPlaneHttpSupport.ApiException(409, "ENTRY_NOT_FOUND", "finding entrypoint is not present in the scan");
        }
        String operatorId = operators.actor(exchange).operatorId();
        if (host.workerApi.hasActiveDynamicTask(finding.projectId(), finding.scanId())) {
            throw new ControlPlaneHttpSupport.ApiException(409, "DYNAMIC_TASK_BUSY",
                    "a dynamic task is already active for this scan; wait for it to finish or retry the dynamic stage first");
        }
        TaskSnapshot snapshot = sandboxProbe.enqueueDynamicForPipeline(finding.scanId(), operatorId, finding.entrypointId());
        host.idempotentFindingReplays.put(replayKey, new ControlPlaneHandlerRecords.FindingReplay(finding.scanId(), snapshot));
        rememberDurableIdempotency(durableScope, key, requestPayload, snapshot.scope().taskId(), null);
        host.store.auditChange(finding.projectId(), operatorId, "finding.replay", "finding", findingId,
                "{\"scanId\":\"" + finding.scanId() + "\",\"entrypointId\":\""
                        + finding.entrypointId() + "\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\"}",
                Instant.now(host.clock).toString());
        ControlPlaneHttpSupport.sendJson(exchange, 202, findingReplayMap(finding, scan, snapshot, false));
    }
    static Map<String, Object> findingReplayMap(ApiDtos.FindingDto finding,
                                                        ControlPlaneStore.ScanRecord scan,
                                                        TaskSnapshot snapshot,
                                                        boolean replayed) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", finding.projectId());
        result.put("scanId", scan.dto().scanId());
        result.put("findingId", finding.findingId());
        result.put("entrypointId", finding.entrypointId());
        result.put("taskId", snapshot.scope().taskId());
        result.put("lifecycle", snapshot.lifecycle().name());
        result.put("verificationStatus", "DYNAMIC_SUSPECTED");
        result.put("dependencyMode", "MOCK");
        result.put("replayed", replayed);
        result.put("requiredCapability", snapshot.spec().requiredCapability().name());
        result.put("dynamicExecutionMode", snapshot.spec().requiredCapability().name());
        return result;
    }

    /**
     * 面向操作员的单入口调试 probe。复用 finding-replay / sandbox_probe 门禁：
     * 操作员鉴权、显式 authorized:true、Idempotency-Key、属于 scan 的 HTTP 入口，
     * 以及另一 dynamic task 活跃时的 DYNAMIC_TASK_BUSY。沙箱策略仍由
     * 服务端持有；永不升级为 VERIFIED。
     */
    public synchronized void focusEntryProbe(HttpExchange exchange, String scanId, String entryId)
            throws IOException {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String requestPayload = JsonCodec.stringify(body);
        String durableScope = "entry:focus-probe:" + scanId + ":" + entryId;
        Set<String> allowed = Set.of("authorized", "techniqueId", "authorizationHeader",
                "secondaryAuthorizationHeader", "bladeAuthHeader",
                "candidateInputs", "maxRequests", "experimentPlanId");
        for (String field : body.keySet()) {
            if (!allowed.contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "FOCUS_PROBE_FIELD_REJECTED",
                        "entry focus-probe body contains an unsupported field");
            }
        }
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit authorization is required to focus-probe an entry");
        }
        ApiDtos.EntryDto entry = scan.dto().entries().stream()
                .filter(value -> value.id().equals(entryId))
                .findFirst()
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "ENTRY_NOT_FOUND",
                        "entry is not present in the scan"));
        if (!"HTTP".equalsIgnoreCase(entry.protocol()) || entry.route() == null || entry.method() == null) {
            throw new ControlPlaneHttpSupport.ApiException(409, "ENTRY_NOT_HTTP",
                    "focus-probe requires an HTTP scan entry with method and route");
        }
        String techniqueId = body.containsKey("techniqueId")
                ? ControlPlaneHttpSupport.optionalText(body, "techniqueId", null) : null;
        String authorizationHeader = body.containsKey("authorizationHeader")
                ? ControlPlaneHttpSupport.optionalText(body, "authorizationHeader", null) : null;
        String bladeAuthHeader = null;
        if (body.containsKey("secondaryAuthorizationHeader")) {
            bladeAuthHeader = ControlPlaneHttpSupport.optionalText(body, "secondaryAuthorizationHeader", null);
        } else if (body.containsKey("bladeAuthHeader")) {
            bladeAuthHeader = ControlPlaneHttpSupport.optionalText(body, "bladeAuthHeader", null);
        }
        List<String> candidateInputs = ControlPlaneHttpSupport.stringList(body.get("candidateInputs"), "candidateInputs");
        long maxRequestsLong = ControlPlaneHttpSupport.positiveLong(body, "maxRequests", 1);
        String experimentPlanId = body.containsKey("experimentPlanId")
                ? ControlPlaneHttpSupport.optionalText(body, "experimentPlanId", null) : null;
        if (experimentPlanId != null && !experimentPlanId.isBlank()) {
            ExperimentPlan bound = findAcceptedPlan(scanId, experimentPlanId)
                    .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "EXPERIMENT_PLAN_NOT_FOUND",
                            "experiment plan was not accepted for this scan"));
            String expectedRef = "entry:" + entryId;
            if (!expectedRef.equals(bound.entrypointRef())
                    && !EntryRefResolver.canonicalRef(entry).equals(bound.entrypointRef())) {
                throw new ControlPlaneHttpSupport.ApiException(409, "EXPERIMENT_PLAN_ENTRY_MISMATCH",
                        "experiment plan entrypoint does not match focus entry");
            }
            if (candidateInputs.isEmpty() && !bound.candidateInputs().isEmpty()) {
                candidateInputs = bound.candidateInputs();
            }
            if (!body.containsKey("maxRequests")) {
                maxRequestsLong = bound.maxAttempts();
            }
        }
        if (candidateInputs.size() > 16) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_FIELD", "candidateInputs is limited to 16 values");
        }
        if (maxRequestsLong > 8) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_FIELD", "maxRequests must be 1..8");
        }
        int maxRequests = (int) maxRequestsLong;
        String boundedTechnique = techniqueId == null ? "" : techniqueId.trim().toUpperCase(Locale.ROOT);
        if (!boundedTechnique.isEmpty() && !boundedTechnique.matches("[A-Z][A-Z0-9_]{1,63}")) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_FIELD", "techniqueId is invalid");
        }
        if (authorizationHeader != null && !authorizationHeader.isBlank()) {
            AuthBypassCandidate.validateAuthMaterialOnly(authorizationHeader);
        }
        if (bladeAuthHeader != null && !bladeAuthHeader.isBlank()) {
            AuthBypassCandidate.validateAuthMaterialOnly(bladeAuthHeader);
        }
        // 优先 buildFocusedAiPocPlan：无 technique/auth 时共享 plan 仍会 flood。
        if (boundedTechnique.isEmpty()
                && (authorizationHeader == null || authorizationHeader.isBlank())
                && (bladeAuthHeader == null || bladeAuthHeader.isBlank())) {
            boundedTechnique = AuthBypassTechnique.CUSTOM_POC.name();
        }

        String key = ControlPlaneHttpSupport.requireIdempotencyKey(exchange);
        String replayKey = scan.dto().projectId() + ":" + scanId + ":" + entryId + ":" + key;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.idempotentEntryFocusProbes, replayKey);
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency, ControlPlaneHttpSupport.idempotencyMapKey(durableScope, key));
        ControlPlaneHandlerRecords.EntryFocusProbe existing = host.idempotentEntryFocusProbes.get(replayKey);
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, requestPayload);
        if (existing == null && durable != null) {
            TaskSnapshot restored = host.workerApi.snapshots(scan.dto().projectId(), scanId).stream()
                    .filter(value -> value.scope().taskId().equals(durable.resultRef())).findFirst()
                    .orElse(null);
            if (restored != null) {
                existing = new ControlPlaneHandlerRecords.EntryFocusProbe(scanId, entryId, restored);
                host.idempotentEntryFocusProbes.putIfAbsent(replayKey, existing);
            }
        }
        if (existing != null) {
            ControlPlaneStore.ScanRecord current = host.store.requireScan(existing.scanId());
            ControlPlaneHttpSupport.sendJson(exchange, 200, entryFocusProbeMap(current, existing.entryId(),
                    existing.snapshot(), true));
            return;
        }
        String operatorId = operators.actor(exchange).operatorId();
        if (host.workerApi.hasActiveDynamicTask(scan.dto().projectId(), scanId)) {
            throw new ControlPlaneHttpSupport.ApiException(409, "DYNAMIC_TASK_BUSY",
                    "a dynamic task is already active for this scan; wait for it to finish or retry the dynamic stage first");
        }
        TaskSnapshot snapshot = sandboxProbe.enqueueDynamicForPipeline(scanId, operatorId, entryId, candidateInputs,
                maxRequests,
                boundedTechnique.isEmpty() ? null : boundedTechnique,
                authorizationHeader == null || authorizationHeader.isBlank() ? null : authorizationHeader,
                bladeAuthHeader == null || bladeAuthHeader.isBlank() ? null : bladeAuthHeader);
        if (experimentPlanId != null && !experimentPlanId.isBlank()) {
            host.traceProjectionService.bindExperimentPlan(snapshot.scope().taskId(), experimentPlanId.trim());
        }
        host.idempotentEntryFocusProbes.put(replayKey, new ControlPlaneHandlerRecords.EntryFocusProbe(scanId, entryId, snapshot));
        rememberDurableIdempotency(durableScope, key, requestPayload, snapshot.scope().taskId(), null);
        String focusAudit = "{\"scanId\":\"" + scanId + "\",\"entrypointId\":\"" + entryId
                + "\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\",\"maxRequests\":" + maxRequests
                + ",\"attemptKind\":\"INITIAL\",\"taskId\":\"" + snapshot.scope().taskId()
                + "\",\"replayed\":false";
        if (experimentPlanId != null && !experimentPlanId.isBlank()) {
            focusAudit += ",\"experimentPlanId\":\"" + experimentPlanId.trim() + "\"";
        }
        focusAudit += "}";
        host.store.auditChange(scan.dto().projectId(), operatorId, "entry.focus-probe", "entry", entryId,
                focusAudit, Instant.now(host.clock).toString());
        ControlPlaneHttpSupport.sendJson(exchange, 202, entryFocusProbeMap(scan, entryId, snapshot, false));
    }

    /**
     * 接受来自 {@code plan_propose} 的服务端门禁 {@link ExperimentPlan}。进程内 MVP
     * 存储；后续经 experimentPlanId 绑定 focus-probe / flood。
     */
    Map<String, Object> entryFocusProbeMap(ControlPlaneStore.ScanRecord scan,
                                                  String entryId,
                                                  TaskSnapshot snapshot,
                                                  boolean replayed) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", scan.dto().projectId());
        result.put("scanId", scan.dto().scanId());
        result.put("findingId", null);
        result.put("entrypointId", entryId);
        result.put("taskId", snapshot.scope().taskId());
        result.put("lifecycle", snapshot.lifecycle().name());
        result.put("verificationStatus", "DYNAMIC_SUSPECTED");
        result.put("dependencyMode", "MOCK");
        result.put("replayed", replayed);
        result.put("attemptKind", replayed ? "REPLAY" : "INITIAL");
        String boundPlan = host.traceProjectionService.experimentPlanIdForTask(snapshot.scope().taskId());
        if (boundPlan != null && !boundPlan.isBlank()) {
            result.put("experimentPlanId", boundPlan);
        }
        result.put("requiredCapability", snapshot.spec().requiredCapability().name());
        result.put("dynamicExecutionMode", snapshot.spec().requiredCapability().name());
        return result;
    }
    public synchronized void acceptExperimentPlan(String scanId, ExperimentPlan plan) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(plan, "plan");
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        ExperimentPlanValidator.validate(plan, 8);
        EntryRefResolver.Resolution entry = EntryRefResolver.resolve(scan.dto().entries(), plan.entrypointRef());
        if (!entry.resolved()) {
            throw new IllegalArgumentException(entry.code());
        }
        final ExperimentPlan acceptedPlan = entry.canonicalRef().equals(plan.entrypointRef())
                ? plan
                : new ExperimentPlan(
                        plan.planId(), entry.canonicalRef(), plan.track(), plan.method(), plan.contentType(),
                        plan.requiredParameters(), plan.authRequired(), plan.successHttpHint(),
                        plan.successJsonPath(), plan.maxAttempts(), plan.candidateInputs(),
                        plan.stopCondition(), plan.packId(), plan.fuzzStrategyJson());
        List<ExperimentPlan> plans = host.scanExperimentPlans.computeIfAbsent(scanId,
                ignored -> new ArrayList<>());
        plans.removeIf(existing -> existing.planId().equals(acceptedPlan.planId()));
        plans.add(acceptedPlan);
        while (plans.size() > 64) {
            plans.remove(0);
        }
        try {
            host.store.persistExperimentPlan(new SQLiteControlPlanePersistence.ExperimentPlanData(
                    acceptedPlan.planId(),
                    scanId,
                    scan.dto().projectId(),
                    scan.dto().artifactDigest(),
                    PayloadSchemaGuard.withSchemaVersion(
                            host.JSON, acceptedPlan, PayloadSchemaGuard.MIN_SCHEMA_VERSION),
                    Instant.now(host.clock).toString(),
                    acceptedPlan.fuzzStrategyJson()));
        } catch (RuntimeException failure) {
            throw new ControlPlaneHttpSupport.ApiException(500, "EXPERIMENT_PLAN_PERSIST_FAILED",
                    "could not persist experiment plan");
        }
    }
    void restoreExperimentPlans() {
        for (SQLiteControlPlanePersistence.ExperimentPlanData stored : host.store.loadExperimentPlans()) {
            ControlPlaneStore.ScanRecord scan = host.store.scan(stored.scanId());
            if (scan == null || !scan.dto().projectId().equals(stored.projectId())
                    || !scan.dto().artifactDigest().equals(stored.artifactDigest())) {
                continue;
            }
            try {
                ExperimentPlan decoded = PayloadSchemaGuard.readIgnoringSchemaVersion(
                                host.JSON, stored.payloadJson(), ExperimentPlan.class,
                                "experiment_plan " + stored.planId());
                final ExperimentPlan plan =
                        (decoded.fuzzStrategyJson() == null || decoded.fuzzStrategyJson().isBlank())
                                && stored.fuzzStrategyJson() != null && !stored.fuzzStrategyJson().isBlank()
                        ? new ExperimentPlan(
                                decoded.planId(), decoded.entrypointRef(), decoded.track(), decoded.method(),
                                decoded.contentType(), decoded.requiredParameters(), decoded.authRequired(),
                                decoded.successHttpHint(), decoded.successJsonPath(), decoded.maxAttempts(),
                                decoded.candidateInputs(), decoded.stopCondition(), decoded.packId(),
                                stored.fuzzStrategyJson())
                        : decoded;
                ExperimentPlanValidator.validate(plan, 8);
                List<ExperimentPlan> plans = host.scanExperimentPlans.computeIfAbsent(stored.scanId(),
                        ignored -> new ArrayList<>());
                plans.removeIf(existing -> existing.planId().equals(plan.planId()));
                plans.add(plan);
                while (plans.size() > 64) plans.remove(0);
            } catch (Exception ignored) {
                // 单行损坏 fail-closed；其他 plan 仍恢复。
            }
        }
    }
    public synchronized void replaySqlExperimentCard(HttpExchange exchange, String scanId, String cardId)
            throws IOException {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String requestPayload = JsonCodec.stringify(body);
        String durableScope = "sql-experiment-card:replay:" + scanId + ":" + cardId;
        Set<String> allowed = Set.of("authorized");
        for (String field : body.keySet()) {
            if (!allowed.contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "EXPERIMENT_CARD_FIELD_REJECTED",
                        "experiment-card replay body contains an unsupported field");
            }
        }
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit authorization is required to replay an experiment card");
        }
        List<ApiDtos.PathRunDto> pathRuns = pathFindings.mergedPathRunsForScan(
                scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
        SqlExperimentCard card = SqlExperimentCardBuilder.fromPathRuns(scanId, pathRuns).stream()
                .filter(value -> value.cardId().equals(cardId))
                .findFirst()
                .orElseThrow(() -> new ControlPlaneHttpSupport.ApiException(404, "EXPERIMENT_CARD_NOT_FOUND",
                        "SQL experiment card not found for scan PathRuns"));
        if ("VERIFIED".equals(card.verificationStatus())) {
            throw new ControlPlaneHttpSupport.ApiException(409, "VERIFIED_FORBIDDEN",
                    "D3 cards must not claim VERIFIED");
        }
        EntryRefResolver.Resolution resolved = EntryRefResolver.resolve(
                scan.dto().entries(), card.entrypointRef());
        if (!resolved.resolved()) {
            throw new ControlPlaneHttpSupport.ApiException(404, resolved.code(),
                    "experiment card entry is not present in the scan");
        }
        ApiDtos.EntryDto entry = resolved.entry();
        if (!"HTTP".equalsIgnoreCase(entry.protocol()) || entry.route() == null || entry.method() == null) {
            throw new ControlPlaneHttpSupport.ApiException(409, "ENTRY_NOT_HTTP",
                    "experiment-card replay requires an HTTP scan entry");
        }
        List<String> inputs = new ArrayList<>();
        if (card.benignInput() != null && !card.benignInput().isBlank()) inputs.add(card.benignInput());
        if (card.metaInput() != null && !card.metaInput().isBlank()) inputs.add(card.metaInput());
        if (inputs.isEmpty()) inputs = List.of("q=benign", "q=" + com.aq.jvmsentinel.worker.SqlDiffProbe.META_MARKER);
        String key = ControlPlaneHttpSupport.requireIdempotencyKey(exchange);
        String replayKey = scan.dto().projectId() + ":" + scanId + ":" + cardId + ":" + key;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.idempotentExperimentCardReplays, replayKey);
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency, ControlPlaneHttpSupport.idempotencyMapKey(durableScope, key));
        ControlPlaneHandlerRecords.EntryFocusProbe existing = host.idempotentExperimentCardReplays.get(replayKey);
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, requestPayload);
        if (existing == null && durable != null) {
            TaskSnapshot restored = host.workerApi.snapshots(scan.dto().projectId(), scanId).stream()
                    .filter(value -> value.scope().taskId().equals(durable.resultRef())).findFirst()
                    .orElse(null);
            if (restored != null) {
                existing = new ControlPlaneHandlerRecords.EntryFocusProbe(scanId, entry.id(), restored);
                host.idempotentExperimentCardReplays.putIfAbsent(replayKey, existing);
            }
        }
        if (existing != null) {
            ControlPlaneStore.ScanRecord current = host.store.requireScan(existing.scanId());
            Map<String, Object> replayed = entryFocusProbeMap(current, existing.entryId(),
                    existing.snapshot(), true);
            replayed.put("cardId", cardId);
            replayed.put("sqlExperimentReplay", true);
            ControlPlaneHttpSupport.sendJson(exchange, 200, replayed);
            return;
        }
        String operatorId = operators.actor(exchange).operatorId();
        if (host.workerApi.hasActiveDynamicTask(scan.dto().projectId(), scanId)) {
            throw new ControlPlaneHttpSupport.ApiException(409, "DYNAMIC_TASK_BUSY",
                    "a dynamic task is already active for this scan; wait for it to finish or retry the dynamic stage first");
        }
        TaskSnapshot snapshot = sandboxProbe.enqueueDynamicForPipeline(scanId, operatorId, entry.id(), inputs, 2,
                AuthBypassTechnique.CUSTOM_POC.name(), null, null);
        if (card.experimentPlanId() != null && !card.experimentPlanId().isBlank()) {
            host.traceProjectionService.bindExperimentPlan(snapshot.scope().taskId(), card.experimentPlanId().trim());
        }
        host.idempotentExperimentCardReplays.put(replayKey, new ControlPlaneHandlerRecords.EntryFocusProbe(scanId, entry.id(), snapshot));
        rememberDurableIdempotency(durableScope, key, requestPayload, snapshot.scope().taskId(), null);
        String replayAudit = "{\"scanId\":\"" + scanId + "\",\"cardId\":\"" + cardId
                + "\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\",\"dependencyMode\":\"MOCK\""
                + ",\"attemptKind\":\"REPLAY\",\"taskId\":\"" + snapshot.scope().taskId()
                + "\",\"replayed\":false";
        if (card.experimentPlanId() != null && !card.experimentPlanId().isBlank()) {
            replayAudit += ",\"experimentPlanId\":\"" + card.experimentPlanId().trim() + "\"";
        }
        replayAudit += "}";
        host.store.auditChange(scan.dto().projectId(), operatorId, "sql-experiment-card.replay", "entry",
                entry.id(), replayAudit, Instant.now(host.clock).toString());
        Map<String, Object> accepted = entryFocusProbeMap(scan, entry.id(), snapshot, false);
        accepted.put("attemptKind", "REPLAY");
        accepted.put("cardId", cardId);
        accepted.put("sqlExperimentReplay", true);
        ControlPlaneHttpSupport.sendJson(exchange, 202, accepted);
    }
}

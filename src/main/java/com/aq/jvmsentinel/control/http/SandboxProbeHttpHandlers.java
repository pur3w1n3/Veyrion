package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.analysis.experiment.WorldPackPlanner;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackDependencyMode;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackExecutionStage;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.RunProfile;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.control.WorkerControlPlaneApi;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.jar.JarFile;

/** 从 ControlPlaneRouteHandlers 拆出的 HTTP 处理器：SandboxProbe 域。 */
final class SandboxProbeHttpHandlers extends ControlPlaneHandlerSupport {
private final OperatorProviderHttpHandlers operators;
private final PathFindingsHttpHandlers pathFindings;

    SandboxProbeHttpHandlers(ControlPlaneHandlerHost host, OperatorProviderHttpHandlers operators, PathFindingsHttpHandlers pathFindings) {
        super(host);
        this.operators = operators;
        this.pathFindings = pathFindings;
    }

    Optional<ToolDataSource.FactRecord> requestSandboxProbe(
            String scanId, ToolExecutionContext.Scope scope, String principalId, String jobId,
            String toolCallId, String entrypointRef, List<String> candidateInputs, int maxRequests,
            String techniqueId, String authorizationHeader, String bladeAuthHeader) {
        return requestSandboxProbe(scanId, scope, principalId, jobId, toolCallId, entrypointRef,
                candidateInputs, maxRequests, techniqueId, authorizationHeader, bladeAuthHeader, null);
    }

    Optional<ToolDataSource.FactRecord> requestSandboxProbe(
            String scanId, ToolExecutionContext.Scope scope, String principalId, String jobId,
            String toolCallId, String entrypointRef, List<String> candidateInputs, int maxRequests,
            String techniqueId, String authorizationHeader, String bladeAuthHeader,
            String experimentPlanId) {
        if (!"local".equals(scope.workspaceId()) || principalId == null || principalId.isBlank()) {
            throw new SecurityException("sandbox probe scope is invalid");
        }
        if (jobId == null || jobId.isBlank()) {
            throw new SecurityException("sandbox probe job identity is required");
        }
        String probeAttemptId = probeAttemptId(jobId, toolCallId);
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        if (!scope.projectId().equals(scan.dto().projectId())) {
            throw new SecurityException("sandbox probe project scope mismatch");
        }
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
        if (!resolution.resolved()) {
            throw new IllegalArgumentException(resolution.code());
        }
        ApiDtos.EntryDto entry = resolution.entry();
        String canonicalRef = resolution.canonicalRef();
        String entryId = entry.id();
        if (!"HTTP".equalsIgnoreCase(entry.protocol()) || entry.route() == null
                || entry.method() == null || maxRequests < 1 || maxRequests > 8) {
            throw new IllegalArgumentException("sandbox probe entry is not an eligible HTTP endpoint");
        }
        String boundedTechnique = techniqueId == null ? "" : techniqueId.trim().toUpperCase(Locale.ROOT);
        if (!boundedTechnique.isEmpty() && !boundedTechnique.matches("[A-Z][A-Z0-9_]{1,63}")) {
            throw new IllegalArgumentException("techniqueId is invalid");
        }
        String boundedAuth = authorizationHeader == null ? "" : authorizationHeader;
        if (!boundedAuth.isEmpty()) {
            com.aq.jvmsentinel.model.AuthBypassCandidate.validateAuthMaterialOnly(boundedAuth);
        }
        String boundedBlade = bladeAuthHeader == null ? "" : bladeAuthHeader;
        if (!boundedBlade.isEmpty()) {
            com.aq.jvmsentinel.model.AuthBypassCandidate.validateAuthMaterialOnly(boundedBlade);
        }
        String boundedPlanId = experimentPlanId == null ? "" : experimentPlanId.trim();
        if (!boundedPlanId.isEmpty()) {
            ExperimentPlan accepted = findAcceptedPlan(scanId, boundedPlanId).orElseThrow(() ->
                    new IllegalArgumentException("EXPERIMENT_PLAN_NOT_FOUND"));
            EntryRefResolver.Resolution planned = EntryRefResolver.resolve(
                    scan.dto().entries(), accepted.entrypointRef());
            if (!planned.resolved() || !canonicalRef.equals(planned.canonicalRef())) {
                throw new IllegalArgumentException("EXPERIMENT_PLAN_ENTRYPOINT_MISMATCH");
            }
        }
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("entrypointRef", canonicalRef);
        request.put("candidateInputs", candidateInputs == null ? List.of() : candidateInputs);
        request.put("maxRequests", maxRequests);
        if (!boundedTechnique.isEmpty()) request.put("techniqueId", boundedTechnique);
        if (!boundedPlanId.isEmpty()) request.put("experimentPlanId", boundedPlanId);
        if (!boundedAuth.isEmpty()) {
            request.put("authorizationHeaderBytes", boundedAuth.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            request.put("authorizationHeaderSha256", ControlPlaneHttpSupport.payloadHash(boundedAuth));
        }
        if (!boundedBlade.isEmpty()) {
            request.put("bladeAuthHeaderBytes", boundedBlade.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            request.put("bladeAuthHeaderSha256", ControlPlaneHttpSupport.payloadHash(boundedBlade));
        }
        String requestPayload = JsonCodec.stringify(request);
        // Attempt 作用域标识：jobId + canonical toolCallId（P0-03）。旧 job-only 键仍可读。
        String durableScope = "sandbox-probe:attempt";
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency, ControlPlaneHttpSupport.idempotencyMapKey(durableScope, probeAttemptId));
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, probeAttemptId, requestPayload);
        if (durable == null && (toolCallId == null || toolCallId.isBlank())) {
            durable = existingDurableIdempotency("sandbox-probe:job", jobId, requestPayload);
        }
        final SQLiteControlPlanePersistence.IdempotencyData durableHit = durable;
        TaskSnapshot existing = host.aiProbeTasks.get(probeAttemptId);
        if (existing == null && durableHit != null) {
            existing = host.workerApi.snapshots(scan.dto().projectId(), scanId).stream()
                    .filter(value -> value.scope().taskId().equals(durableHit.resultRef())).findFirst()
                    .orElse(null);
            if (existing == null) {
                return Optional.of(probeExecutionFailureFact(scope, probeAttemptId, scanId, canonicalRef, entry,
                        candidateInputs, maxRequests, "SANDBOX_PROBE_REPLAY_MISSING",
                        "sandbox probe replay has no persistent worker task"));
            }
            host.aiProbeTasks.putIfAbsent(probeAttemptId, existing);
        }
        try {
            if (existing != null) {
                TaskSnapshot refreshed = refreshTaskSnapshot(scan.dto().projectId(), scanId, existing.scope().taskId())
                        .orElse(existing);
                host.aiProbeTasks.put(probeAttemptId, refreshed);
                if (isActiveLifecycle(refreshed.lifecycle())) {
                    refreshed = awaitDynamicTaskTerminal(scan.dto().projectId(), scanId, refreshed.scope().taskId(),
                            Duration.ofMinutes(8)).orElse(refreshed);
                    host.aiProbeTasks.put(probeAttemptId, refreshed);
                }
                return Optional.of(probeFact(scope, refreshed, entry, probeState(refreshed),
                        candidateInputs, maxRequests, probeAttemptId));
            }
            boolean scanBusy = host.workerApi.snapshots(scan.dto().projectId(), scanId).stream()
                    .anyMatch(value -> isActiveLifecycle(value.lifecycle()));
            if (scanBusy) {
                // 勿将外来在途 task 绑定到请求的 entry / attempt。
                Map<String, Object> busy = new LinkedHashMap<>();
                busy.put("schemaVersion", 1);
                busy.put("state", "BUSY");
                busy.put("scanId", scanId);
                busy.put("probeAttemptId", probeAttemptId);
                busy.put("entrypointRef", canonicalRef);
                busy.put("method", entry.method());
                busy.put("route", entry.route());
                busy.put("networkMode", "DENY");
                busy.put("executor", "SERVER_OWNED_TRUSTED_DOCKER");
                busy.put("candidateCount", candidateInputs == null ? 0 : Math.min(16, candidateInputs.size()));
                busy.put("requestLimit", Math.min(8, Math.max(1, maxRequests)));
                busy.put("retryable", true);
                return Optional.of(new ToolDataSource.FactRecord(scope,
                        "sandbox-probe:busy:" + probeAttemptId, host.JSON.valueToTree(busy)));
            }

            TaskSnapshot snapshot = enqueueDynamicForPipeline(scanId, principalId, entryId, candidateInputs,
                    maxRequests, boundedTechnique.isEmpty() ? null : boundedTechnique,
                    boundedAuth.isEmpty() ? null : boundedAuth,
                    boundedBlade.isEmpty() ? null : boundedBlade);
            if (!boundedPlanId.isEmpty()) {
                host.traceProjectionService.bindExperimentPlan(snapshot.scope().taskId(), boundedPlanId);
            }
            if (host.aiProbeTasks.size() >= ControlPlaneHttpLimits.MAX_IDEMPOTENCY_KEYS && !host.aiProbeTasks.containsKey(probeAttemptId)) {
                return Optional.of(probeExecutionFailureFact(scope, probeAttemptId, scanId, canonicalRef, entry,
                        candidateInputs, maxRequests, "SANDBOX_PROBE_JOB_LIMIT",
                        "sandbox probe attempt limit reached"));
            }
            host.aiProbeTasks.putIfAbsent(probeAttemptId, snapshot);
            rememberDurableIdempotency(durableScope, probeAttemptId, requestPayload,
                    snapshot.scope().taskId(), null);
            TaskSnapshot finished = awaitDynamicTaskTerminal(scan.dto().projectId(), scanId, snapshot.scope().taskId(),
                    Duration.ofMinutes(8)).orElse(snapshot);
            host.aiProbeTasks.put(probeAttemptId, finished);
            return Optional.of(probeFact(scope, finished, entry, probeState(finished),
                    candidateInputs, maxRequests, probeAttemptId));
        } catch (ControlPlaneHttpSupport.ApiException apiException) {
            return Optional.of(probeExecutionFailureFact(scope, probeAttemptId, scanId, canonicalRef, entry,
                    candidateInputs, maxRequests, apiException.code,
                    apiException.getMessage() == null ? apiException.code : apiException.getMessage()));
        } catch (RuntimeException runtime) {
            String code = runtime.getMessage() != null && runtime.getMessage().matches("[A-Z][A-Z0-9_]{2,127}")
                    ? runtime.getMessage()
                    : "SANDBOX_PROBE_EXECUTION_FAILED";
            return Optional.of(probeExecutionFailureFact(scope, probeAttemptId, scanId, canonicalRef, entry,
                    candidateInputs, maxRequests, code,
                    runtime.getMessage() == null ? code : runtime.getMessage()));
        }
    }

    /** 稳定 attempt 标识：{@code jobId + canonical toolCallId}（P0-03）。 */
    public static String probeAttemptId(String jobId, String toolCallId) {
        String call = toolCallId == null || toolCallId.isBlank() ? "legacy" : toolCallId.trim();
        return "patt-" + ControlPlaneHttpSupport.payloadHash(jobId + "\0" + call).substring(0, 32);
    }
    ToolDataSource.FactRecord probeExecutionFailureFact(
            ToolExecutionContext.Scope scope, String probeAttemptId, String scanId, String canonicalRef,
            ApiDtos.EntryDto entry, List<String> candidateInputs, int maxRequests,
            String failureCode, String detail) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("schemaVersion", 1);
        value.put("state", "FAILED");
        value.put("lifecycle", "FAILED");
        value.put("scanId", scanId);
        value.put("probeAttemptId", probeAttemptId);
        value.put("entrypointRef", canonicalRef);
        value.put("method", entry.method());
        value.put("route", entry.route());
        value.put("networkMode", "DENY");
        value.put("executor", "SERVER_OWNED_TRUSTED_DOCKER");
        value.put("candidateCount", candidateInputs == null ? 0 : Math.min(16, candidateInputs.size()));
        value.put("requestLimit", Math.min(8, Math.max(1, maxRequests)));
        value.put("pathRunCount", 0);
        value.put("failureCode", failureCode == null || failureCode.isBlank()
                ? "SANDBOX_PROBE_EXECUTION_FAILED" : failureCode);
        value.put("stopReason", "WORKER_FAILURE");
        value.put("retryable", false);
        if (detail != null && !detail.isBlank()) {
            value.put("detail", detail.length() > 240 ? detail.substring(0, 240) : detail);
        }
        return new ToolDataSource.FactRecord(scope, "sandbox-probe:failed:" + probeAttemptId,
                host.JSON.valueToTree(value));
    }
    static boolean isActiveLifecycle(TaskLifecycle lifecycle) {
        return lifecycle == TaskLifecycle.QUEUED
                || lifecycle == TaskLifecycle.LEASED
                || lifecycle == TaskLifecycle.RUNNING
                || lifecycle == TaskLifecycle.PAUSED;
    }
    static String probeState(TaskSnapshot snapshot) {
        return switch (snapshot.lifecycle()) {
            case COMPLETED -> "COMPLETED";
            case FAILED -> "FAILED";
            case CANCELLED -> "CANCELLED";
            default -> "QUEUED";
        };
    }
    Optional<TaskSnapshot> refreshTaskSnapshot(String projectId, String scanId, String taskId) {
        return host.workerApi.snapshots(projectId, scanId).stream()
                .filter(value -> value.scope().taskId().equals(taskId))
                .findFirst();
    }
    Optional<TaskSnapshot> awaitDynamicTaskTerminal(String projectId, String scanId, String taskId,
                                                            Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        Optional<TaskSnapshot> latest = refreshTaskSnapshot(projectId, scanId, taskId);
        while (System.nanoTime() < deadline) {
            if (latest.isPresent() && !isActiveLifecycle(latest.get().lifecycle())) {
                return latest;
            }
            try {
                Thread.sleep(250L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return latest;
            }
            latest = refreshTaskSnapshot(projectId, scanId, taskId);
        }
        return latest;
    }
    ToolDataSource.FactRecord probeFact(ToolExecutionContext.Scope scope,
                                                TaskSnapshot snapshot,
                                                ApiDtos.EntryDto entry,
                                                String state,
                                                List<String> candidateInputs,
                                                int maxRequests,
                                                String probeAttemptId) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("schemaVersion", 1);
        value.put("state", state);
        value.put("probeAttemptId", probeAttemptId);
        value.put("taskId", snapshot.scope().taskId());
        value.put("scanId", snapshot.scope().scanId());
        value.put("lifecycle", snapshot.lifecycle().name());
        value.put("entrypointRef", "entry:" + entry.id());
        value.put("method", entry.method());
        value.put("route", entry.route());
        value.put("networkMode", "DENY");
        value.put("executor", "SERVER_OWNED_TRUSTED_DOCKER");
        value.put("candidateCount", candidateInputs == null ? 0 : Math.min(16, candidateInputs.size()));
        value.put("requestLimit", Math.min(8, Math.max(1, maxRequests)));
        value.put("probePlanId", "probe-plan:" + snapshot.scope().taskId());
        String boundPlan = host.traceProjectionService.experimentPlanIdForTask(snapshot.scope().taskId());
        if (boundPlan != null && !boundPlan.isBlank()) {
            value.put("experimentPlanId", boundPlan);
        }
        if (snapshot.stopReason() != null) value.put("stopReason", snapshot.stopReason().name());
        if (snapshot.failureCode() != null) value.put("failureCode", snapshot.failureCode());
        List<ApiDtos.PathRunDto> pathRuns = pathFindings.mergedPathRunsForTask(snapshot.scope());
        value.put("pathRunCount", pathRuns.size());
        List<Object> pathRunSummaries = new ArrayList<>();
        int emitted = 0;
        int sqlTotal = 0;
        Map<String, Integer> outcomeCounts = new LinkedHashMap<>();
        for (ApiDtos.PathRunDto run : pathRuns) {
            sqlTotal += run.sqlEvents().size();
            outcomeCounts.merge(run.outcomeClass(), 1, Integer::sum);
            if (emitted < 16) {
                pathRunSummaries.add(ControlPlaneToolDataSource.pathRunPromptSummary(run));
                emitted++;
            }
        }
        value.put("pathRuns", pathRunSummaries);
        value.put("pathRunsTruncated", pathRuns.size() > 16);
        value.put("sqlEventCount", sqlTotal);
        value.put("outcomeClassCounts", outcomeCounts);
        value.put("pathRunFactHint", "facts_search kind=PATH_RUN or evidence_get pathrun:<pathRunId>");
        return new ToolDataSource.FactRecord(scope, "sandbox-probe:attempt:" + probeAttemptId,
                host.JSON.valueToTree(value));
    }
    synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId) {
        return enqueueDynamicForPipeline(scanId, actorId, null, List.of(),
                ProbePlanService.MAX_DYNAMIC_PROBES, null, null, null);
    }

    synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId,
                                                                 String preferredEntryId) {
        return enqueueDynamicForPipeline(scanId, actorId, preferredEntryId, List.of(),
                ProbePlanService.MAX_DYNAMIC_PROBES, null, null, null);
    }

    synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId,
                                                                 String preferredEntryId,
                                                                 List<String> candidateInputs,
                                                                 int maxRequests) {
        return enqueueDynamicForPipeline(scanId, actorId, preferredEntryId, candidateInputs,
                maxRequests, null, null, null);
    }

    synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId,
                                                                 String preferredEntryId,
                                                                 List<String> candidateInputs,
                                                                 int maxRequests,
                                                                 String techniqueId,
                                                                 String authorizationHeader) {
        return enqueueDynamicForPipeline(scanId, actorId, preferredEntryId, candidateInputs,
                maxRequests, techniqueId, authorizationHeader, null);
    }

    synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId,
                                                                 String preferredEntryId,
                                                                 List<String> candidateInputs,
                                                                 int maxRequests,
                                                                 String techniqueId,
                                                                 String authorizationHeader,
                                                                 String bladeAuthHeader) {
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(scan.dto().projectId());
        ArtifactDescriptor artifact = host.store.artifact(project, scan.dto().artifactDigest());
        if (artifact == null) {
            throw new ControlPlaneHttpSupport.ApiException(409, "SCAN_SCOPE_INVALID", "scan artifact is not registered for project");
        }
        // WAR/CLASS 永不宿主执行。Boot Main-Class 在 worker 注册时复检。
        if (artifact.type() == ArtifactType.CLASS) {
            throw new ControlPlaneHttpSupport.ApiException(409, RunProfile.MODE_CLASS_STATIC_ONLY,
                    "CLASS artifacts remain static-only; dynamic execution is disabled");
        }
        if (artifact.type() == ArtifactType.WAR) {
            throw new ControlPlaneHttpSupport.ApiException(409, RunProfile.MODE_NO_RUN_PROFILE,
                    "WAR dynamic requires a complete run profile; silent host execution is forbidden");
        }
        if (artifact.type() != ArtifactType.JAR) {
            throw new ControlPlaneHttpSupport.ApiException(409, "JAR_REQUIRED",
                    "Docker dynamic execution currently requires a JAR");
        }
        ProbePlanService.ProbePlan plan = buildProbePlan(scan, null, preferredEntryId, candidateInputs, maxRequests,
                techniqueId, authorizationHeader, bladeAuthHeader, artifact.normalizedPath());
        if (plan.primary() == null) {
            throw new ControlPlaneHttpSupport.ApiException(409, "TARGET_ENTRY_NOT_IN_SCAN",
                    "the scan has no entrypoint to observe");
        }
        int planBytes = ExternalArtifactTaskExecutor.probePlanUtf8Bytes(plan.probes());
        if (planBytes <= 0 || planBytes > ProbePlanService.MAX_PROBE_PLAN_UPLOAD_BYTES) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PROBE_PLAN_TOO_LARGE",
                    "probe plan serialized size exceeds sandbox upload budget ("
                            + planBytes + " > " + ProbePlanService.MAX_PROBE_PLAN_UPLOAD_BYTES
                            + " bytes); lower maxRequests or shrink auth header material");
        }
        host.unreachedDynamicPaths.put(scanId, plan.unreachedPaths());
        host.scanExpandedProbes.put(scanId, List.copyOf(plan.probes()));
        String taskId = "task-dynamic-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        ResourceBudget budget = dynamicBudgetForArtifact(artifact, plan.probes().size());
        WorkerTaskSpec spec = new WorkerTaskSpec(
                WorkerControlPlaneApi.CONTRACT_VERSION,
                scan.dto().projectId(),
                scan.dto().artifactDigest(),
                scanId,
                taskId,
                plan.primary().id(),
                true,
                budget,
                NetworkPolicy.denyAll(),
                WorkerCapability.TRUSTED_DOCKER);
        host.dynamicProbePlans.put(taskId, plan);
        TaskSnapshot snapshot;
        try {
            snapshot = host.workerApi.enqueueFromControlPlane(spec,
                    "pipeline-dynamic-" + UUID.randomUUID().toString().replace("-", ""));
        } catch (RuntimeException failure) {
            host.dynamicProbePlans.remove(taskId, plan);
            throw failure;
        }
        List<String> boundedInputs = candidateInputs == null ? List.of()
                : candidateInputs.stream().filter(Objects::nonNull).limit(16).toList();
        String inputsJson = JsonCodec.stringify(boundedInputs);
        // V011 存储有界 probe-input 元数据（CHECK max_requests 1..8）。
        // V026 亦存储编译后的 plan payload，使 startup restore 跳过 harvest。
        int storedMaxRequests = Math.max(1, Math.min(8, maxRequests));
        String payloadJson = ProbePlanService.serializePlanPayload(plan);
        host.store.persistProbePlan(new SQLiteControlPlanePersistence.ProbePlanData(
                taskId, scan.dto().projectId(), scan.dto().artifactDigest(), scanId,
                plan.primary().id(), inputsJson, storedMaxRequests,
                probePlanHash(scanId, plan.primary().id(), inputsJson, storedMaxRequests),
                Instant.now(host.clock).toString(), payloadJson));
        host.store.auditChange(scan.dto().projectId(), actorId, "dynamic-task.enqueue",
                "worker-task", taskId,
                "{\"capability\":\"TRUSTED_DOCKER\",\"networkMode\":\"DENY\",\"source\":\"PIPELINE\","
                        + "\"probeCount\":" + plan.probes().size()
                        + ",\"unreachedCount\":" + plan.unreachedPaths().size() + "}",
                Instant.now(host.clock).toString());
        return snapshot;
    }
    static ResourceBudget dynamicBudgetForArtifact(ArtifactDescriptor artifact, int probeCount) {
        long size = Math.max(0L, artifact.sizeBytes());
        int probes = Math.max(1, Math.min(ProbePlanService.MAX_DYNAMIC_PROBES, probeCount));
        // 冷启动 + 并行 loopback probe 波次（快 800ms）加有界慢重试（最多 128 × 2000ms）。
        // 为 MOCK 依赖 hang 保留余量。
        long baseWall = size >= 80L * 1024 * 1024 ? 420 : size >= 20L * 1024 * 1024 ? 300 : 180;
        long probeWaves = (probes + 7L) / 8L;
        long slowRetryCap = Math.min(128L, probes);
        long slowWaves = (slowRetryCap + 7L) / 8L;
        long wallSeconds = Math.min(3_600L,
                Math.max(baseWall, baseWall + probeWaves * 2L + slowWaves * 4L + 90L));
        long memoryBytes = size >= 80L * 1024 * 1024
                ? 3L * 1024 * 1024 * 1024 : ControlPlaneHttpLimits.DEFAULT_MEMORY_BYTES;
        // 为 agent 事件及每个 probe 一条 APPLICATION_REPORTED HTTP 行保留空间。
        long traceBytes = Math.min(16L * 1024 * 1024,
                Math.max(size >= 20L * 1024 * 1024 ? 4L * 1024 * 1024 : 512L * 1024,
                        512L * 1024 + probes * 2_048L));
        return new ResourceBudget(wallSeconds, wallSeconds * 1_000L, memoryBytes,
                64L * 1024 * 1024, traceBytes);
    }
    public ExternalArtifactTaskExecutor.ArtifactRegistration requireLocalArtifact(TaskScope scope) {
        Objects.requireNonNull(scope, "scope");
        ControlPlaneStore.ScanRecord scan = host.store.requireScan(scope.scanId());
        if (!scan.dto().projectId().equals(scope.projectId())
                || !scan.dto().artifactDigest().equals(scope.artifactDigest())) {
            throw new SecurityException("worker task scope does not match the persisted scan");
        }
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(scope.projectId());
        ArtifactDescriptor artifact = host.store.artifact(project, scope.artifactDigest());
        if (artifact == null) throw new SecurityException("worker artifact is not registered");
        host.artifactRegistry.verifyUnchanged(artifact);
        Path path = artifact.normalizedPath().toAbsolutePath().normalize();
        Path managedRoot = host.artifactRegistry.allowedRoot().resolve(".veyrion")
                .resolve("artifacts").resolve("sha256").toAbsolutePath().normalize();
        if (!path.startsWith(managedRoot)
                || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(path)
                || !path.getFileName().toString().matches(scope.artifactDigest() + "\\.jar")) {
            throw new SecurityException("dynamic execution requires the managed content-addressed JAR copy");
        }
        if (!hasExecutableMainClass(path)) {
            throw new SecurityException("registered JAR has no executable Main-Class");
        }
        ProbePlanService.ProbePlan plan = host.dynamicProbePlans.getOrDefault(scope.taskId(), buildProbePlan(scan, scope.taskId()));
        if (plan.primary() == null) {
            throw new SecurityException("scan has no bounded HTTP probe target");
        }
        host.unreachedDynamicPaths.put(scope.scanId(), plan.unreachedPaths());
        host.scanExpandedProbes.put(scope.scanId(), List.copyOf(plan.probes()));
        ApiDtos.EntryDto entry = plan.primary();
        // 优先 scan 入口间共用 app 包，以便 Service/Util/Repository 跳转
        // 在 FORCED 下被插桩（不仅 primary entry 的 leaf .controller 包）。
        String classPrefix = com.aq.jvmsentinel.worker.InstrumentationClassPrefix.resolve(
                entry, scan.dto().entries());
        ExternalArtifactTaskExecutor.ProbeTarget primaryProbe = ProbePlanService.probeTargetFor(entry);
        return new ExternalArtifactTaskExecutor.ArtifactRegistration(
                scope.projectId(), scope.artifactDigest(), path, artifact.sizeBytes(), true,
                primaryProbe.method(), primaryProbe.route(), classPrefix, plan.probes(),
                resolveWorldPackDependencyMode(plan.probes()).name());
    }

    /**
     * 为多 probe Docker task 解析单一 JVM World Pack 依赖模式。
     * 主注册始终为 exploration 阶段（{@code MOCK_CONTINUE}）；
     * confirmation（{@code OBSERVE_FAIL}）为后续分阶段 World Pack 绑定 — 永不
     * 由 AI/前端覆盖，也永不按 DB 厂商分支。
     */
    WorldPackDependencyMode resolveWorldPackDependencyMode(
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes) {
        List<PostureExperimentCompiler.CompiledPostureExperiment> plans = new ArrayList<>();
        if (probes != null) {
            for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
                if (probe == null || probe.experimentPlanId() == null || probe.experimentPlanId().isBlank()) {
                    continue;
                }
                PostureExperimentCompiler.CompiledPostureExperiment plan =
                        host.store.postureExperiment(probe.experimentPlanId());
                if (plan != null) {
                    plans.add(plan);
                }
            }
        }
        return WorldPackPlanner.resolveRuntimeDependencyMode(
                plans, WorldPackExecutionStage.EXPLORATION);
    }

    /**
     * 从持久化 V026 载荷恢复内存 probe plan。
     * 启动时不调用 {@code buildProbePlan} / identity harvest / posture 重持久化。
     * 不完整或损坏行按行 fail-closed 跳过，而非静默重建。
     */
    void restoreProbePlans() {
        List<SQLiteControlPlanePersistence.ProbePlanData> storedPlans = host.store.loadProbePlans();
        long startedNanos = System.nanoTime();
        System.out.println("Restoring " + storedPlans.size() + " probe plans...");
        int restored = 0;
        int 跳过ped = 0;
        for (SQLiteControlPlanePersistence.ProbePlanData stored : storedPlans) {
            try {
                ControlPlaneStore.ScanRecord scan = host.store.scan(stored.scanId());
                if (scan == null || !scan.dto().projectId().equals(stored.projectId())
                        || !scan.dto().artifactDigest().equals(stored.artifactDigest())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "probe plan scope does not match scan");
                }
                TaskSnapshot task = host.workerApi.snapshots(stored.projectId(), stored.scanId()).stream()
                        .filter(value -> value.scope().taskId().equals(stored.taskId())).findFirst()
                        .orElseThrow(() -> new SQLiteControlPlanePersistence.PersistenceException(
                                "probe plan has no persistent worker task"));
                if (!task.spec().targetEntryId().equals(stored.targetEntryId())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "probe plan target does not match task");
                }
                persistedStringList(stored.candidateInputsJson());
                String expectedHash = probePlanHash(stored.scanId(), stored.targetEntryId(),
                        stored.candidateInputsJson(), stored.maxRequests());
                if (!expectedHash.equals(stored.planHash())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException("probe plan checksum mismatch");
                }
                ProbePlanService.ProbePlan plan =
                        ProbePlanService.hydrateFromStoredPayload(stored.payloadJson());
                if (plan == null) {
                    System.err.println("Skipping probe plan " + stored.taskId()
                            + ": stored payload missing (no re-harvest on startup)");
                    跳过ped++;
                    continue;
                }
                if (plan.primary() == null || !stored.targetEntryId().equals(plan.primary().id())) {
                    throw new SQLiteControlPlanePersistence.PersistenceException(
                            "probe plan payload primary does not match target entry");
                }
                host.dynamicProbePlans.put(stored.taskId(), plan);
                host.unreachedDynamicPaths.put(stored.scanId(), plan.unreachedPaths());
                host.scanExpandedProbes.put(stored.scanId(), List.copyOf(plan.probes()));
                restored++;
            } catch (RuntimeException failure) {
                System.err.println("Skipping probe plan " + stored.taskId() + ": " + failure.getMessage());
                跳过ped++;
            }
        }
        double seconds = (System.nanoTime() - startedNanos) / 1_000_000_000.0;
        System.out.println("Restored " + restored + " probe plans in "
                + String.format(Locale.ROOT, "%.2f", seconds) + "s"
                + (跳过ped == 0 ? "" : " (跳过ped " + 跳过ped + ")"));
    }

    /** 包可见，供恢复验收测试使用。 */
    ProbePlanService.ProbePlan restoredDynamicProbePlan(String taskId) {
        return host.dynamicProbePlans.get(taskId);
    }
    static List<String> persistedStringList(String json) {
        Object value;
        try {
            value = JsonCodec.parse(json);
        } catch (IllegalArgumentException malformed) {
            throw new SQLiteControlPlanePersistence.PersistenceException("probe plan inputs are malformed", malformed);
        }
        if (!(value instanceof List<?> list) || list.size() > 16) {
            throw new SQLiteControlPlanePersistence.PersistenceException("probe plan input limit exceeded");
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String text) || text.length() > 1024) {
                throw new SQLiteControlPlanePersistence.PersistenceException("probe plan input is invalid");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }
    static String probePlanHash(String scanId, String targetEntryId,
                                        String inputsJson, int maxRequests) {
        return ControlPlaneHttpSupport.payloadHash(scanId + "\n" + targetEntryId + "\n" + inputsJson + "\n"
                + Math.max(1, Math.min(8, maxRequests)));
    }
    ProbePlanService.ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint) {
        return host.probePlanService.buildProbePlan(scan, taskIdHint);
    }

    ProbePlanService.ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId) {
        return host.probePlanService.buildProbePlan(scan, taskIdHint, preferredEntryId);
    }

    ProbePlanService.ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId, List<String> candidateInputs,
                                     int requestedMaxRequests) {
        return host.probePlanService.buildProbePlan(scan, taskIdHint, preferredEntryId, candidateInputs,
                requestedMaxRequests);
    }

    ProbePlanService.ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId, List<String> candidateInputs,
                                     int requestedMaxRequests, String techniqueId,
                                     String authorizationHeader, Path artifactPath) {
        return host.probePlanService.buildProbePlan(scan, taskIdHint, preferredEntryId, candidateInputs,
                requestedMaxRequests, techniqueId, authorizationHeader, artifactPath);
    }

    ProbePlanService.ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId, List<String> candidateInputs,
                                     int requestedMaxRequests, String techniqueId,
                                     String authorizationHeader, String bladeAuthHeader,
                                     Path artifactPath) {
        try {
            return host.probePlanService.buildProbePlan(scan, taskIdHint, preferredEntryId, candidateInputs,
                    requestedMaxRequests, techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
        } catch (ProbePlanService.TargetEntryNotInScanException missing) {
            throw new ControlPlaneHttpSupport.ApiException(409, "TARGET_ENTRY_NOT_IN_SCAN", missing.getMessage());
        }
    }

    /** 包可见，供 MISSING_AUTH / AI PoC 物化验收测试使用。 */
    public static ProbePlanService.AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, Path artifactPath) {
        return ProbePlanService.materializeAiPocAuth(techniqueId, authorizationHeader, artifactPath);
    }

    /** 包可见，供 MISSING_AUTH / AI PoC 物化验收测试使用。 */

    public static ProbePlanService.AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, String bladeAuthHeader, Path artifactPath) {
        return ProbePlanService.materializeAiPocAuth(
                techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
    }

    /** 包可见门面，供验收测试使用。 */
    static List<ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            Path artifactPath,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        return ProbePlanService.expandProbesByIdentityTracks(artifactPath, httpEntries, base, maxProbes);
    }
    static boolean hasExecutableMainClass(Path path) {
        try (JarFile jar = new JarFile(path.toFile(), false)) {
            return jar.getManifest() != null
                    && jar.getManifest().getMainAttributes().getValue("Main-Class") != null;
        } catch (IOException invalidJar) {
            throw new SecurityException("registered JAR manifest could not be read", invalidJar);
        }
    }
}

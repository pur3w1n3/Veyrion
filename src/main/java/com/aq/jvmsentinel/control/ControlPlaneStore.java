package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.analysis.experiment.DefaultExperimentPlanFactory;
import com.aq.jvmsentinel.analysis.experiment.PathTraceEvidenceGraphDelta;
import com.aq.jvmsentinel.analysis.experiment.PathTraceObservationBridge;
import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.analysis.experiment.RuntimeObservationProjector;
import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentGate;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.domain.experiment.RuntimeObservation;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.ir.ProgramNode;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.security.ProviderSecretCipher;
import com.aq.jvmsentinel.security.RootKeyStore;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.aq.jvmsentinel.worker.HypothesisExperimentPlanValidator;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceChunk;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Bounded Control Plane store with injectable in-memory or SQLite persistence.
 *
 * <p>The no-argument constructor deliberately remains process-local for unit
 * and fixture tests. Use {@link #sqlite(Path, Path)} for restart-safe local
 * persistence.</p>
 */
public class ControlPlaneStore {
    private static final int MAX_PROJECTS = 10_000;
    private static final int MAX_ARTIFACTS_PER_PROJECT = 1_000;
    private static final int MAX_SCANS = 20_000;
    private static final int MAX_EVIDENCE = 100_000;
    private static final int MAX_FINDINGS = 100_000;

    private final Map<String, ProjectRecord> projects = new ConcurrentHashMap<>();
    private final Map<String, ScanRecord> scans = new ConcurrentHashMap<>();
    private final Map<String, ApiDtos.FindingDto> findings = new ConcurrentHashMap<>();
    private final Map<String, ApiDtos.EvidenceDto> evidence = new ConcurrentHashMap<>();
    private final Map<String, ApiDtos.AttackChainDto> chains = new ConcurrentHashMap<>();
    private final Map<String, StaticFactSnapshot> staticFacts = new ConcurrentHashMap<>();
    private final Map<String, List<SecurityHypothesis>> hypothesesByScan = new ConcurrentHashMap<>();
    private final Map<String, SecurityHypothesis> hypothesesById = new ConcurrentHashMap<>();
    /** Scoped index permits identical hypothesis ids in different scans without cross-linking. */
    private final Map<String, SecurityHypothesis> hypothesesByScopedId = new ConcurrentHashMap<>();
    /**
     * P1-08: process-local LanguageAnalyzer / Test Analyzer ProgramNode overlays.
     * Not elevated to FACT authority beyond producer provenance on each node.
     */
    private final Map<String, List<ProgramNode>> analyzerProgramNodesByScan = new ConcurrentHashMap<>();
    /** P1-06: hypothesis-bound experiment plans (process-local; experimentPlanId identity preserved). */
    private final Map<String, List<HypothesisExperimentPlan>> hypothesisPlansByScan = new ConcurrentHashMap<>();
    private final Map<String, HypothesisExperimentPlan> hypothesisPlansById = new ConcurrentHashMap<>();
    /** experimentPlanId / pathRunId → probe binding for hypothesisId+planKind. */
    private final Map<String, ProbeHypothesisBinding> probeHypothesisBindings = new ConcurrentHashMap<>();
    /** P0-21: server-compiled posture experiment plans keyed by experimentPlanId. */
    private final Map<String, PostureExperimentCompiler.CompiledPostureExperiment> postureExperimentsById =
            new ConcurrentHashMap<>();
    /** pathRunId → latest PathTrace payload for API enrichment. */
    private final Map<String, PathTrace> pathTracesByPathRunId = new ConcurrentHashMap<>();
    /** Latest PathTrace → Evidence Graph delta wire maps keyed by pathTraceId. */
    private final Map<String, Map<String, Object>> pathTraceEvidenceDeltas = new ConcurrentHashMap<>();
    private final List<ObservationKindRef> pendingIncrementalSubjects = new ArrayList<>();
    private final SQLiteControlPlanePersistence persistence;
    private final SecretKey rootKey;
    private final ProviderSecretCipher providerCipher;

    public ControlPlaneStore() {
        this.persistence = null;
        this.rootKey = null;
        this.providerCipher = null;
    }

    private ControlPlaneStore(Path databasePath, Path allowedRoot) {
        this.persistence = new SQLiteControlPlanePersistence(databasePath, allowedRoot);
        try {
            Path keyPath = this.persistence.databasePath().getParent()
                    .resolve("security").resolve("provider-root.key");
            this.rootKey = new RootKeyStore(keyPath).loadOrCreate(
                    new RootKeyStore.DeploymentPolicy(true, false)).key();
        } catch (IOException failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    "provider root key could not be loaded", failure);
        }
        this.providerCipher = new ProviderSecretCipher();
        restore(this.persistence.load());
    }

    public static ControlPlaneStore sqlite(Path databasePath, Path allowedRoot) {
        return new ControlPlaneStore(databasePath, allowedRoot);
    }

    public String persistenceMode() {
        return persistence == null ? "IN_MEMORY_MVP" : "SQLITE";
    }

    public List<SQLiteControlPlanePersistence.IdempotencyData> loadIdempotency() {
        return persistence == null ? List.of() : persistence.loadIdempotency();
    }

    public SQLiteControlPlanePersistence.IdempotencyData persistIdempotency(
            SQLiteControlPlanePersistence.IdempotencyData candidate) {
        if (persistence == null) return candidate;
        return persistence.putIdempotency(candidate);
    }

    public List<SQLiteControlPlanePersistence.PipelineRunData> loadPipelineRuns() {
        return persistence == null ? List.of() : persistence.loadPipelineRuns();
    }

    public void persistPipelineRun(SQLiteControlPlanePersistence.PipelineRunData run) {
        if (persistence != null) persistence.savePipelineRun(run);
    }

    /**
     * Persistent CAS for pipeline cursor advancement. In-memory stores always accept the
     * write so unit tests without SQLite still exercise coordinator identity matching.
     */
    public boolean compareAndAdvancePipelineRun(
            SQLiteControlPlanePersistence.PipelineRunData expected,
            SQLiteControlPlanePersistence.PipelineRunData next) {
        if (persistence == null) {
            persistPipelineRun(next);
            return true;
        }
        return persistence.compareAndAdvancePipelineRun(expected, next);
    }

    public List<SQLiteControlPlanePersistence.ProbePlanData> loadProbePlans() {
        return persistence == null ? List.of() : persistence.loadProbePlans();
    }

    public void persistProbePlan(SQLiteControlPlanePersistence.ProbePlanData plan) {
        if (persistence != null) persistence.saveProbePlan(plan);
    }

    public List<SQLiteControlPlanePersistence.ExperimentPlanData> loadExperimentPlans() {
        return persistence == null ? List.of() : persistence.loadExperimentPlans();
    }

    public List<SQLiteControlPlanePersistence.ExperimentPlanData> loadExperimentPlansForScan(String scanId) {
        return persistence == null ? List.of() : persistence.loadExperimentPlansForScan(scanId);
    }

    public void persistExperimentPlan(SQLiteControlPlanePersistence.ExperimentPlanData plan) {
        if (persistence != null) persistence.saveExperimentPlan(plan);
    }

    public void persistTracePlan(SQLiteControlPlanePersistence.TracePlanData plan) {
        if (persistence != null) persistence.saveTracePlan(plan);
    }

    public List<SQLiteControlPlanePersistence.TracePlanData> loadTracePlansForScan(String scanId) {
        return persistence == null ? List.of() : persistence.loadTracePlansForScan(scanId);
    }

    public void persistWorldPack(SQLiteControlPlanePersistence.WorldPackData pack) {
        if (persistence != null) persistence.saveWorldPack(pack);
    }

    public List<SQLiteControlPlanePersistence.WorldPackData> loadWorldPacksForScan(String scanId) {
        return persistence == null ? List.of() : persistence.loadWorldPacksForScan(scanId);
    }

    public void replacePathTracesForTask(String projectId, String artifactDigest, String scanId,
                                         String taskId, List<SQLiteControlPlanePersistence.PathTraceData> traces,
                                         String createdAt) {
        if (persistence != null) {
            persistence.replacePathTracesForTask(projectId, artifactDigest, scanId, taskId, traces, createdAt);
        }
        if (traces != null) {
            for (SQLiteControlPlanePersistence.PathTraceData row : traces) {
                if (row == null || row.pathRunId() == null || row.pathRunId().isBlank()) continue;
                try {
                    PathTrace trace = PathTrace.fromMap(JsonCodec.parseObject(row.payloadJson()));
                    pathTracesByPathRunId.put(row.pathRunId(), trace);
                } catch (RuntimeException ignored) {
                    // Malformed trace payloads must not break task completion.
                }
            }
            applyPathTraceEvidenceGraphDelta(scanId, traces);
        }
    }

    private void applyPathTraceEvidenceGraphDelta(
            String scanId, List<SQLiteControlPlanePersistence.PathTraceData> traces) {
        if (scanId == null || scanId.isBlank() || traces == null || traces.isEmpty()) {
            return;
        }
        Optional<StaticFactSnapshot> facts = staticFacts(scanId);
        if (facts.isEmpty() || !facts.get().hasPersistedEvidenceGraph()) {
            return;
        }
        EvidenceGraph base = facts.get().evidenceGraph().orElse(null);
        if (base == null) {
            return;
        }
        List<IrNode> extras = new ArrayList<>();
        for (SQLiteControlPlanePersistence.PathTraceData row : traces) {
            if (row == null || row.payloadJson() == null || row.payloadJson().isBlank()) {
                continue;
            }
            try {
                PathTrace trace = PathTrace.fromMap(JsonCodec.parseObject(row.payloadJson()));
                PathTraceEvidenceGraphDelta.Delta delta =
                        PathTraceEvidenceGraphDelta.fromPathTrace(trace, scanId);
                extras.addAll(delta.nodes());
                pathTraceEvidenceDeltas.put(trace.pathTraceId(),
                        PathTraceEvidenceGraphDelta.toWireMap(delta));
            } catch (RuntimeException ignored) {
                // Malformed trace must not break evidence graph merge.
            }
        }
        if (extras.isEmpty()) {
            return;
        }
        EvidenceGraph merged = EvidenceGraphMerge.withExtraNodes(base, extras);
        staticFacts.put(scanId, facts.get().withEvidenceGraph(merged));
    }

    public Map<String, Object> pathTraceEvidenceDelta(String pathTraceId) {
        if (pathTraceId == null || pathTraceId.isBlank()) {
            return Map.of();
        }
        Map<String, Object> delta = pathTraceEvidenceDeltas.get(pathTraceId);
        return delta == null ? Map.of() : Map.copyOf(delta);
    }

    public List<SQLiteControlPlanePersistence.PathTraceData> loadPathTracesForScan(
            String projectId, String artifactDigest, String scanId) {
        return persistence == null
                ? List.of()
                : persistence.loadPathTracesForScan(projectId, artifactDigest, scanId);
    }

    public PathTrace pathTraceForPathRun(String pathRunId) {
        if (pathRunId == null || pathRunId.isBlank()) return null;
        PathTrace cached = pathTracesByPathRunId.get(pathRunId);
        if (cached != null) return cached;
        return null;
    }

    public void registerPostureExperiment(PostureExperimentCompiler.CompiledPostureExperiment plan) {
        if (plan == null || plan.experimentPlanId().isBlank()) return;
        postureExperimentsById.put(plan.experimentPlanId(), plan);
    }

    public PostureExperimentCompiler.CompiledPostureExperiment postureExperiment(String experimentPlanId) {
        if (experimentPlanId == null || experimentPlanId.isBlank()) return null;
        return postureExperimentsById.get(experimentPlanId);
    }

    public Map<String, PostureExperimentCompiler.CompiledPostureExperiment> postureExperimentsForScan(String scanId) {
        if (scanId == null || scanId.isBlank()) return Map.of();
        Map<String, PostureExperimentCompiler.CompiledPostureExperiment> result = new LinkedHashMap<>();
        for (PostureExperimentCompiler.CompiledPostureExperiment plan : postureExperimentsById.values()) {
            if (plan.experimentPlanId().contains(scanId) || plan.tracePlanId().contains(scanId)) {
                result.put(plan.experimentPlanId(), plan);
            }
        }
        return Map.copyOf(result);
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForScan(String projectId, String artifactDigest, String scanId) {
        return persistence == null ? List.of() : persistence.loadPathRunsForScan(projectId, artifactDigest, scanId);
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForTask(String taskId) {
        return persistence == null ? List.of() : persistence.loadPathRunsForTask(taskId);
    }

    public void replacePathRunsForTask(String projectId, String artifactDigest, String scanId,
                                       String taskId, List<ApiDtos.PathRunDto> pathRuns, String createdAt) {
        if (persistence != null) {
            persistence.replacePathRunsForTask(projectId, artifactDigest, scanId, taskId, pathRuns, createdAt);
        }
        applyPathRunHypothesisObservations(pathRuns);
    }

    public void replacePathRunsAndTracesForTask(String projectId, String artifactDigest, String scanId,
                                                String taskId, List<ApiDtos.PathRunDto> pathRuns,
                                                List<SQLiteControlPlanePersistence.PathTraceData> traces,
                                                String createdAt) {
        replacePathTracesForTask(projectId, artifactDigest, scanId, taskId, traces, createdAt);
        replacePathRunsForTask(projectId, artifactDigest, scanId, taskId, pathRuns, createdAt);
    }

    /**
     * AUDIT_FLOW IR2: full detector suite recompute after dynamic observation / OBS feedback.
     * Merges hypotheses; never elevates finding verification. Returns merged hypothesis count.
     */
    public synchronized int recomputeDetectorsAfterObservation(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return 0;
        }
        ScanRecord scan;
        try {
            scan = requireScan(scanId);
        } catch (RuntimeException missing) {
            return 0;
        }
        Optional<StaticFactSnapshot> facts = staticFacts(scanId);
        StaticFactSnapshot snapshot = facts.orElse(
                new StaticFactSnapshot(StaticFactSnapshot.LEGACY_INCOMPLETE, List.of(), null));
        ArtifactUniverse universe = snapshot.effectiveArtifactUniverse();
        var result = com.aq.jvmsentinel.analysis.detector.AffectedDetectorRecompute.recompute(
                scanId,
                universe,
                snapshot,
                scan.dto().entries(),
                scan.dto().sinks(),
                scan.dto().dependencies(),
                scan.evidence(),
                List.of(),
                null,
                hypotheses(scanId),
                com.aq.jvmsentinel.analysis.detector.DetectorRegistry.defaults());
        if (result.ran() && !result.mergedHypotheses().isEmpty()) {
            saveHypotheses(scanId, result.mergedHypotheses(), "ir2-detector-recompute");
        }
        return result.mergedTotal();
    }

    /**
     * PATH/TRIAGE ↔ OBS loop predicate: STATIC_ONLY contrast rows remain (static hit, no pass-gate
     * PathRun). Does <em>not</em> loop solely because CANDIDATE hypotheses exist — that would
     * force full dynamic floods every audit.
     */
    public synchronized boolean hasPendingObservationLoopWork(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return false;
        }
        try {
            ScanRecord scan = requireScan(scanId);
            List<ApiDtos.PathRunDto> runs = loadPathRunsForScan(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
            var ledger = com.aq.jvmsentinel.analysis.contrast.ContrastLedger.build(
                    scan.dto().entries(),
                    scan.dto().sinks(),
                    scan.evidence(),
                    runs,
                    StaticFactSnapshot.resolveTaintPaths(staticFacts(scanId), scan.dto().sinks()));
            for (var row : ledger.rows()) {
                if (row != null && row.contrastStatus() == ContrastStatus.STATIC_ONLY) {
                    return true;
                }
            }
        } catch (RuntimeException ignored) {
            return false;
        }
        return false;
    }

    /**
     * Projects persisted PathRuns into RuntimeObservation and applies the hypothesis lifecycle gate.
     * Failed / empty projections never change lifecycle. Successful matches may move
     * {@code CANDIDATE → SUPPORTED|CONTRADICTED} only. Never elevates finding verification status.
     */
    public synchronized List<HypothesisExperimentGate.Decision> applyPathRunHypothesisObservations(
            List<ApiDtos.PathRunDto> pathRuns) {
        if (pathRuns == null || pathRuns.isEmpty()) {
            return List.of();
        }
        List<HypothesisExperimentGate.Decision> decisions = new ArrayList<>();
        for (ApiDtos.PathRunDto run : pathRuns) {
            if (run == null) continue;
            String planId = run.experimentPlanId();
            if (planId == null || planId.isBlank()) {
                continue;
            }
            ProbeHypothesisBinding binding = probeHypothesisBinding(planId);
            HypothesisExperimentPlan plan = hypothesisExperimentPlan(planId);
            if (plan == null || !run.scanId().equals(plan.scanId())
                    || !EntryRefResolver.resolve(requireScan(run.scanId()).dto().entries(), run.entrypointRef()).resolved()) {
                continue;
            }
            String hypothesisId = binding != null
                    ? binding.hypothesisId()
                    : (plan != null ? plan.hypothesisId() : "");
            ExperimentPlanKind planKind = binding != null
                    ? binding.planKind()
                    : (plan != null ? plan.planKind() : null);
            if (hypothesisId.isBlank() || planKind == null) {
                continue;
            }
            RuntimeObservation observation = projectPathRunObservation(run, hypothesisId, planKind);
            PathTrace trace = pathTraceForPathRun(run.pathRunId());
            if (trace != null && !trace.legacyIncomplete()) {
                observation = PathTraceObservationBridge.fromPathTrace(
                        trace, hypothesisId, planKind, run.evidenceRefs());
            }
            decisions.add(applyHypothesisObservation(planId, observation));
        }
        return List.copyOf(decisions);
    }

    private static RuntimeObservation projectPathRunObservation(ApiDtos.PathRunDto run,
                                                                String hypothesisId,
                                                                ExperimentPlanKind planKind) {
        if (!isSuccessfulPathRunProjection(run)) {
            String reason = run.stopReason() == null || run.stopReason().isBlank()
                    ? "FAILED" : run.stopReason();
            return RuntimeObservationProjector.emptyOrFailed(hypothesisId, planKind, reason);
        }
        boolean effectHit = run.sqlEvents() != null && !run.sqlEvents().isEmpty();
        return RuntimeObservationProjector.fromPathRunProjection(
                run.pathRunId(),
                hypothesisId,
                planKind,
                run.outcomeClass(),
                run.entryHit(),
                effectHit,
                null,
                run.evidenceRefs(),
                true);
    }

    private static boolean isSuccessfulPathRunProjection(ApiDtos.PathRunDto run) {
        if (run.pathRunId() == null || run.pathRunId().isBlank()) {
            return false;
        }
        if (run.evidenceRefs() == null || run.evidenceRefs().isEmpty()) {
            return false;
        }
        String status = run.verificationStatus() == null
                ? "" : run.verificationStatus().trim().toUpperCase(java.util.Locale.ROOT);
        if ("FAILED".equals(status) || "BUSY".equals(status) || "CANCELLED".equals(status)
                || ApiDtos.UNREACHED.equals(status)) {
            return false;
        }
        String stop = run.stopReason() == null ? "" : run.stopReason().trim().toUpperCase(java.util.Locale.ROOT);
        return !"FAILED".equals(stop) && !"PROJECTION_FAILED".equals(stop) && !"EMPTY".equals(stop);
    }

    public SQLiteControlPlanePersistence.WorkerState loadWorkerState() {
        return persistence == null ? SQLiteControlPlanePersistence.WorkerState.empty() : persistence.loadWorkerState();
    }

    public void persistWorkerTask(TaskSnapshot snapshot) {
        if (persistence != null) persistence.persistWorkerTask(snapshot);
    }

    public void persistWorkerTrace(String idempotencyKey, TraceChunk chunk) {
        if (persistence != null) persistence.persistWorkerTrace(idempotencyKey, chunk);
    }

    public ArtifactUploadService.UploadPersistence artifactUploadPersistence() {
        if (persistence == null) return ArtifactUploadService.UploadPersistence.NONE;
        return new ArtifactUploadService.UploadPersistence() {
            @Override
            public List<ArtifactUploadService.PersistedSession> load() {
                return persistence.loadArtifactUploads();
            }

            @Override
            public void save(ArtifactUploadService.PersistedSession session) {
                persistence.persistArtifactUpload(session);
            }

            @Override
            public void delete(String uploadId) {
                persistence.deleteArtifactUpload(uploadId);
            }
        };
    }

    public List<VersionedEvent> loadSseEvents() {
        return persistence == null ? List.of() : persistence.loadSseEvents();
    }

    public void persistSseEvent(String scanId, VersionedEvent event) {
        if (persistence != null) persistence.persistSseEvent(scanId, event);
    }

    public void bootstrapOperator(String token, String now) {
        requirePersistentManagement();
        persistence.bootstrapOperator(token, now);
    }

    public SQLiteControlPlanePersistence.OperatorData authenticateOperator(String token) {
        return persistence == null ? null : persistence.authenticateOperator(token).orElse(null);
    }

    public List<SQLiteControlPlanePersistence.OperatorData> operators() {
        requirePersistentManagement();
        return persistence.listOperators();
    }

    public CreatedOperator createOperator(String username, OperatorRole role, String actorId, String now) {
        requirePersistentManagement();
        validateManagementText(username, "username");
        Objects.requireNonNull(role, "role");
        String id = "operator-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String pat = "vyr_pat_" + Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        Arrays.fill(random, (byte) 0);
        SQLiteControlPlanePersistence.OperatorData operator =
                new SQLiteControlPlanePersistence.OperatorData(id, username, role, now, now);
        persistence.createOperator(operator, sha256(pat), actorId);
        return new CreatedOperator(operator, pat);
    }

    public void updateOperator(String operatorId, OperatorRole role, boolean revokeTokens,
                               String actorId, String now) {
        requirePersistentManagement();
        if (persistence.listOperators().stream().noneMatch(value -> value.operatorId().equals(operatorId))) {
            throw new MissingRecordException("operator not found");
        }
        persistence.updateOperator(operatorId, Objects.requireNonNull(role, "role"),
                revokeTokens, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.ProviderData> providers() {
        requirePersistentManagement();
        return persistence.listProviders();
    }

    public SQLiteControlPlanePersistence.ProviderData requireProvider(String providerId) {
        requirePersistentManagement();
        return persistence.findProvider(providerId)
                .orElseThrow(() -> new MissingRecordException("provider not found"));
    }

    public SQLiteControlPlanePersistence.ProviderData saveProvider(
            String providerId, String name, ProviderContracts.ProviderKind kind, String baseUrl,
            String model, boolean enabled, String apiKey, String actorId, String now) {
        requirePersistentManagement();
        validateId(providerId, "providerId");
        validateManagementText(name, "name");
        URI endpoint;
        try {
            endpoint = ProviderContracts.validatedEndpoint(URI.create(baseUrl), kind);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("provider baseUrl is invalid");
        }
        SQLiteControlPlanePersistence.ProviderData existing =
                persistence.findProvider(providerId).orElse(null);
        String createdAt = existing == null ? now : existing.createdAt();
        boolean hasCredential = apiKey != null || existing != null && existing.hasCredential();
        SQLiteControlPlanePersistence.ProviderData provider =
                new SQLiteControlPlanePersistence.ProviderData(providerId, name, kind,
                        endpoint.toString(), model, enabled, createdAt, now, hasCredential);
        SQLiteControlPlanePersistence.StoredSecret secret = null;
        if (apiKey != null) {
            validateManagementText(apiKey, "apiKey");
            SQLiteControlPlanePersistence.StoredSecret existingSecret =
                    persistence.findProviderSecret(providerId).orElse(null);
            long version = existingSecret == null ? 1L
                    : existingSecret.scope().credentialVersion() + 1;
            String credentialId = existingSecret == null
                    ? "provider-api-key-" + sha256(providerId).substring(0, 32)
                    : existingSecret.scope().credentialId();
            ProviderSecretCipher.SecretScope scope = new ProviderSecretCipher.SecretScope(
                    SQLiteControlPlanePersistence.LOCAL_WORKSPACE, providerId,
                    credentialId, version);
            byte[] plaintext = apiKey.getBytes(StandardCharsets.UTF_8);
            try {
                secret = new SQLiteControlPlanePersistence.StoredSecret(
                        scope, providerCipher.encrypt(rootKey, scope, plaintext));
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
        persistence.saveProvider(provider, secret, actorId);
        return requireProvider(providerId);
    }

    public void verifyProviderCredential(String providerId) {
        requirePersistentManagement();
        SQLiteControlPlanePersistence.StoredSecret stored = persistence.findProviderSecret(providerId)
                .orElseThrow(() -> new MissingRecordException("provider credential not found"));
        byte[] plaintext = providerCipher.decrypt(rootKey, stored.scope(), stored.encrypted());
        Arrays.fill(plaintext, (byte) 0);
    }

    /**
     * Decrypts a provider credential only for the duration of the supplied operation.
     * The operation must not retain the array; this method clears it on every exit path.
     */
    public <T> T withProviderCredential(String providerId, Function<byte[], T> operation) {
        requirePersistentManagement();
        Objects.requireNonNull(operation, "operation");
        SQLiteControlPlanePersistence.StoredSecret stored = persistence.findProviderSecret(providerId)
                .orElseThrow(() -> new MissingRecordException("provider credential not found"));
        byte[] plaintext = providerCipher.decrypt(rootKey, stored.scope(), stored.encrypted());
        try {
            return operation.apply(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    public void deleteProvider(String providerId, String actorId, String now) {
        requireProvider(providerId);
        persistence.deleteProvider(providerId, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.RoleBindingData> roleBindings(String projectId) {
        requireProject(projectId);
        requirePersistentManagement();
        return persistence.listRoleBindings(projectId);
    }

    public SQLiteControlPlanePersistence.RoleBindingData saveRoleBinding(
            String projectId, AgentRole role, String providerId, String model, String actorId, String now) {
        return saveRoleBinding(projectId, role, providerId, model, null, null, actorId, now);
    }

    public SQLiteControlPlanePersistence.RoleBindingData saveRoleBinding(
            String projectId, AgentRole role, String providerId, String model,
            String promptZh, String promptEn, String actorId, String now) {
        requireProject(projectId);
        requireProvider(providerId);
        validateManagementText(model, "model");
        validatePrompt(promptZh, "promptZh");
        validatePrompt(promptEn, "promptEn");
        SQLiteControlPlanePersistence.RoleBindingData binding =
                new SQLiteControlPlanePersistence.RoleBindingData(projectId, role, providerId, model, now,
                        blankToNull(promptZh), blankToNull(promptEn));
        persistence.saveRoleBinding(binding, actorId);
        return binding;
    }

    private static void validatePrompt(String value, String name) {
        if (value != null && (value.length() > 16_384 || value.indexOf('\0') >= 0
                || value.chars().anyMatch(ch -> Character.isISOControl(ch)
                && ch != '\n' && ch != '\r' && ch != '\t'))) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    public void deleteRoleBinding(String projectId, AgentRole role, String actorId, String now) {
        requireProject(projectId);
        if (persistence.findRoleBinding(projectId, role).isEmpty()) {
            throw new MissingRecordException("role assignment not found");
        }
        persistence.deleteRoleBinding(projectId, role, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, boolean authorized, String actorId, String now) {
        return createAiJob(projectId, requestedRole, null, AiOutputLanguage.ZH_CN,
                authorized, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, String requestedScanId,
            boolean authorized, String actorId, String now) {
        return createAiJob(projectId, requestedRole, requestedScanId, AiOutputLanguage.ZH_CN,
                authorized, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, String requestedScanId,
            AiOutputLanguage outputLanguage, boolean authorized, String actorId, String now) {
        requireProject(projectId);
        requirePersistentManagement();
        Objects.requireNonNull(outputLanguage, "outputLanguage");
        if (!authorized) throw new SecurityException("explicit AI job authorization is required");
        String jobId = "ai-job-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        var binding = persistence.findRoleBinding(projectId, requestedRole).orElse(null);
        var provider = binding == null ? null : persistence.findProvider(binding.providerId()).orElse(null);
        ProjectRecord project = requireProject(projectId);
        ScanRecord scan = requestedScanId == null
                ? project.latestScanId() == null ? null : scan(project.latestScanId())
                : scan(requestedScanId);
        if (scan != null && !projectId.equals(scan.dto().projectId())) {
            throw new SecurityException("AI job scan does not belong to project");
        }
        String reason = null;
        if (binding == null) reason = "ROLE_BINDING_REQUIRED";
        else if (provider == null) reason = "PROVIDER_NOT_FOUND";
        else if (!provider.enabled()) reason = "PROVIDER_DISABLED";
        else if (!provider.hasCredential()) reason = "PROVIDER_CREDENTIAL_REQUIRED";
        else if (provider.kind() != ProviderContracts.ProviderKind.OPENAI_CHAT
                && provider.kind() != ProviderContracts.ProviderKind.ANTHROPIC_MESSAGES
                && provider.kind() != ProviderContracts.ProviderKind.OPENAI_COMPATIBLE) {
            reason = "PROVIDER_PROTOCOL_UNSUPPORTED";
        } else if (scan == null) reason = "SCAN_REQUIRED";
        String status = reason == null ? "QUEUED" : "BLOCKED";
        Map<String, Object> stage = new LinkedHashMap<>();
        stage.put("schemaVersion", 1);
        stage.put("role", requestedRole.name());
        stage.put("status", status);
        if (reason != null) stage.put("errorCode", reason);
        if (binding != null) {
            stage.put("providerId", binding.providerId());
            stage.put("model", binding.model());
        }
        List<Map<String, Object>> stages = List.of(stage);
        String stagesJson = JsonCodec.stringify(stages);
        Map<String, Object> policySnapshot = new LinkedHashMap<>();
        policySnapshot.put("schemaVersion", 1);
        policySnapshot.put("maxRounds", 5);
        policySnapshot.put("maxToolCalls", 16);
        policySnapshot.put("maxOutputTokens", 2048);
        policySnapshot.put("maxResponseBytes", 1_048_576);
        policySnapshot.put("requestTimeoutSeconds", 120);
        policySnapshot.put("parallelToolCalls", false);
        policySnapshot.put("outputLanguage", outputLanguage.name());
        policySnapshot.put("outputFormat", "MARKDOWN");
        if (binding != null) {
            policySnapshot.put("providerId", binding.providerId());
            policySnapshot.put("model", binding.model());
            policySnapshot.put("roleBindingUpdatedAt", binding.updatedAt());
            if (binding.promptZh() != null) policySnapshot.put("promptZh", binding.promptZh());
            if (binding.promptEn() != null) policySnapshot.put("promptEn", binding.promptEn());
        }
        if (provider != null) {
            policySnapshot.put("providerKind", provider.kind().name());
            policySnapshot.put("providerBaseUrl", provider.baseUrl());
            policySnapshot.put("providerConfigurationUpdatedAt", provider.updatedAt());
        }
        String policy = JsonCodec.stringify(policySnapshot);
        SQLiteControlPlanePersistence.AiJobData job = new SQLiteControlPlanePersistence.AiJobData(
                jobId, SQLiteControlPlanePersistence.LOCAL_WORKSPACE, projectId,
                scan == null ? null : scan.dto().scanId(),
                scan == null ? null : scan.dto().artifactDigest(), requestedRole,
                binding == null ? null : binding.providerId(), binding == null ? null : binding.model(),
                policy, true, status, reason == null ? "QUEUED" : reason, stagesJson,
                null, 0, 0, "[]", null, now, now);
        persistence.saveAiJob(job, actorId, status.equals("QUEUED") ? "ai-job.queued" : "ai-job.blocked");
        return job;
    }

    public SQLiteControlPlanePersistence.AiJobData updateAiJob(
            SQLiteControlPlanePersistence.AiJobData existing, String status, String stopReason,
            String stagesJson, String providerRequestId, long elapsedMillis, int rounds,
            String toolSummaryJson, String conclusionJson, String actorId, String action, String now) {
        requirePersistentManagement();
        // Cancel wins at the store boundary: never resurrect CANCELLED into another status.
        SQLiteControlPlanePersistence.AiJobData latest = requireAiJob(existing.aiJobId());
        if ("CANCELLED".equals(latest.status()) && !"CANCELLED".equals(status)) {
            return latest;
        }
        SQLiteControlPlanePersistence.AiJobData updated = new SQLiteControlPlanePersistence.AiJobData(
                latest.aiJobId(), latest.workspaceId(), latest.projectId(), latest.scanId(),
                latest.artifactDigest(), latest.role(), latest.providerId(), latest.model(),
                latest.policySnapshotJson(), latest.authorized(), status, stopReason, stagesJson,
                providerRequestId, Math.max(0, elapsedMillis), Math.max(0, rounds),
                toolSummaryJson == null ? "[]" : toolSummaryJson, conclusionJson,
                latest.createdAt(), now);
        persistence.saveAiJob(updated, actorId, action);
        return updated;
    }

    public List<SQLiteControlPlanePersistence.AiJobData> aiJobs(String projectId) {
        if (projectId != null) requireProject(projectId);
        requirePersistentManagement();
        return persistence.listAiJobs(projectId);
    }

    public SQLiteControlPlanePersistence.AiJobData requireAiJob(String jobId) {
        requirePersistentManagement();
        return persistence.findAiJob(jobId).orElseThrow(() -> new MissingRecordException("AI job not found"));
    }

    public SQLiteControlPlanePersistence.AiJobEventData appendAiJobEvent(
            SQLiteControlPlanePersistence.AiJobEventData event) {
        requirePersistentManagement();
        SQLiteControlPlanePersistence.AiJobData job = requireAiJob(event.aiJobId());
        if (!job.workspaceId().equals(event.workspaceId())
                || !job.projectId().equals(event.projectId())) {
            throw new IllegalArgumentException("AI job event scope mismatch");
        }
        return persistence.appendAiJobEvent(event);
    }

    public List<SQLiteControlPlanePersistence.AiJobEventData> aiJobEvents(String jobId) {
        requireAiJob(jobId);
        return persistence.listAiJobEvents(jobId);
    }

    public SQLiteControlPlanePersistence.AiJobData cancelAiJob(String jobId, String actorId, String now) {
        SQLiteControlPlanePersistence.AiJobData existing = requireAiJob(jobId);
        if ("COMPLETED".equals(existing.status()) || "FAILED".equals(existing.status())
                || "CANCELLED".equals(existing.status()) || "BLOCKED".equals(existing.status())) {
            return existing;
        }
        return updateAiJob(existing, "CANCELLED", "USER_CANCELLED", existing.stagesJson(),
                existing.providerRequestId(), existing.elapsedMillis(), existing.rounds(),
                existing.toolSummaryJson(), null, actorId, "ai-job.cancel", now);
    }

    public void deleteAiJob(String jobId, String actorId, String now) {
        SQLiteControlPlanePersistence.AiJobData existing = requireAiJob(jobId);
        if ("QUEUED".equals(existing.status()) || "RUNNING".equals(existing.status())) {
            throw new IllegalStateException("active AI job must be cancelled before deletion");
        }
        persistence.deleteAiJob(existing, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.AuditData> auditEvents(String projectId) {
        requirePersistentManagement();
        if (projectId != null) requireProject(projectId);
        return persistence.listAudit(projectId);
    }

    public void auditChange(String projectId, String actorId, String action,
                            String targetType, String targetId, String detailsJson, String now) {
        if (persistence != null) {
            persistence.recordAudit(projectId, actorId, action, targetType, targetId, detailsJson, now);
        }
    }

    private void requirePersistentManagement() {
        if (persistence == null) throw new IllegalStateException("management configuration requires SQLite");
    }

    private static void validateManagementText(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 4096
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    public synchronized ProjectRecord createProject(String requestedId, String requestedName, String createdAt,
                                                    String actorId) {
        String id = requestedId == null || requestedId.isBlank()
                ? "project-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16)
                : requestedId;
        String name = requestedName == null || requestedName.isBlank() ? id : requestedName;
        validateId(id, "projectId");
        if (createdAt == null || createdAt.isBlank()) throw new IllegalArgumentException("createdAt is required");
        if (projects.size() >= MAX_PROJECTS) throw new StoreLimitException("project limit reached");
        ProjectRecord candidate = new ProjectRecord(id, name, "ACTIVE", createdAt, createdAt, null);
        if (projects.containsKey(id)) throw new DuplicateRecordException("project already exists");
        if (persistence != null) persistence.insertProject(id, name, candidate.status, createdAt, createdAt, actorId);
        ProjectRecord existing = projects.putIfAbsent(id, candidate);
        if (existing != null) throw new DuplicateRecordException("project already exists");
        return candidate;
    }

    public ProjectRecord requireProject(String projectId) {
        ProjectRecord result = project(projectId);
        if (result == null) throw new MissingRecordException("project not found");
        return result;
    }

    public ProjectRecord project(String projectId) {
        ProjectRecord project = projectId == null ? null : projects.get(projectId);
        return project == null || project.deleted() ? null : project;
    }

    public List<ProjectRecord> projects() {
        return projects.values().stream().filter(project -> !project.deleted())
                .sorted(Comparator.comparing(ProjectRecord::createdAt).thenComparing(ProjectRecord::projectId))
                .toList();
    }

    public synchronized ProjectRecord updateProject(String projectId, String requestedName,
                                                    String requestedStatus, String updatedAt, String actorId) {
        ProjectRecord project = requireProject(projectId);
        String name = requestedName == null ? project.name : requestedName;
        String status = requestedStatus == null ? project.status : requestedStatus.toUpperCase(java.util.Locale.ROOT);
        if (name.isBlank() || name.length() > 512) throw new IllegalArgumentException("name is invalid");
        if (!status.equals("ACTIVE") && !status.equals("ARCHIVED")) {
            throw new IllegalArgumentException("status must be ACTIVE or ARCHIVED");
        }
        if (updatedAt == null || updatedAt.isBlank()) throw new IllegalArgumentException("updatedAt is required");
        if (persistence != null) persistence.updateProject(projectId, name, status, updatedAt, actorId);
        project.name = name;
        project.status = status;
        project.updatedAt = updatedAt;
        return project;
    }

    public synchronized void softDeleteProject(String projectId, String deletedAt, String actorId) {
        ProjectRecord project = requireProject(projectId);
        if (deletedAt == null || deletedAt.isBlank()) throw new IllegalArgumentException("deletedAt is required");
        if (persistence != null) persistence.softDeleteProject(projectId, deletedAt, actorId);
        project.status = "DELETED";
        project.updatedAt = deletedAt;
        project.deletedAt = deletedAt;
    }

    public synchronized void registerArtifact(ProjectRecord project, ArtifactDescriptor descriptor,
                                              String actorId) {
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(descriptor, "descriptor");
        synchronized (project) {
            if (project.artifacts.size() >= MAX_ARTIFACTS_PER_PROJECT
                    && !project.artifacts.containsKey(descriptor.sha256())) {
                throw new StoreLimitException("artifact limit reached for project");
            }
            if (project.deleted()) throw new MissingRecordException("project not found");
            if (persistence != null) persistence.insertArtifact(project.projectId, descriptor, actorId);
            project.artifacts.put(descriptor.sha256(), descriptor);
        }
    }

    public ArtifactDescriptor artifact(ProjectRecord project, String digestOrId) {
        if (project == null || digestOrId == null) return null;
        synchronized (project) {
            ArtifactDescriptor byDigest = project.artifacts.get(digestOrId);
            if (byDigest != null) return byDigest;
            for (ArtifactDescriptor descriptor : project.artifacts.values()) {
                if (descriptor.artifactId().equals(digestOrId)) return descriptor;
            }
            return null;
        }
    }

    public List<ArtifactDescriptor> artifacts(ProjectRecord project) {
        if (project == null) return List.of();
        synchronized (project) { return List.copyOf(project.artifacts.values()); }
    }

    public synchronized void saveScan(ScanRecord record, String actorId) {
        Objects.requireNonNull(record, "record");
        ProjectRecord project = requireProject(record.dto().projectId());
        if (scans.size() >= MAX_SCANS && !scans.containsKey(record.dto().scanId())) {
            throw new StoreLimitException("scan limit reached");
        }
        if (scans.containsKey(record.dto().scanId())) throw new DuplicateRecordException("scan already exists");
        // Validate all global limits before publishing any part of the
        // snapshot.  A failed save must not leave a scan pointer or orphaned
        // evidence behind.
        int newEvidence = 0;
        for (ApiDtos.EvidenceDto item : record.evidence().values()) {
            if (!evidence.containsKey(item.evidenceId())) newEvidence++;
        }
        if (evidence.size() + newEvidence > MAX_EVIDENCE) throw new StoreLimitException("evidence limit reached");
        int newFindings = 0;
        for (ApiDtos.FindingDto item : record.findings()) {
            if (!findings.containsKey(item.findingId())) newFindings++;
        }
        if (findings.size() + newFindings > MAX_FINDINGS) throw new StoreLimitException("finding limit reached");
        if (persistence != null) persistence.insertScan(record, actorId);
        ScanRecord prior = scans.putIfAbsent(record.dto().scanId(), record);
        if (prior != null) throw new DuplicateRecordException("scan already exists");
        synchronized (project) { project.latestScanId = record.dto().scanId(); }
        for (ApiDtos.EvidenceDto item : record.evidence().values()) evidence.putIfAbsent(item.evidenceId(), item);
        for (ApiDtos.FindingDto item : record.findings()) findings.putIfAbsent(item.findingId(), item);
        for (ApiDtos.AttackChainDto item : record.chains()) chains.putIfAbsent(item.chainId(), item);
    }

    public synchronized void saveStaticFacts(String scanId, StaticFactSnapshot snapshot, String actorId) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(snapshot, "snapshot");
        requireScan(scanId);
        if (persistence != null) {
            persistence.insertTaintGraph(scanId, snapshot.toJson(), Instant.now().toString(), actorId);
        }
        staticFacts.put(scanId, snapshot);
    }

    public synchronized void saveHypotheses(String scanId, List<SecurityHypothesis> hypotheses, String actorId) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(hypotheses, "hypotheses");
        requireScan(scanId);
        List<SecurityHypothesis> copy = List.copyOf(hypotheses);
        Set<String> incomingIds = new java.util.HashSet<>();
        for (SecurityHypothesis item : copy) {
            if (item == null || !scanId.equals(item.scanId())) {
                throw new IllegalArgumentException("hypothesis scanId does not match target scan");
            }
            if (!incomingIds.add(item.hypothesisId())) {
                throw new IllegalArgumentException("duplicate hypothesis id");
            }
        }
        if (persistence != null) {
            persistence.insertHypotheses(scanId, copy, actorId);
        }
        List<SecurityHypothesis> prior = hypothesesByScan.put(scanId, copy);
        if (prior != null) {
            for (SecurityHypothesis item : prior) {
                hypothesesByScopedId.remove(scopedHypothesisKey(scanId, item.hypothesisId()), item);
            }
        }
        for (SecurityHypothesis item : copy) {
            hypothesesByScopedId.put(scopedHypothesisKey(scanId, item.hypothesisId()), item);
        }
        rebuildGlobalHypothesisIndex();
    }

    public List<SecurityHypothesis> hypotheses(String scanId) {
        if (scanId == null || scanId.isBlank()) return List.of();
        List<SecurityHypothesis> cached = hypothesesByScan.get(scanId);
        return cached == null ? List.of() : cached;
    }

    /** P1-08: bounded supplemental ProgramNode merge; direct adapters never grant FACT authority. */
    public synchronized void saveAnalyzerProgramNodes(String scanId, List<ProgramNode> nodes) {
        Objects.requireNonNull(scanId, "scanId");
        requireScan(scanId);
        if (nodes == null || nodes.isEmpty()) return;
        if (nodes.size() > 10_000) {
            throw new IllegalArgumentException("analyzer ProgramNode batch exceeds limit");
        }
        Map<String, ProgramNode> merged = new LinkedHashMap<>();
        for (ProgramNode existing : analyzerProgramNodes(scanId)) {
            merged.put(existing.id(), existing);
        }
        for (ProgramNode node : nodes) {
            if (node == null || node.id() == null || node.id().isBlank()) continue;
            if (node.id().length() > 1024 || node.symbol().length() > 8192
                    || node.location().length() > 8192 || node.evidenceRefs().size() > 256
                    || node.extensions().size() > 64) {
                throw new IllegalArgumentException("analyzer ProgramNode exceeds field limits");
            }
            ProgramNode clamped = new ProgramNode(
                    node.id(), node.elementKind(), node.language(), node.symbol(), node.location(),
                    node.evidenceRefs(), "INFERENCE", node.extensions());
            merged.putIfAbsent(clamped.id(), clamped);
            if (merged.size() > 10_000) {
                throw new IllegalArgumentException("analyzer ProgramNode scan limit exceeded");
            }
        }
        analyzerProgramNodesByScan.put(scanId, List.copyOf(merged.values()));
    }

    public List<ProgramNode> analyzerProgramNodes(String scanId) {
        if (scanId == null || scanId.isBlank()) return List.of();
        List<ProgramNode> cached = analyzerProgramNodesByScan.get(scanId);
        return cached == null ? List.of() : cached;
    }

    public SecurityHypothesis hypothesis(String hypothesisId) {
        if (hypothesisId == null || hypothesisId.isBlank()) return null;
        SecurityHypothesis result = hypothesesById.get(hypothesisId);
        if (result == null) return null;
        return scan(result.scanId()) == null ? null : result;
    }

    /** Resolve a hypothesis only within its owning scan; never uses a global id. */
    public SecurityHypothesis hypothesis(String scanId, String hypothesisId) {
        if (scanId == null || scanId.isBlank() || hypothesisId == null || hypothesisId.isBlank()) return null;
        SecurityHypothesis result = hypothesesByScopedId.get(scopedHypothesisKey(scanId, hypothesisId));
        return result == null || scan(result.scanId()) == null ? null : result;
    }

    /**
     * Generates and stores server-owned default ExperimentPlan candidates for all hypotheses
     * on a scan (P1-06). Does not consult the model.
     */
    public synchronized List<HypothesisExperimentPlan> generateDefaultHypothesisExperimentPlans(
            String scanId) {
        requireScan(scanId);
        List<HypothesisExperimentPlan> generated =
                DefaultExperimentPlanFactory.fromHypotheses(hypotheses(scanId));
        return saveHypothesisExperimentPlans(scanId, generated);
    }

    public synchronized List<HypothesisExperimentPlan> saveHypothesisExperimentPlans(
            String scanId, List<HypothesisExperimentPlan> plans) {
        Objects.requireNonNull(scanId, "scanId");
        ScanRecord scan = requireScan(scanId);
        List<HypothesisExperimentPlan> copy = List.copyOf(plans == null ? List.of() : plans);
        Set<String> incomingIds = new java.util.HashSet<>();
        for (HypothesisExperimentPlan plan : copy) {
            if (plan == null || !scanId.equals(plan.scanId())) {
                throw new IllegalArgumentException("hypothesis experiment plan scanId mismatch");
            }
            HypothesisExperimentPlanValidator.validate(plan, 8);
            SecurityHypothesis hypothesis = hypothesis(scanId, plan.hypothesisId());
            if (hypothesis == null || !scanId.equals(hypothesis.scanId())) {
                throw new IllegalArgumentException("hypothesis experiment plan hypothesis scope mismatch");
            }
            if (!plan.entrypointRef().isBlank()
                    && !EntryRefResolver.resolve(scan.dto().entries(), plan.entrypointRef()).resolved()) {
                throw new IllegalArgumentException("hypothesis experiment plan entrypoint scope mismatch");
            }
            if (!incomingIds.add(plan.experimentPlanId())) {
                throw new IllegalArgumentException("duplicate hypothesis experiment plan id");
            }
            HypothesisExperimentPlan existing = hypothesisPlansById.get(plan.experimentPlanId());
            if (existing != null && !scanId.equals(existing.scanId())) {
                throw new IllegalArgumentException("hypothesis experiment plan id belongs to another scan");
            }
        }

        List<HypothesisExperimentPlan> prior = hypothesisPlansByScan.getOrDefault(scanId, List.of());
        for (HypothesisExperimentPlan plan : prior) {
            hypothesisPlansById.remove(plan.experimentPlanId(), plan);
            probeHypothesisBindings.remove(plan.experimentPlanId());
        }
        hypothesisPlansByScan.put(scanId, copy);
        for (HypothesisExperimentPlan plan : copy) {
            hypothesisPlansById.put(plan.experimentPlanId(), plan);
            bindProbeHypothesis(plan.experimentPlanId(), plan.hypothesisId(), plan.planKind(),
                    plan.stageAttemptId(), plan.probeAttemptId());
        }
        return copy;
    }
    public List<HypothesisExperimentPlan> hypothesisExperimentPlans(String scanId) {
        if (scanId == null || scanId.isBlank()) return List.of();
        List<HypothesisExperimentPlan> cached = hypothesisPlansByScan.get(scanId);
        return cached == null ? List.of() : cached;
    }

    public HypothesisExperimentPlan hypothesisExperimentPlan(String experimentPlanId) {
        if (experimentPlanId == null || experimentPlanId.isBlank()) return null;
        return hypothesisPlansById.get(experimentPlanId);
    }

    /**
     * Binds sandbox_probe / PathRun identity to hypothesisId+planKind without mutating P0-08
     * experimentPlanId semantics.
     */
    public void bindProbeHypothesis(String bindingKey,
                                    String hypothesisId,
                                    ExperimentPlanKind planKind,
                                    String stageAttemptId,
                                    String probeAttemptId) {
        if (bindingKey == null || bindingKey.isBlank()
                || hypothesisId == null || hypothesisId.isBlank()
                || planKind == null) {
            return;
        }
        probeHypothesisBindings.put(bindingKey.trim(), new ProbeHypothesisBinding(
                bindingKey.trim(),
                hypothesisId.trim(),
                planKind,
                stageAttemptId == null ? "" : stageAttemptId.trim(),
                probeAttemptId == null ? "" : probeAttemptId.trim()));
    }

    public ProbeHypothesisBinding probeHypothesisBinding(String bindingKey) {
        if (bindingKey == null || bindingKey.isBlank()) return null;
        return probeHypothesisBindings.get(bindingKey.trim());
    }

    /**
     * Applies a runtime observation to hypothesis lifecycle. Failed/empty projections are
     * explicit no-ops. Successful matches may move CANDIDATE → SUPPORTED|CONTRADICTED only.
     */
    public synchronized HypothesisExperimentGate.Decision applyHypothesisObservation(
            String experimentPlanId,
            RuntimeObservation observation) {
        Objects.requireNonNull(observation, "observation");
        HypothesisExperimentPlan plan = resolveHypothesisPlan(experimentPlanId, observation);
        if (plan == null) {
            return new HypothesisExperimentGate.Decision(
                    HypothesisExperimentGate.Verdict.NO_CHANGE,
                    HypothesisLifecycle.CANDIDATE,
                    "PLAN_NOT_FOUND");
        }
        SecurityHypothesis current = hypothesis(plan.scanId(), plan.hypothesisId());
        if (current == null) {
            return new HypothesisExperimentGate.Decision(
                    HypothesisExperimentGate.Verdict.NO_CHANGE,
                    HypothesisLifecycle.CANDIDATE,
                    "HYPOTHESIS_NOT_FOUND");
        }
        if (!observation.successfulProjection() || observation.isEmptyOrFailed()) {
            // Fail / empty never mutates lifecycle, even if signal strings look supportive.
            return new HypothesisExperimentGate.Decision(
                    HypothesisExperimentGate.Verdict.NO_CHANGE,
                    current.lifecycle(),
                    "EMPTY_OR_FAILED_PROJECTION");
        }
        HypothesisExperimentGate.Decision decision =
                HypothesisExperimentGate.evaluate(current.lifecycle(), plan, observation);
        if (decision.changed()) {
            replaceHypothesisLifecycle(current, decision.nextLifecycle());
            queueIncrementalSubjects(observation);
        }
        return decision;
    }

    private HypothesisExperimentPlan resolveHypothesisPlan(String experimentPlanId,
                                                           RuntimeObservation observation) {
        HypothesisExperimentPlan plan = hypothesisExperimentPlan(experimentPlanId);
        if (plan != null) {
            return plan;
        }
        String hypothesisId = observation.hypothesisId();
        if (hypothesisId == null || hypothesisId.isBlank()) {
            return null;
        }
        String scanId = findScanIdForHypothesis(hypothesisId);
        if (scanId.isBlank()) {
            return null;
        }
        return hypothesisExperimentPlans(scanId).stream()
                .filter(item -> item.hypothesisId().equals(hypothesisId)
                        && (observation.planKind() == null || item.planKind() == observation.planKind()))
                .findFirst()
                .orElse(null);
    }

    /** Explicit failed/empty path: lifecycle unchanged by contract. */
    public synchronized HypothesisLifecycle recordFailedHypothesisProjection(String hypothesisId) {
        SecurityHypothesis current = hypothesis(hypothesisId);
        if (current == null) {
            return HypothesisLifecycle.CANDIDATE;
        }
        return current.lifecycle();
    }

    public synchronized List<ObservationKindRef> drainPendingIncrementalSubjects() {
        List<ObservationKindRef> drained = List.copyOf(pendingIncrementalSubjects);
        pendingIncrementalSubjects.clear();
        return drained;
    }

    private void queueIncrementalSubjects(RuntimeObservation observation) {
        for (var kind : observation.incrementalSubjects()) {
            pendingIncrementalSubjects.add(new ObservationKindRef(
                    observation.hypothesisId(), kind.name()));
        }
        while (pendingIncrementalSubjects.size() > 256) {
            pendingIncrementalSubjects.remove(0);
        }
    }

    private void replaceHypothesisLifecycle(SecurityHypothesis current, HypothesisLifecycle next) {
        if (current.lifecycle() != HypothesisLifecycle.CANDIDATE) {
            return;
        }
        if (next != HypothesisLifecycle.SUPPORTED && next != HypothesisLifecycle.CONTRADICTED) {
            return;
        }
        SecurityHypothesis updated = new SecurityHypothesis(
                current.schemaVersion(),
                current.hypothesisId(),
                current.scanId(),
                current.securityProperty(),
                current.family(),
                next,
                current.detectorVersion(),
                current.supportingEvidenceRefs(),
                current.contradictingEvidenceRefs(),
                current.coverageGapRefs(),
                current.source(),
                current.effect()
        );
        List<SecurityHypothesis> existing = new ArrayList<>(hypotheses(current.scanId()));
        for (int i = 0; i < existing.size(); i++) {
            if (existing.get(i).hypothesisId().equals(current.hypothesisId())) {
                existing.set(i, updated);
                break;
            }
        }
        // Actor must be a real operators row for SQLite audit FK (local bootstrap admin).
        saveHypotheses(current.scanId(), existing, "local-admin");
    }

    private String findScanIdForHypothesis(String hypothesisId) {
        SecurityHypothesis hypothesis = hypothesesById.get(hypothesisId);
        return hypothesis == null ? "" : hypothesis.scanId();
    }

    public Optional<StaticFactSnapshot> staticFacts(String scanId) {
        if (scanId == null || scanId.isBlank()) return Optional.empty();
        StaticFactSnapshot cached = staticFacts.get(scanId);
        if (cached != null) return Optional.of(cached);
        if (persistence == null) return Optional.empty();
        Optional<StaticFactSnapshot> loaded = persistence.loadTaintGraph(scanId);
        loaded.ifPresent(snapshot -> staticFacts.putIfAbsent(scanId, snapshot));
        return Optional.ofNullable(staticFacts.get(scanId));
    }

    public List<ScanRecord> scansForProject(String projectId) {
        requireProject(projectId);
        return scans.values().stream()
                .filter(record -> record.dto().projectId().equals(projectId))
                .sorted(Comparator.comparing((ScanRecord record) -> record.dto().createdAt()).reversed()
                        .thenComparing(record -> record.dto().scanId()))
                .toList();
    }

    public ScanRecord scan(String scanId) {
        ScanRecord result = scanId == null ? null : scans.get(scanId);
        return result == null || project(result.dto().projectId()) == null ? null : result;
    }

    public ScanRecord requireScan(String scanId) {
        ScanRecord result = scan(scanId);
        if (result == null) throw new MissingRecordException("scan not found");
        return result;
    }

    /**
     * Permanently deletes one scan history item and its scan-scoped dependents.
     * Callers must cancel active AI jobs / worker leases first (audit-history UX:
     * cancel-then-delete); this method still fails closed if any remain active.
     */
    public synchronized void deleteScan(String scanId, String expectedProjectId, String actorId, String now) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(actorId, "actorId");
        Objects.requireNonNull(now, "now");
        ScanRecord existing = requireScan(scanId);
        String projectId = existing.dto().projectId();
        if (expectedProjectId != null && !expectedProjectId.equals(projectId)) {
            throw new MissingRecordException("scan not found");
        }
        ProjectRecord project = requireProject(projectId);
        if (persistence != null) {
            for (SQLiteControlPlanePersistence.AiJobData job : persistence.listAiJobs(projectId)) {
                if (scanId.equals(job.scanId())
                        && ("QUEUED".equals(job.status()) || "RUNNING".equals(job.status()))) {
                    throw new IllegalStateException("active AI job must be cancelled before scan deletion");
                }
            }
            persistence.deleteScan(existing, actorId, now);
        }
        scans.remove(scanId, existing);
        for (ApiDtos.EvidenceDto item : existing.evidence().values()) {
            evidence.remove(item.evidenceId(), item);
        }
        for (ApiDtos.FindingDto item : existing.findings()) {
            findings.remove(item.findingId(), item);
        }
        for (ApiDtos.AttackChainDto item : existing.chains()) {
            chains.remove(item.chainId(), item);
        }
        staticFacts.remove(scanId);
        List<SecurityHypothesis> priorHypotheses = hypothesesByScan.remove(scanId);
        if (priorHypotheses != null) {
            for (SecurityHypothesis item : priorHypotheses) {
                hypothesesByScopedId.remove(scopedHypothesisKey(scanId, item.hypothesisId()), item);
            }
        }
        rebuildGlobalHypothesisIndex();
        analyzerProgramNodesByScan.remove(scanId);
        List<HypothesisExperimentPlan> priorPlans = hypothesisPlansByScan.remove(scanId);
        if (priorPlans != null) {
            for (HypothesisExperimentPlan plan : priorPlans) {
                hypothesisPlansById.remove(plan.experimentPlanId(), plan);
                probeHypothesisBindings.remove(plan.experimentPlanId());
            }
        }
        for (String experimentPlanId : postureExperimentsForScan(scanId).keySet()) {
            postureExperimentsById.remove(experimentPlanId);
        }
        pathTracesByPathRunId.entrySet().removeIf(entry -> {
            PathTrace trace = entry.getValue();
            if (trace == null) return true;
            return containsScanToken(trace.pathTraceId(), scanId)
                    || containsScanToken(trace.pathRunId(), scanId)
                    || containsScanToken(trace.experimentPlanId(), scanId)
                    || containsScanToken(trace.tracePlanId(), scanId);
        });
        pathTraceEvidenceDeltas.entrySet().removeIf(entry -> containsScanToken(entry.getKey(), scanId));
        Set<String> removedHypothesisIds = new java.util.HashSet<>();
        if (priorHypotheses != null) {
            for (SecurityHypothesis item : priorHypotheses) {
                removedHypothesisIds.add(item.hypothesisId());
            }
        }
        if (!removedHypothesisIds.isEmpty()) {
            pendingIncrementalSubjects.removeIf(ref -> ref != null
                    && removedHypothesisIds.contains(ref.hypothesisId()));
        }
        synchronized (project) {
            if (scanId.equals(project.latestScanId)) {
                project.latestScanId = scans.values().stream()
                        .filter(record -> projectId.equals(record.dto().projectId()))
                        .max(Comparator.comparing((ScanRecord record) -> record.dto().createdAt())
                                .thenComparing(record -> record.dto().scanId()))
                        .map(record -> record.dto().scanId())
                        .orElse(null);
            }
        }
    }

    /**
     * Appends evidence onto an existing in-memory scan snapshot (e.g. DYNAMIC_TAINT_UPDATE).
     * Does not rewrite the durable scan payload; callers may persist separately later.
     */
    public synchronized ScanRecord appendScanEvidence(String scanId, List<ApiDtos.EvidenceDto> extras) {
        ScanRecord prior = requireScan(scanId);
        if (extras == null || extras.isEmpty()) return prior;
        Map<String, ApiDtos.EvidenceDto> merged = new LinkedHashMap<>(prior.evidence());
        List<String> refs = new ArrayList<>(prior.dto().evidenceRefs());
        for (ApiDtos.EvidenceDto item : extras) {
            if (item == null) continue;
            if (evidence.size() >= MAX_EVIDENCE && !evidence.containsKey(item.evidenceId())
                    && !merged.containsKey(item.evidenceId())) {
                throw new StoreLimitException("evidence limit reached");
            }
            merged.put(item.evidenceId(), item);
            evidence.put(item.evidenceId(), item);
            if (!refs.contains(item.evidenceId())) refs.add(item.evidenceId());
        }
        ApiDtos.ScanDto dto = prior.dto();
        ApiDtos.ScanDto updated = new ApiDtos.ScanDto(
                dto.schemaVersion(), dto.projectId(), dto.artifactDigest(), dto.scanId(),
                dto.status(), dto.verificationStatus(), dto.dependencyMode(),
                dto.createdAt(), dto.completedAt(), List.copyOf(refs),
                dto.entries(), dto.dependencies(), dto.sinks(), dto.findings(), dto.paths());
        ScanRecord next = new ScanRecord(updated, merged, prior.findings(), prior.chains());
        scans.put(scanId, next);
        return next;
    }

    public ApiDtos.FindingDto finding(String findingId) {
        ApiDtos.FindingDto result = findingId == null ? null : findings.get(findingId);
        return result == null || project(result.projectId()) == null ? null : result;
    }

    /**
     * Attaches or replaces a TRIAGE-sourced finding on an existing scan (P0-07).
     * In-memory snapshot is authoritative for dashboard/REPORT in the same process;
     * does not rewrite the durable scan insert payload.
     */
    public synchronized ApiDtos.FindingDto attachTriageFinding(String scanId, ApiDtos.FindingDto finding) {
        Objects.requireNonNull(finding, "finding");
        ScanRecord prior = requireScan(scanId);
        if (!prior.dto().scanId().equals(finding.scanId())
                || !prior.dto().projectId().equals(finding.projectId())
                || !prior.dto().artifactDigest().equals(finding.artifactDigest())) {
            throw new IllegalArgumentException("finding scope does not match scan");
        }
        if (findings.size() >= MAX_FINDINGS && !findings.containsKey(finding.findingId())) {
            throw new StoreLimitException("finding limit reached");
        }
        ApiDtos.FindingDto priorFinding = findings.get(finding.findingId());
        if (priorFinding == null) {
            for (ApiDtos.FindingDto item : prior.findings()) {
                if (item.findingId().equals(finding.findingId())) {
                    priorFinding = item;
                    break;
                }
            }
        }
        ApiDtos.FindingDto attached = finding;
        if (priorFinding != null) {
            String hypothesisId = finding.hypothesisId() == null || finding.hypothesisId().isBlank()
                    ? priorFinding.hypothesisId() : finding.hypothesisId();
            String securityProperty = finding.securityProperty() == null || finding.securityProperty().isBlank()
                    ? priorFinding.securityProperty() : finding.securityProperty();
            if ((hypothesisId != null && !hypothesisId.isBlank())
                    || (securityProperty != null && !securityProperty.isBlank())) {
                attached = finding.withHypothesis(hypothesisId, securityProperty);
            }
        }
        List<ApiDtos.FindingDto> nextFindings = new ArrayList<>();
        boolean replaced = false;
        for (ApiDtos.FindingDto item : prior.findings()) {
            if (item.findingId().equals(attached.findingId())) {
                nextFindings.add(attached);
                replaced = true;
            } else {
                nextFindings.add(item);
            }
        }
        if (!replaced) {
            nextFindings.add(attached);
        }
        List<ApiDtos.FindingDto> scanFindings = new ArrayList<>(prior.dto().findings());
        boolean dtoReplaced = false;
        for (int i = 0; i < scanFindings.size(); i++) {
            if (scanFindings.get(i).findingId().equals(attached.findingId())) {
                scanFindings.set(i, attached);
                dtoReplaced = true;
                break;
            }
        }
        if (!dtoReplaced) {
            scanFindings.add(attached);
        }
        ApiDtos.ScanDto dto = prior.dto();
        ApiDtos.ScanDto updated = new ApiDtos.ScanDto(
                dto.schemaVersion(), dto.projectId(), dto.artifactDigest(), dto.scanId(),
                dto.status(), dto.verificationStatus(), dto.dependencyMode(),
                dto.createdAt(), dto.completedAt(), dto.evidenceRefs(),
                dto.entries(), dto.dependencies(), dto.sinks(), List.copyOf(scanFindings), dto.paths());
        ScanRecord next = new ScanRecord(updated, prior.evidence(), List.copyOf(nextFindings), prior.chains());
        scans.put(scanId, next);
        findings.put(attached.findingId(), attached);
        return attached;
    }

    public ApiDtos.EvidenceDto evidence(String evidenceId) {
        ApiDtos.EvidenceDto result = evidenceId == null ? null : evidence.get(evidenceId);
        return result == null || project(result.projectId()) == null ? null : result;
    }

    public List<ApiDtos.AttackChainDto> attackChains(String projectId) {
        List<ApiDtos.AttackChainDto> result = new ArrayList<>();
        for (ApiDtos.AttackChainDto chain : chains.values()) {
            if (project(chain.projectId()) != null
                    && (projectId == null || projectId.equals(chain.projectId()))) result.add(chain);
        }
        return List.copyOf(result);
    }

    private void restore(SQLiteControlPlanePersistence.Snapshot snapshot) {
        for (SQLiteControlPlanePersistence.ProjectData item : snapshot.projects()) {
            projects.put(item.projectId(), new ProjectRecord(item.projectId(), item.name(), item.status(),
                    item.createdAt(), item.updatedAt(), item.deletedAt()));
        }
        for (SQLiteControlPlanePersistence.ArtifactData item : snapshot.artifacts()) {
            ProjectRecord project = projects.get(item.projectId());
            if (project == null) throw new SQLiteControlPlanePersistence.PersistenceException(
                    "artifact references a missing project");
            project.artifacts.put(item.descriptor().sha256(), item.descriptor());
        }
        for (ScanRecord record : snapshot.scans()) {
            ProjectRecord project = projects.get(record.dto().projectId());
            if (project == null || !project.artifacts.containsKey(record.dto().artifactDigest())) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "scan references missing project or artifact");
            }
            scans.put(record.dto().scanId(), record);
            project.latestScanId = record.dto().scanId();
            for (ApiDtos.EvidenceDto item : record.evidence().values()) evidence.put(item.evidenceId(), item);
            for (ApiDtos.FindingDto item : record.findings()) findings.put(item.findingId(), item);
            for (ApiDtos.AttackChainDto item : record.chains()) chains.put(item.chainId(), item);
        }
        for (Map.Entry<String, StaticFactSnapshot> item : snapshot.staticFacts().entrySet()) {
            staticFacts.put(item.getKey(), item.getValue());
        }
        if (snapshot.hypotheses() != null) {
            for (Map.Entry<String, List<SecurityHypothesis>> item : snapshot.hypotheses().entrySet()) {
                List<SecurityHypothesis> list = List.copyOf(item.getValue() == null ? List.of() : item.getValue());
                hypothesesByScan.put(item.getKey(), list);
                for (SecurityHypothesis hypothesis : list) {
                    hypothesesByScopedId.put(scopedHypothesisKey(item.getKey(), hypothesis.hypothesisId()), hypothesis);
                }
            }
        }
        rebuildGlobalHypothesisIndex();
    }

    private static String scopedHypothesisKey(String scanId, String hypothesisId) {
        return scanId + "\u0000" + hypothesisId;
    }

    private static boolean containsScanToken(String value, String scanId) {
        return value != null && !value.isBlank() && scanId != null && value.contains(scanId);
    }

    private void rebuildGlobalHypothesisIndex() {
        hypothesesById.clear();
        Set<String> ambiguous = new java.util.HashSet<>();
        for (SecurityHypothesis hypothesis : hypothesesByScopedId.values()) {
            String id = hypothesis.hypothesisId();
            if (ambiguous.contains(id)) continue;
            SecurityHypothesis prior = hypothesesById.putIfAbsent(id, hypothesis);
            if (prior != null && !prior.scanId().equals(hypothesis.scanId())) {
                hypothesesById.remove(id, prior);
                ambiguous.add(id);
            }
        }
    }
    /** PathRun / probe binding that carries hypothesisId+planKind alongside experimentPlanId. */
    public record ProbeHypothesisBinding(
            String bindingKey,
            String hypothesisId,
            ExperimentPlanKind planKind,
            String stageAttemptId,
            String probeAttemptId
    ) {
        public ProbeHypothesisBinding {
            Objects.requireNonNull(bindingKey, "bindingKey");
            Objects.requireNonNull(hypothesisId, "hypothesisId");
            Objects.requireNonNull(planKind, "planKind");
            stageAttemptId = stageAttemptId == null ? "" : stageAttemptId;
            probeAttemptId = probeAttemptId == null ? "" : probeAttemptId;
        }
    }

    /** Minimal incremental recompute hint after a successful observation. */
    public record ObservationKindRef(String hypothesisId, String observationKind) {
        public ObservationKindRef {
            hypothesisId = hypothesisId == null ? "" : hypothesisId;
            observationKind = observationKind == null ? "" : observationKind;
        }
    }

    public static final class ProjectRecord {
        private final String projectId;
        private volatile String name;
        private final String createdAt;
        private volatile String status;
        private volatile String updatedAt;
        private volatile String deletedAt;
        private final Map<String, ArtifactDescriptor> artifacts = new LinkedHashMap<>();
        private volatile String latestScanId;

        private ProjectRecord(String projectId, String name, String status, String createdAt,
                              String updatedAt, String deletedAt) {
            this.projectId = projectId;
            this.name = name;
            this.status = status;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
            this.deletedAt = deletedAt;
        }

        public String projectId() { return projectId; }
        public String name() { return name; }
        public String status() { return status; }
        public String createdAt() { return createdAt; }
        public String updatedAt() { return updatedAt; }
        public String deletedAt() { return deletedAt; }
        public boolean deleted() { return deletedAt != null; }
        public String latestScanId() { return latestScanId; }
    }

    /** Immutable scan snapshot plus its evidence and correlation records. */
    public record ScanRecord(ApiDtos.ScanDto dto, Map<String, ApiDtos.EvidenceDto> evidence,
                             List<ApiDtos.FindingDto> findings, List<ApiDtos.AttackChainDto> chains) {
        public ScanRecord {
            Objects.requireNonNull(dto, "dto");
            Map<String, ApiDtos.EvidenceDto> copiedEvidence = new LinkedHashMap<>();
            if (evidence != null) copiedEvidence.putAll(evidence);
            evidence = Collections.unmodifiableMap(copiedEvidence);
            findings = List.copyOf(findings == null ? List.of() : findings);
            chains = List.copyOf(chains == null ? List.of() : chains);
        }
    }

    public record CreatedOperator(SQLiteControlPlanePersistence.OperatorData operator, String personalAccessToken) { }

    public static final class MissingRecordException extends RuntimeException {
        public MissingRecordException(String message) { super(message); }
    }

    public static final class DuplicateRecordException extends RuntimeException {
        public DuplicateRecordException(String message) { super(message); }
    }

    public static final class StoreLimitException extends RuntimeException {
        public StoreLimitException(String message) { super(message); }
    }

    static void validateId(String value, String name) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " contains invalid characters");
        }
    }
}

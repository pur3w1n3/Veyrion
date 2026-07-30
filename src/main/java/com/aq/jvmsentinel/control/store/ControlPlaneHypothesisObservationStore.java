package com.aq.jvmsentinel.control.store;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.analysis.experiment.DefaultExperimentPlanFactory;
import com.aq.jvmsentinel.analysis.experiment.PathTraceObservationBridge;
import com.aq.jvmsentinel.analysis.experiment.RuntimeObservationProjector;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentGate;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.domain.experiment.RuntimeObservation;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.ProgramNode;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.worker.HypothesisExperimentPlanValidator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Store 辅助类。 */
public final class ControlPlaneHypothesisObservationStore {
    private static final int MAX_FINDINGS = 100_000;

    private final ControlPlaneMemoryState state;
    private final SQLiteControlPlanePersistence persistence;
    private final ControlPlaneEntityAccess entities;
    private final ControlPlanePathRunTraceStore pathRuns;

    public ControlPlaneHypothesisObservationStore(ControlPlaneMemoryState state,
                                         SQLiteControlPlanePersistence persistence,
                                         ControlPlaneEntityAccess entities,
                                         ControlPlanePathRunTraceStore pathRuns) {
        this.state = Objects.requireNonNull(state, "state");
        this.persistence = persistence;
        this.entities = entities;
        this.pathRuns = pathRuns;
    }

    public synchronized void saveHypotheses(String scanId, List<SecurityHypothesis> hypotheses, String actorId) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(hypotheses, "hypotheses");
        entities.requireScan(scanId);
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
        List<SecurityHypothesis> prior = state.hypothesesByScan.put(scanId, copy);
        if (prior != null) {
            for (SecurityHypothesis item : prior) {
                state.hypothesesByScopedId.remove(scopedHypothesisKey(scanId, item.hypothesisId()), item);
            }
        }
        for (SecurityHypothesis item : copy) {
            state.hypothesesByScopedId.put(scopedHypothesisKey(scanId, item.hypothesisId()), item);
        }
        rebuildGlobalHypothesisIndex();
    }

    public List<SecurityHypothesis> hypotheses(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return List.of();
        }
        List<SecurityHypothesis> cached = state.hypothesesByScan.get(scanId);
        return cached == null ? List.of() : cached;
    }

    /** P1-08：有效 ProgramNode 合并；直连 adapter 永不授予 FACT 权威。 */
    public synchronized void saveAnalyzerProgramNodes(String scanId, List<ProgramNode> nodes) {
        Objects.requireNonNull(scanId, "scanId");
        entities.requireScan(scanId);
        if (nodes == null || nodes.isEmpty()) {
            return;
        }
        if (nodes.size() > 10_000) {
            throw new IllegalArgumentException("analyzer ProgramNode batch exceeds limit");
        }
        Map<String, ProgramNode> merged = new LinkedHashMap<>();
        for (ProgramNode existing : analyzerProgramNodes(scanId)) {
            merged.put(existing.id(), existing);
        }
        for (ProgramNode node : nodes) {
            if (node == null || node.id() == null || node.id().isBlank()) {
                continue;
            }
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
        state.analyzerProgramNodesByScan.put(scanId, List.copyOf(merged.values()));
    }

    public List<ProgramNode> analyzerProgramNodes(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return List.of();
        }
        List<ProgramNode> cached = state.analyzerProgramNodesByScan.get(scanId);
        return cached == null ? List.of() : cached;
    }

    public SecurityHypothesis hypothesis(String hypothesisId) {
        if (hypothesisId == null || hypothesisId.isBlank()) {
            return null;
        }
        SecurityHypothesis result = state.hypothesesById.get(hypothesisId);
        if (result == null) {
            return null;
        }
        return entities.scan(result.scanId()) == null ? null : result;
    }

    /** 仅在所属 scan 内解析假设；绝不使用全局 id。 */
    public SecurityHypothesis hypothesis(String scanId, String hypothesisId) {
        if (scanId == null || scanId.isBlank() || hypothesisId == null || hypothesisId.isBlank()) {
            return null;
        }
        SecurityHypothesis result = state.hypothesesByScopedId.get(scopedHypothesisKey(scanId, hypothesisId));
        return result == null || entities.scan(result.scanId()) == null ? null : result;
    }

    public synchronized List<HypothesisExperimentPlan> generateDefaultHypothesisExperimentPlans(String scanId) {
        entities.requireScan(scanId);
        List<HypothesisExperimentPlan> generated =
                DefaultExperimentPlanFactory.fromHypotheses(hypotheses(scanId));
        return saveHypothesisExperimentPlans(scanId, generated);
    }

    public synchronized List<HypothesisExperimentPlan> saveHypothesisExperimentPlans(
            String scanId, List<HypothesisExperimentPlan> plans) {
        Objects.requireNonNull(scanId, "scanId");
        ControlPlaneStore.ScanRecord scan = entities.requireScan(scanId);
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
            HypothesisExperimentPlan existing = state.hypothesisPlansById.get(plan.experimentPlanId());
            if (existing != null && !scanId.equals(existing.scanId())) {
                throw new IllegalArgumentException("hypothesis experiment plan id belongs to another scan");
            }
        }

        List<HypothesisExperimentPlan> prior = state.hypothesisPlansByScan.getOrDefault(scanId, List.of());
        for (HypothesisExperimentPlan plan : prior) {
            state.hypothesisPlansById.remove(plan.experimentPlanId(), plan);
            state.probeHypothesisBindings.remove(plan.experimentPlanId());
        }
        state.hypothesisPlansByScan.put(scanId, copy);
        for (HypothesisExperimentPlan plan : copy) {
            state.hypothesisPlansById.put(plan.experimentPlanId(), plan);
            bindProbeHypothesis(plan.experimentPlanId(), plan.hypothesisId(), plan.planKind(),
                    plan.stageAttemptId(), plan.probeAttemptId());
        }
        return copy;
    }

    public List<HypothesisExperimentPlan> hypothesisExperimentPlans(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return List.of();
        }
        List<HypothesisExperimentPlan> cached = state.hypothesisPlansByScan.get(scanId);
        return cached == null ? List.of() : cached;
    }

    public HypothesisExperimentPlan hypothesisExperimentPlan(String experimentPlanId) {
        if (experimentPlanId == null || experimentPlanId.isBlank()) {
            return null;
        }
        return state.hypothesisPlansById.get(experimentPlanId);
    }

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
        state.probeHypothesisBindings.put(bindingKey.trim(), new ControlPlaneStore.ProbeHypothesisBinding(
                bindingKey.trim(),
                hypothesisId.trim(),
                planKind,
                stageAttemptId == null ? "" : stageAttemptId.trim(),
                probeAttemptId == null ? "" : probeAttemptId.trim()));
    }

    public ControlPlaneStore.ProbeHypothesisBinding probeHypothesisBinding(String bindingKey) {
        if (bindingKey == null || bindingKey.isBlank()) {
            return null;
        }
        return state.probeHypothesisBindings.get(bindingKey.trim());
    }

    /**
     * AUDIT_FLOW IR2：动态观测 / OBS 反馈后全量 detector 重算。
     * 合并假设；永不提升 finding 验证状态。返回合并后的假设数量。
     */
    public synchronized int recomputeDetectorsAfterObservation(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return 0;
        }
        ControlPlaneStore.ScanRecord scan;
        try {
            scan = entities.requireScan(scanId);
        } catch (RuntimeException missing) {
            return 0;
        }
        Optional<StaticFactSnapshot> facts = pathRuns.staticFacts(scanId);
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
     * PATH/TRIAGE→OBS 闭环谓词：仍存在 STATIC_ONLY 对比行（静态命中、无 pass-gate PathRun）。
     * 不因 CANDIDATE 假设存在而单独闭环——那会迫使每次审计全量动态 flood。
     */
    public synchronized boolean hasPendingObservationLoopWork(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return false;
        }
        try {
            ControlPlaneStore.ScanRecord scan = entities.requireScan(scanId);
            List<ApiDtos.PathRunDto> runs = pathRuns.loadPathRunsForScan(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
            var ledger = com.aq.jvmsentinel.analysis.contrast.ContrastLedger.build(
                    scan.dto().entries(),
                    scan.dto().sinks(),
                    scan.evidence(),
                    runs,
                    StaticFactSnapshot.resolveTaintPaths(pathRuns.staticFacts(scanId), scan.dto().sinks()));
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
     * 将持久化 PathRun 投影为 RuntimeObservation 并应用假设生命周期门控。
     * 失败/空投影永不改变生命周期。成功匹配可将 {@code CANDIDATE} 变为 {@code SUPPORTED|CONTRADICTED}。
     * 永不提升 finding 验证状态。
     */
    public synchronized List<HypothesisExperimentGate.Decision> applyPathRunHypothesisObservations(
            List<ApiDtos.PathRunDto> pathRuns) {
        if (pathRuns == null || pathRuns.isEmpty()) {
            return List.of();
        }
        List<HypothesisExperimentGate.Decision> decisions = new ArrayList<>();
        for (ApiDtos.PathRunDto run : pathRuns) {
            if (run == null) {
                continue;
            }
            String planId = run.experimentPlanId();
            if (planId == null || planId.isBlank()) {
                continue;
            }
            ControlPlaneStore.ProbeHypothesisBinding binding = probeHypothesisBinding(planId);
            HypothesisExperimentPlan plan = hypothesisExperimentPlan(planId);
            if (plan == null || !run.scanId().equals(plan.scanId())
                    || !EntryRefResolver.resolve(entities.requireScan(run.scanId()).dto().entries(),
                    run.entrypointRef()).resolved()) {
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
            PathTrace trace = this.pathRuns.pathTraceForPathRun(run.pathRunId());
            if (trace != null && !trace.legacyIncomplete()) {
                observation = PathTraceObservationBridge.fromPathTrace(
                        trace, hypothesisId, planKind, run.evidenceRefs());
            }
            decisions.add(applyHypothesisObservation(planId, observation));
        }
        return List.copyOf(decisions);
    }

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

    public synchronized HypothesisLifecycle recordFailedHypothesisProjection(String hypothesisId) {
        SecurityHypothesis current = hypothesis(hypothesisId);
        if (current == null) {
            return HypothesisLifecycle.CANDIDATE;
        }
        return current.lifecycle();
    }

    public synchronized List<ControlPlaneStore.ObservationKindRef> drainPendingIncrementalSubjects() {
        List<ControlPlaneStore.ObservationKindRef> drained = List.copyOf(state.pendingIncrementalSubjects);
        state.pendingIncrementalSubjects.clear();
        return drained;
    }

    /**
     * 在现有 scan 上附加或替换 TRIAGE 来源 finding（P0-07）。
     * 同进程内内存快照对 dashboard/REPORT 具权威性；不重写 durable scan insert 负载。
     */
    public synchronized ApiDtos.FindingDto attachTriageFinding(String scanId, ApiDtos.FindingDto finding) {
        Objects.requireNonNull(finding, "finding");
        ControlPlaneStore.ScanRecord prior = entities.requireScan(scanId);
        if (!prior.dto().scanId().equals(finding.scanId())
                || !prior.dto().projectId().equals(finding.projectId())
                || !prior.dto().artifactDigest().equals(finding.artifactDigest())) {
            throw new IllegalArgumentException("finding scope does not match scan");
        }
        if (state.findings.size() >= MAX_FINDINGS && !state.findings.containsKey(finding.findingId())) {
            throw new ControlPlaneStore.StoreLimitException("finding limit reached");
        }
        ApiDtos.FindingDto priorFinding = state.findings.get(finding.findingId());
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
        ControlPlaneStore.ScanRecord next = new ControlPlaneStore.ScanRecord(
                updated, prior.evidence(), List.copyOf(nextFindings), prior.chains());
        state.scans.put(scanId, next);
        state.findings.put(attached.findingId(), attached);
        return attached;
    }

    public void restoreHypotheses(Map<String, List<SecurityHypothesis>> hypotheses) {
        if (hypotheses == null) {
            return;
        }
        for (Map.Entry<String, List<SecurityHypothesis>> item : hypotheses.entrySet()) {
            List<SecurityHypothesis> list = List.copyOf(item.getValue() == null ? List.of() : item.getValue());
            state.hypothesesByScan.put(item.getKey(), list);
            for (SecurityHypothesis hypothesis : list) {
                state.hypothesesByScopedId.put(
                        scopedHypothesisKey(item.getKey(), hypothesis.hypothesisId()), hypothesis);
            }
        }
        rebuildGlobalHypothesisIndex();
    }

    public void purgeScanScopedState(String scanId) {
        state.staticFacts.remove(scanId);
        List<SecurityHypothesis> priorHypotheses = state.hypothesesByScan.remove(scanId);
        if (priorHypotheses != null) {
            for (SecurityHypothesis item : priorHypotheses) {
                state.hypothesesByScopedId.remove(scopedHypothesisKey(scanId, item.hypothesisId()), item);
            }
        }
        rebuildGlobalHypothesisIndex();
        state.analyzerProgramNodesByScan.remove(scanId);
        List<HypothesisExperimentPlan> priorPlans = state.hypothesisPlansByScan.remove(scanId);
        if (priorPlans != null) {
            for (HypothesisExperimentPlan plan : priorPlans) {
                state.hypothesisPlansById.remove(plan.experimentPlanId(), plan);
                state.probeHypothesisBindings.remove(plan.experimentPlanId());
            }
        }
        Set<String> removedHypothesisIds = new java.util.HashSet<>();
        if (priorHypotheses != null) {
            for (SecurityHypothesis item : priorHypotheses) {
                removedHypothesisIds.add(item.hypothesisId());
            }
        }
        if (!removedHypothesisIds.isEmpty()) {
            state.pendingIncrementalSubjects.removeIf(ref -> ref != null
                    && removedHypothesisIds.contains(ref.hypothesisId()));
        }
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

    private void queueIncrementalSubjects(RuntimeObservation observation) {
        for (var kind : observation.incrementalSubjects()) {
            state.pendingIncrementalSubjects.add(new ControlPlaneStore.ObservationKindRef(
                    observation.hypothesisId(), kind.name()));
        }
        while (state.pendingIncrementalSubjects.size() > 256) {
            state.pendingIncrementalSubjects.remove(0);
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
        // ...
    }

    private String findScanIdForHypothesis(String hypothesisId) {
        SecurityHypothesis hypothesis = state.hypothesesById.get(hypothesisId);
        return hypothesis == null ? "" : hypothesis.scanId();
    }

    private static String scopedHypothesisKey(String scanId, String hypothesisId) {
        return scanId + "\u0000" + hypothesisId;
    }

    private void rebuildGlobalHypothesisIndex() {
        state.hypothesesById.clear();
        Set<String> ambiguous = new java.util.HashSet<>();
        for (SecurityHypothesis hypothesis : state.hypothesesByScopedId.values()) {
            String id = hypothesis.hypothesisId();
            if (ambiguous.contains(id)) {
                continue;
            }
            SecurityHypothesis prior = state.hypothesesById.putIfAbsent(id, hypothesis);
            if (prior != null && !prior.scanId().equals(hypothesis.scanId())) {
                state.hypothesesById.remove(id, prior);
                ambiguous.add(id);
            }
        }
    }
}

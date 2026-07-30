package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.experiment.DefaultExperimentPlanFactory;
import com.aq.jvmsentinel.analysis.experiment.RuntimeObservationProjector;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentGate;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.domain.experiment.RuntimeObservation;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.HypothesisExperimentPlanValidator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * P1-06：hypothesis 驱动 ExperimentPlan kind、服务端 default 候选与 lifecycle gate。
 */
public final class HypothesisExperimentAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        planKindsCoverContract();
        defaultPlansAndLifecycleGate();
        pathRunProjectionAdvancesLifecycle();
        System.out.println("HypothesisExperimentAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void planKindsCoverContract() {
        Set<ExperimentPlanKind> kinds = EnumSet.allOf(ExperimentPlanKind.class);
        check(kinds.containsAll(EnumSet.of(
                        ExperimentPlanKind.REACHABILITY,
                        ExperimentPlanKind.DATAFLOW_DIFF,
                        ExperimentPlanKind.GUARD_DIFF,
                        ExperimentPlanKind.STATE_SEQUENCE,
                        ExperimentPlanKind.TYPESTATE_API,
                        ExperimentPlanKind.CONCURRENCY_RESOURCE)),
                "planKind enum covers PATH_EXPERIMENT_MODEL types");
        check(ExperimentPlanKind.tryParse("guard_diff").orElseThrow() == ExperimentPlanKind.GUARD_DIFF,
                "planKind parse is case-insensitive");
        check(ExperimentPlanKind.tryParse("NOT_A_KIND").isEmpty(), "unknown planKind rejected");
        try {
            HypothesisExperimentPlanValidator.requirePlanKind("VERIFIED");
            throw new AssertionError("VERIFIED must not be a planKind");
        } catch (IllegalArgumentException expected) {
            check("UNKNOWN_PLAN_KIND".equals(expected.getMessage()), "unknown planKind fail-closed");
        }
    }

    private static void defaultPlansAndLifecycleGate() throws Exception {
        Path root = Files.createTempDirectory("veyrion-hyp-experiment");
        try {
            ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
            String now = Instant.now().toString();
            store.bootstrapOperator("bootstrap-token", now);
            var project = store.createProject("project-hyp-exp", "Hypothesis experiment", now, "local-admin");
            Path artifact = root.resolve("Fixture.class");
            Files.writeString(artifact, "fixture");
            String digest = "a".repeat(64);
            store.registerArtifact(project, new ArtifactDescriptor("artifact-hyp-exp", ArtifactType.CLASS,
                    artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"),
                    "local-admin");
            String scanId = "scan-hyp-exp";
            var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, scanId, "entry-1",
                    "HTTP", "GET", "/api/item", "example.ItemController", "example",
                    List.of(), List.of(), "STATIC_INFERRED", 0.8, 0, List.of());
            var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, scanId,
                    "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                    List.of(), List.of(entry), List.of(), List.of(), List.of(), List.of());
            store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");

            SecurityHypothesis dataflow = new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION, "hyp-df-1", scanId, "SQL",
                    HypothesisFamily.DATAFLOW, HypothesisLifecycle.CANDIDATE,
                    "test-detector/0.1", List.of("ev-static-1"), List.of(), List.of(),
                    "/api/item", "Statement.execute");
            SecurityHypothesis guard = new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION, "hyp-gc-1", scanId, "AUTH_GAP",
                    HypothesisFamily.GUARD_COVERAGE, HypothesisLifecycle.CANDIDATE,
                    "test-detector/0.1", List.of("ev-static-2"), List.of(), List.of(),
                    "/api/item", "missing-auth-guard");
            store.saveHypotheses(scanId, List.of(dataflow, guard), "local-admin");

            List<HypothesisExperimentPlan> generated = store.generateDefaultHypothesisExperimentPlans(scanId);
            check(!generated.isEmpty(), "server generates default experiment plans");
            check(generated.stream().allMatch(plan -> plan.hypothesisId().startsWith("hyp-")),
                    "plans bind hypothesisId");
            Set<ExperimentPlanKind> dataflowKinds = generated.stream()
                    .filter(plan -> "hyp-df-1".equals(plan.hypothesisId()))
                    .map(HypothesisExperimentPlan::planKind)
                    .collect(Collectors.toSet());
            check(dataflowKinds.containsAll(Set.of(
                            ExperimentPlanKind.REACHABILITY, ExperimentPlanKind.DATAFLOW_DIFF)),
                    "DATAFLOW defaults include reachability + dataflow diff");
            Set<ExperimentPlanKind> guardKinds = generated.stream()
                    .filter(plan -> "hyp-gc-1".equals(plan.hypothesisId()))
                    .map(HypothesisExperimentPlan::planKind)
                    .collect(Collectors.toSet());
            check(guardKinds.contains(ExperimentPlanKind.GUARD_DIFF),
                    "GUARD_COVERAGE defaults include guard diff");
            check(generated.stream().noneMatch(plan ->
                            plan.expectedSignals().isEmpty() && plan.counterSignals().isEmpty()),
                    "plans declare expected/counter signals");

            // Factory 服务端 owned（无 model）：相同 input → 相同 plan id。
            List<HypothesisExperimentPlan> again = DefaultExperimentPlanFactory.fromHypothesis(
                    dataflow, "entry:entry-1", IdentityTrack.UNAUTH);
            check(again.get(0).experimentPlanId().equals(
                            generated.stream().filter(p -> "hyp-df-1".equals(p.hypothesisId())).findFirst()
                                    .orElseThrow().experimentPlanId()),
                    "default plan ids are deterministic");

            HypothesisExperimentPlan reachability = generated.stream()
                    .filter(plan -> "hyp-df-1".equals(plan.hypothesisId())
                            && plan.planKind() == ExperimentPlanKind.REACHABILITY)
                    .findFirst()
                    .orElseThrow();
            HypothesisExperimentPlanValidator.validate(reachability, 8);
            store.bindProbeHypothesis(reachability.experimentPlanId(), reachability.hypothesisId(),
                    reachability.planKind(), "stage-1", "probe-1");
            ControlPlaneStore.ProbeHypothesisBinding binding =
                    store.probeHypothesisBinding(reachability.experimentPlanId());
            check(binding != null, "probe binding stored");
            check("hyp-df-1".equals(binding.hypothesisId()), "binding carries hypothesisId");
            check(binding.planKind() == ExperimentPlanKind.REACHABILITY, "binding carries planKind");
            check("probe-1".equals(binding.probeAttemptId()), "binding carries probeAttemptId");

            // 失败/空 projection 不得变更 lifecycle。
            RuntimeObservation failed = RuntimeObservationProjector.emptyOrFailed(
                    "hyp-df-1", ExperimentPlanKind.REACHABILITY, "FAILED");
            HypothesisExperimentGate.Decision failedDecision =
                    store.applyHypothesisObservation(reachability.experimentPlanId(), failed);
            check(!failedDecision.changed(), "failed projection does not change lifecycle");
            check(store.hypothesis("hyp-df-1").lifecycle() == HypothesisLifecycle.CANDIDATE,
                    "lifecycle stays CANDIDATE after failure");
            check(store.recordFailedHypothesisProjection("hyp-df-1") == HypothesisLifecycle.CANDIDATE,
                    "explicit failed path preserves CANDIDATE");

            RuntimeObservation empty = RuntimeObservationProjector.fromPathRunProjection(
                    "", "hyp-df-1", ExperimentPlanKind.REACHABILITY, "COMPLETED",
                    true, true, "ENTRY_HIT", List.of(), false);
            HypothesisExperimentGate.Decision emptyDecision =
                    store.applyHypothesisObservation(reachability.experimentPlanId(), empty);
            check(!emptyDecision.changed(), "empty projection does not change lifecycle");
            check(store.hypothesis("hyp-df-1").lifecycle() == HypothesisLifecycle.CANDIDATE,
                    "lifecycle stays CANDIDATE after empty projection");

            // 成功 expected signal → SUPPORTED + incremental subject。
            RuntimeObservation supportedObs = RuntimeObservationProjector.fromPathRunProjection(
                    "pathrun-support-1", "hyp-df-1", ExperimentPlanKind.REACHABILITY, "COMPLETED",
                    true, false, "ENTRY_HIT", List.of("ev-runtime-1"), true);
            HypothesisExperimentGate.Decision supported =
                    store.applyHypothesisObservation(reachability.experimentPlanId(), supportedObs);
            check(supported.verdict() == HypothesisExperimentGate.Verdict.SUPPORTED,
                    "expected signal supports hypothesis");
            check(store.hypothesis("hyp-df-1").lifecycle() == HypothesisLifecycle.SUPPORTED,
                    "lifecycle CANDIDATE→SUPPORTED");
            List<ControlPlaneStore.ObservationKindRef> incremental = store.drainPendingIncrementalSubjects();
            check(!incremental.isEmpty(), "successful observation queues incremental subjects");
            check(incremental.stream().anyMatch(ref -> "hyp-df-1".equals(ref.hypothesisId())),
                    "incremental subjects bind hypothesisId");

            // 已 SUPPORTED 不能被另一 observation re-elevate / contradict。
            RuntimeObservation second = RuntimeObservationProjector.fromPathRunProjection(
                    "pathrun-support-2", "hyp-df-1", ExperimentPlanKind.REACHABILITY, "AUTH_CHALLENGE",
                    false, false, "AUTH_CHALLENGE", List.of("ev-runtime-2"), true);
            HypothesisExperimentGate.Decision noReopen =
                    store.applyHypothesisObservation(reachability.experimentPlanId(), second);
            check(!noReopen.changed(), "non-CANDIDATE lifecycle is frozen");
            check(store.hypothesis("hyp-df-1").lifecycle() == HypothesisLifecycle.SUPPORTED,
                    "SUPPORTED stays SUPPORTED");

            // 另一 hypothesis 上 counter signal → CONTRADICTED。
            HypothesisExperimentPlan guardPlan = generated.stream()
                    .filter(plan -> "hyp-gc-1".equals(plan.hypothesisId())
                            && plan.planKind() == ExperimentPlanKind.GUARD_DIFF)
                    .findFirst()
                    .orElseThrow();
            RuntimeObservation contradictedObs = RuntimeObservationProjector.fromPathRunProjection(
                    "pathrun-contra-1", "hyp-gc-1", ExperimentPlanKind.GUARD_DIFF, "AUTH_CHALLENGE",
                    true, false, "GUARD_DENY", List.of("ev-runtime-3"), true);
            HypothesisExperimentGate.Decision contradicted =
                    store.applyHypothesisObservation(guardPlan.experimentPlanId(), contradictedObs);
            check(contradicted.verdict() == HypothesisExperimentGate.Verdict.CONTRADICTED,
                    "counter signal contradicts hypothesis");
            check(store.hypothesis("hyp-gc-1").lifecycle() == HypothesisLifecycle.CONTRADICTED,
                    "lifecycle CANDIDATE→CONTRADICTED");

            // Gate 永不发明 VERIFIED / DYNAMIC_CONFIRMED lifecycle 值。
            Set<String> lifecycles = Arrays.stream(HypothesisLifecycle.values())
                    .map(Enum::name)
                    .collect(Collectors.toSet());
            check(!lifecycles.contains("VERIFIED"), "hypothesis lifecycle has no VERIFIED");
            check(!lifecycles.contains("DYNAMIC_CONFIRMED"),
                    "hypothesis lifecycle has no DYNAMIC_CONFIRMED");
            check(store.hypothesis("hyp-df-1").lifecycle() != HypothesisLifecycle.DISMISSED,
                    "support path does not dismiss");
        } finally {
            deleteTree(root);
        }
    }

    /**
     * P1-06 接线：PathRun 成功经 {@link ControlPlaneStore#replacePathRunsForTask}
     * / {@link ControlPlaneStore#applyPathRunHypothesisObservations} advances lifecycle;
     * 失败 PathRun 不。
     */
    private static void pathRunProjectionAdvancesLifecycle() throws Exception {
        Path root = Files.createTempDirectory("veyrion-hyp-pathrun");
        try {
            ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
            String now = Instant.now().toString();
            store.bootstrapOperator("bootstrap-token", now);
            var project = store.createProject("project-pathrun-hyp", "PathRun lifecycle", now, "local-admin");
            Path artifact = root.resolve("Fixture.class");
            Files.writeString(artifact, "fixture");
            String digest = "b".repeat(64);
            store.registerArtifact(project, new ArtifactDescriptor("artifact-pathrun-hyp", ArtifactType.CLASS,
                    artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"),
                    "local-admin");
            String scanId = "scan-pathrun-hyp";
            var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, scanId, "entry-pr",
                    "HTTP", "GET", "/api/item", "example.ItemController", "example",
                    List.of(), List.of(), "STATIC_INFERRED", 0.8, 0, List.of());
            var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, scanId,
                    "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                    List.of(), List.of(entry), List.of(), List.of(), List.of(), List.of());
            store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");

            SecurityHypothesis dataflow = new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION, "hyp-pr-df", scanId, "SQL",
                    HypothesisFamily.DATAFLOW, HypothesisLifecycle.CANDIDATE,
                    "test-detector/0.1", List.of("ev-static"), List.of(), List.of(),
                    "/api/item", "Statement.execute");
            SecurityHypothesis guard = new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION, "hyp-pr-gc", scanId, "AUTH_GAP",
                    HypothesisFamily.GUARD_COVERAGE, HypothesisLifecycle.CANDIDATE,
                    "test-detector/0.1", List.of("ev-static-g"), List.of(), List.of(),
                    "/api/item", "missing-auth-guard");
            store.saveHypotheses(scanId, List.of(dataflow, guard), "local-admin");
            List<HypothesisExperimentPlan> plans = store.generateDefaultHypothesisExperimentPlans(scanId);
            HypothesisExperimentPlan reachability = plans.stream()
                    .filter(plan -> "hyp-pr-df".equals(plan.hypothesisId())
                            && plan.planKind() == ExperimentPlanKind.REACHABILITY)
                    .findFirst()
                    .orElseThrow();
            HypothesisExperimentPlan guardDiff = plans.stream()
                    .filter(plan -> "hyp-pr-gc".equals(plan.hypothesisId())
                            && plan.planKind() == ExperimentPlanKind.GUARD_DIFF)
                    .findFirst()
                    .orElseThrow();

            // 失败 PathRun（空 evidence）不得变更 lifecycle。
            ApiDtos.PathRunDto failedRun = new ApiDtos.PathRunDto(
                    ApiDtos.SCHEMA_VERSION, "pathrun-fail-1", scanId, "entry:entry-pr",
                    IdentityTrack.UNAUTH.name(), "attempt-fail",
                    reachability.experimentPlanId(), "GET", "application/json",
                    "GET /api/item", "FAILED", 500, false, false, List.of(),
                    "PROJECTION_FAILED", "FAILED", List.of(), ApiDtos.MOCK, "");
            store.replacePathRunsForTask(project.projectId(), digest, scanId, "task-fail",
                    List.of(failedRun), now);
            check(store.hypothesis("hyp-pr-df").lifecycle() == HypothesisLifecycle.CANDIDATE,
                    "PathRun failure keeps CANDIDATE");

            // 成功 expected ENTRY_HIT → SUPPORTED，经 replacePathRunsForTask callback。
            ApiDtos.PathRunDto supportedRun = new ApiDtos.PathRunDto(
                    ApiDtos.SCHEMA_VERSION, "pathrun-ok-1", scanId, "entry:entry-pr",
                    IdentityTrack.UNAUTH.name(), "attempt-ok",
                    reachability.experimentPlanId(), "GET", "application/json",
                    "GET /api/item", "COMPLETED", 200, true, false, List.of(),
                    "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-runtime-path-1"),
                    ApiDtos.MOCK, "");
            List<HypothesisExperimentGate.Decision> decisions = store.applyPathRunHypothesisObservations(
                    List.of(supportedRun));
            check(!decisions.isEmpty() && decisions.get(0).changed(),
                    "successful PathRun observation changes lifecycle");
            check(store.hypothesis("hyp-pr-df").lifecycle() == HypothesisLifecycle.SUPPORTED,
                    "PathRun success CANDIDATE→SUPPORTED");
            check(!store.drainPendingIncrementalSubjects().isEmpty(),
                    "PathRun success queues incremental subjects");

            // GUARD_DIFF 上 AUTH_CHALLENGE counter signal → CONTRADICTED。
            ApiDtos.PathRunDto contraRun = new ApiDtos.PathRunDto(
                    ApiDtos.SCHEMA_VERSION, "pathrun-contra-pr", scanId, "entry:entry-pr",
                    IdentityTrack.UNAUTH.name(), "attempt-contra",
                    guardDiff.experimentPlanId(), "GET", "application/json",
                    "GET /api/item", "AUTH_CHALLENGE", 401, true, false, List.of(),
                    "AUTH_CHALLENGE", "DYNAMIC_SUSPECTED", List.of("ev-runtime-path-2"),
                    ApiDtos.MOCK, "");
            List<HypothesisExperimentGate.Decision> contraDecisions =
                    store.applyPathRunHypothesisObservations(List.of(contraRun));
            check(!contraDecisions.isEmpty()
                            && contraDecisions.get(0).verdict()
                            == HypothesisExperimentGate.Verdict.CONTRADICTED,
                    "AUTH_CHALLENGE on GUARD_DIFF yields CONTRADICTED verdict");
            check(store.hypothesis("hyp-pr-gc").lifecycle() == HypothesisLifecycle.CONTRADICTED,
                    "PathRun counter CANDIDATE→CONTRADICTED");

            // hypothesis lifecycle 上不得发明 VERIFIED / DYNAMIC_CONFIRMED。
            check(store.hypothesis("hyp-pr-df").lifecycle() == HypothesisLifecycle.SUPPORTED,
                    "supported hypothesis stays SUPPORTED (not VERIFIED)");
            check(store.hypothesis("hyp-pr-gc").lifecycle() != HypothesisLifecycle.DISMISSED,
                    "contradicted path is not dismissed");
        } finally {
            deleteTree(root);
        }
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var walk = Files.walk(root)) {
            List<Path> paths = walk.sorted((left, right) -> right.compareTo(left)).toList();
            for (Path path : paths) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

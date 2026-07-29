package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.ObservationKind;
import com.aq.jvmsentinel.domain.experiment.RuntimeObservation;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.RuntimeObservationNode;
import com.aq.jvmsentinel.domain.pathdebug.ForcedGuardKind;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;
import com.aq.jvmsentinel.worker.AgentJsonlTraceConverter;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-21 minimum acceptance fixtures without live Docker.
 */
public final class PathDebugMinimumAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        codeQueryEffectThenDbUnavailable();
        authPostures();
        dbMissingTableDataGap();
        licenseUnavailable();
        securityDenials();
        evidenceGraphDelta();
        agentEventProjection();
        gapAdvisorAndLegacySink();
        bypassCandidateOnly();
        System.out.println("PathDebugMinimumAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static PathTraceProjector.ProjectionInput baseInput(RuntimePosture posture) {
        return new PathTraceProjector.ProjectionInput(
                "pathtrace:minimum",
                "pathrun:minimum",
                "probe:minimum",
                "plan:minimum",
                "traceplan:minimum",
                "entry:code",
                posture.identityTrackWire(),
                posture,
                "worldpack:observe:scan",
                "corr:minimum",
                1,
                List.of(),
                List.of(),
                256,
                "");
    }

    /** GET /code?code=x: PARAMETER_BOUND → METHOD_HOP → EFFECT → DEPENDENCY_FAILURE. */
    private static void codeQueryEffectThenDbUnavailable() {
        PathTrace trace = PathTraceProjector.projectCodeQueryDbUnavailable(baseInput(RuntimePosture.coverage()));
        check(trace.hasEffectBeforeExit(), "effect retained before dependency exit");
        check(!trace.effectRefs().isEmpty(), "effectRefs retained");
        check(trace.exitReason() == TraceExitReason.DEPENDENCY_UNAVAILABLE, "DEPENDENCY_UNAVAILABLE exit");
        var kinds = trace.events().stream().map(e -> e.kind()).toList();
        check(kinds.contains(TraceEventKind.PARAMETER_BOUND), "PARAMETER_BOUND present");
        check(kinds.contains(TraceEventKind.METHOD_HOP), "METHOD_HOP present");
        check(kinds.contains(TraceEventKind.EFFECT_TRIGGERED), "EFFECT_TRIGGERED present");
        check(kinds.contains(TraceEventKind.DEPENDENCY_FAILURE), "DEPENDENCY_FAILURE present");
    }

    private static void authPostures() {
        PathTrace unauth = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:unauth", "pathrun:unauth", "probe:unauth", "plan:unauth",
                "traceplan:unauth", "entry:secure", "UNAUTH", RuntimePosture.unauth(),
                "worldpack:unauth", "corr:unauth", 1,
                List.of(new PathTraceProjector.EventSummary(
                        TraceEventKind.GUARD_DECISION, "401", "AuthFilter", "AUTH_CHALLENGE", false, List.of())),
                List.of(), 256, ""));
        check(unauth.exitReason() == TraceExitReason.AUTH_CHALLENGE, "UNAUTH 401 auth challenge");
        check("AUTH_REQUIRED".equals(PathTraceProjector.authRequirementFor(unauth, 401)), "authRequirement set");

        PathTrace coverage = PathTraceProjector.projectCodeQueryDbUnavailable(baseInput(RuntimePosture.coverage()));
        check("SCAN_AUTH_POSTURE".equals(PathTraceProjector.authRequirementFor(coverage, 200)),
                "COVERAGE_POSTURE enters handler path");

        PathTrace forced = PathTraceProjector.projectCodeQueryDbUnavailable(
                baseInput(RuntimePosture.forced(List.of("GUARD:AUTH"))));
        check("INSTRUMENTATION_REACHABILITY".equals(PathTraceProjector.authRequirementFor(forced, 200)),
                "FORCED past guard with reachability marker");
        check(forced.posture().forcedGuardRefs().contains("GUARD:AUTH"), "forced guard refs recorded");
    }

    private static void dbMissingTableDataGap() {
        List<PathTraceProjector.EventSummary> summaries = List.of(
                new PathTraceProjector.EventSummary(
                        TraceEventKind.EFFECT_TRIGGERED, "SQL query", "Repo#find", "EFFECT:SQL", false,
                        List.of("EFFECT:SQL")),
                new PathTraceProjector.EventSummary(
                        TraceEventKind.DEPENDENCY_FAILURE, "Table 'users' doesn't exist",
                        "JdbcTemplate#query", "DEPENDENCY_DATA_GAP", false, List.of()));
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:gap", "pathrun:gap", "probe:gap", "plan:gap", "traceplan:gap",
                "entry:users", "ADMIN", RuntimePosture.coverage(), "worldpack:observe",
                "corr:gap", 1, summaries, List.of(), 256, ""));
        check(trace.exitReason() == TraceExitReason.DEPENDENCY_DATA_GAP, "DEPENDENCY_DATA_GAP exit");
        check(!trace.effectRefs().isEmpty(), "SQL/effect kept on data gap");
        RuntimeObservation obs = PathTraceObservationBridge.fromPathTrace(
                trace, "hyp-gap", ExperimentPlanKind.REACHABILITY, List.of("evidence-gap"));
        check(obs.successfulProjection(), "observation projects from data-gap trace");
        check(!obs.incrementalSubjects().contains(ObservationKind.EFFECT)
                        || obs.signalCode().contains("DEPENDENCY"),
                "data gap trace does not alone confirm dynamic exploit");
    }

    private static void securityDenials() {
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(false, false, Map.of());
            check(false, "non-Docker forced must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("DOCKER_ONLY"), "non-Docker forced denied");
        }
        Map<String, Object> overrides = new LinkedHashMap<>();
        overrides.put("forcedGuardRefs", List.of("GUARD:AUTH"));
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(true, false, overrides);
            check(false, "AI/frontend forcedGuardRefs must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("CLIENT_POLICY_OVERRIDE_DENIED"), "client override denied");
        }
        check(ForcedGuardKind.isForbiddenForceTarget("SANITIZER"), "sanitizer force forbidden");
        overrides.clear();
        overrides.put("serverGuardRefs", List.of("SANITIZER"));
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(true, false, overrides);
            check(false, "sanitizer force must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("FORBIDDEN_FORCE_TARGET"), "sanitizer force denied");
        }
    }

    private static void evidenceGraphDelta() {
        PathTrace trace = PathTraceProjector.projectCodeQueryDbUnavailable(
                baseInput(RuntimePosture.forced(List.of("GUARD:AUTH"))));
        PathTraceEvidenceGraphDelta.Delta delta =
                PathTraceEvidenceGraphDelta.fromPathTrace(trace, "scan-minimum");
        check(!delta.nodes().isEmpty(), "effect observed → observation nodes present");
        check(delta.nodes().stream().anyMatch(n -> n.eventKind().equals("EFFECT")),
                "effect node kind present");
        boolean forcedLimited = delta.nodes().stream()
                .filter(n -> n.eventKind().equals("EFFECT"))
                .allMatch(n -> "UNREACHED".equals(n.verificationStatus()));
        check(forcedLimited, "forced-only effect nodes marked limited");
        EvidenceGraph base = new EvidenceGraph(
                EvidenceGraph.SCHEMA_VERSION, "scan-minimum", List.of(), List.of(),
                false, EvidenceGraph.DEFAULT_MAX_NODES, EvidenceGraph.DEFAULT_MAX_EDGES, "", null);
        EvidenceGraph merged = PathTraceEvidenceGraphDelta.mergeInto(base, delta);
        check(merged.nodes().size() > base.nodes().size(), "delta merged into graph");
    }

    private static void agentEventProjection() {
        AgentJsonlTraceConverter.AgentEvent hop = new AgentJsonlTraceConverter.AgentEvent(
                1L, "HTTP", "AGENT_INSTRUMENTED", "DYNAMIC_SUSPECTED",
                "com.example.CodeService", "handle", "2020-01-01T00:00:00Z", "main",
                Map.of("pathDebugKind", "METHOD_HOP", "captureMode", "APPLICATION_METHOD"));
        AgentJsonlTraceConverter.AgentEvent effect = new AgentJsonlTraceConverter.AgentEvent(
                2L, "PROCESS", "AGENT_INSTRUMENTED", "DYNAMIC_SUSPECTED",
                "com.example.Util", "exec", "2020-01-01T00:00:00Z", "main",
                Map.of("pathDebugKind", "EFFECT_TRIGGERED", "effectKind", "EXPRESSION"));
        AgentJsonlTraceConverter.AgentEvent depFail = new AgentJsonlTraceConverter.AgentEvent(
                3L, "JDBC", "AGENT_INSTRUMENTED", "DYNAMIC_SUSPECTED",
                "com.example.Repo", "execute", "2020-01-01T00:00:00Z", "main",
                Map.of("pathDebugKind", "DEPENDENCY_FAILURE", "failureClass", "DEPENDENCY_UNAVAILABLE",
                        "summary", "Connection refused"));
        var summaries = PathTraceProjectionBridge.projectFromPathRun(
                minimalRun(), null, List.of(hop, effect, depFail));
        check(summaries.events().stream().anyMatch(e -> e.kind() == TraceEventKind.METHOD_HOP),
                "bridge reads METHOD_HOP from agent detail");
        check(summaries.events().stream().anyMatch(e -> e.kind() == TraceEventKind.EFFECT_TRIGGERED),
                "bridge reads EFFECT_TRIGGERED from agent detail");
        check(summaries.events().stream().anyMatch(e -> e.kind() == TraceEventKind.DEPENDENCY_FAILURE),
                "bridge reads DEPENDENCY_FAILURE from agent detail");
    }

    private static com.aq.jvmsentinel.control.ApiDtos.PathRunDto minimalRun() {
        return new com.aq.jvmsentinel.control.ApiDtos.PathRunDto(
                1, "pathrun:agent-bridge", "scan-minimum", "entry:code", "ADMIN",
                "probe:agent", "plan:agent", "GET", "application/json",
                "GET /code correlationId=corr-min", "UNKNOWN", 200,
                true, true, List.of(), "", "DYNAMIC_SUSPECTED", List.of("evidence-1"),
                "MOCK", "", Map.of());
    }

    private static void licenseUnavailable() {
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:license", "pathrun:license", "probe:license", "plan:license",
                "traceplan:license", "entry:licensed", "ADMIN",
                RuntimePosture.forced(List.of("GUARD:LICENSE")),
                "worldpack:license", "corr:license", 1,
                List.of(
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.ENTRY_HIT, "handler", "LicensedController#run",
                                "ENTRY_HIT", true, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.METHOD_HOP, "downstream", "LicenseService#check",
                                "METHOD_HOP", true, List.of()),
                        new PathTraceProjector.EventSummary(
                                TraceEventKind.DEPENDENCY_FAILURE, "license file missing",
                                "LicenseChecker", "LICENSE_UNAVAILABLE", false, List.of())),
                List.of(), 256, "license"));
        check(trace.exitReason() == TraceExitReason.LICENSE_UNAVAILABLE
                        || WorldPackPlanner.classifyDependencyFailure("license file missing")
                        == TraceExitReason.LICENSE_UNAVAILABLE,
                "LICENSE_UNAVAILABLE classified");
        check(!"VERIFIED".equals(trace.posture().postureProvenance()),
                "license forced posture does not elevate verification provenance");
        check(RuntimePosture.PROVENANCE_INSTRUMENTATION.equals(trace.posture().postureProvenance()),
                "forced license exploration remains INSTRUMENTATION_REACHABILITY");
    }

    private static void gapAdvisorAndLegacySink() {
        PathTrace trace = PathTraceProjector.projectCodeQueryDbUnavailable(
                baseInput(RuntimePosture.coverage()));
        List<PathTraceGapAdvisor.Suggestion> suggestions = PathTraceGapAdvisor.suggest(trace);
        check(!suggestions.isEmpty(), "gap advisor emits suggestions");
        check(suggestions.stream().anyMatch(s -> "WORLD_PACK_REFINE".equals(s.kind())),
                "dependency exit suggests World Pack refine");
        check(suggestions.stream().allMatch(s -> !s.evidenceRefs().isEmpty()
                        || s.entryRef().equals(trace.entryRef())),
                "suggestions bind entry/evidence");

        var entry = new com.aq.jvmsentinel.control.ApiDtos.EntryDto(
                com.aq.jvmsentinel.control.ApiDtos.SCHEMA_VERSION,
                "project-min", "a".repeat(64), "scan-min", "entry-legacy",
                "HTTP", "GET", "/legacy", "demo.LegacyController", "demo",
                List.of(), List.of(), com.aq.jvmsentinel.control.ApiDtos.STATIC_INFERRED,
                0.5, 0, List.of());
        var plan = TracePlanCompiler.compileWithLegacySinkPaths(
                entry,
                List.of("LegacyController#run -> LegacyService#handle -> ExprUtil#eval SINK_EXPRESSION"),
                List.of("GUARD:AUTH"),
                List.of());
        check(plan.expectedHops().stream().anyMatch(h -> h.contains("LegacyService")),
                "legacy taint path projects hops");
        check(plan.expectedEffectRefs().stream().anyMatch(e -> e.contains("EXPRESSION")),
                "legacy sink projects expected effect");
    }

    private static void bypassCandidateOnly() {
        List<RuntimePosture> withCandidate =
                RuntimePostureOrchestrator.planDefaultPostures(List.of("GUARD:AUTH"), true);
        check(withCandidate.stream().anyMatch(p -> p.postureKind().name().equals("BYPASS")),
                "BYPASS generated when candidate present");
        List<RuntimePosture> without =
                RuntimePostureOrchestrator.planDefaultPostures(List.of("GUARD:AUTH"), false);
        check(without.stream().noneMatch(p -> p.postureKind().name().equals("BYPASS")),
                "BYPASS absent without candidate");
        try {
            RuntimePostureOrchestrator.bypassForCandidate(false, false);
            check(false, "bypass without candidate must throw");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("BYPASS_REQUIRES_CANDIDATE"), "bypass requires candidate");
        }
        RuntimePosture bypass = RuntimePostureOrchestrator.bypassForCandidate(true, false);
        check(bypass.postureKind().name().equals("BYPASS"), "AUTH PoC enables bypass posture");
        String longEntry = "entry:GET:/" + "x".repeat(200);
        String planId = PostureExperimentCompiler.boundedPlanId(
                longEntry, com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind.FORCED_REACHABILITY);
        check(planId.length() <= 128, "bounded plan id fits ProbeTarget limit");
        check(planId.matches("[A-Za-z0-9_.:/-]{1,128}"), "bounded plan id charset safe");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

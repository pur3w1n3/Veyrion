package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * P0-21：从 PathTrace gap 产生确定性 PATH/TRIAGE 建议。
 * 建议仅为 advisory — 服务端仍编译并授权 ExperimentPlan。
 */
public final class PathTraceGapAdvisor {
    public static final String PRODUCER = "path-trace-gap-advisor/0.1";

    private PathTraceGapAdvisor() {
    }

    public record Suggestion(
            String kind,
            String objective,
            String entryRef,
            String recommendedWorldPackMode,
            String recommendedPosture,
            List<String> candidateInputs,
            List<String> evidenceRefs,
            String stopCondition
    ) {
        public Suggestion {
            kind = kind == null ? "REPLAY" : kind;
            objective = objective == null ? "" : objective;
            entryRef = entryRef == null ? "" : entryRef;
            recommendedWorldPackMode = recommendedWorldPackMode == null ? "" : recommendedWorldPackMode;
            recommendedPosture = recommendedPosture == null ? "" : recommendedPosture;
            candidateInputs = List.copyOf(candidateInputs == null ? List.of() : candidateInputs);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            stopCondition = stopCondition == null || stopCondition.isBlank()
                    ? "BUDGET_OR_EXIT_SIGNAL" : stopCondition;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("kind", kind);
            map.put("objective", objective);
            map.put("entryRef", entryRef);
            map.put("recommendedWorldPackMode", recommendedWorldPackMode);
            map.put("recommendedPosture", recommendedPosture);
            map.put("candidateInputs", candidateInputs);
            map.put("evidenceRefs", evidenceRefs);
            map.put("stopCondition", stopCondition);
            map.put("producer", PRODUCER);
            return map;
        }
    }

    public static List<Suggestion> suggest(PathTrace trace) {
        Objects.requireNonNull(trace, "trace");
        List<Suggestion> out = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        if (!trace.pathTraceId().isBlank()) {
            evidence.add("pathTrace:" + trace.pathTraceId());
        }
        for (var event : trace.events()) {
            if (!event.evidenceRef().isBlank()) {
                evidence.add(event.evidenceRef());
            }
        }
        if (trace.exitReason() == TraceExitReason.DEPENDENCY_UNAVAILABLE
                || trace.exitReason() == TraceExitReason.DEPENDENCY_DATA_GAP) {
            out.add(new Suggestion(
                    "WORLD_PACK_REFINE",
                    "Effect or SQL already observed; refine World Pack schema/seed or replay with OBSERVE_FAIL.",
                    trace.entryRef(),
                    "OBSERVE_FAIL",
                    trace.posture().postureKind().name(),
                    parameterCandidates(trace),
                    evidence,
                    "DEPENDENCY_EXIT_OR_COMPLETED"));
        }
        if (trace.exitReason() == TraceExitReason.PARAMETER_BINDING_GAP
                || !trace.hasEffectBeforeExit() && trace.parameterFlow().isEmpty()) {
            out.add(new Suggestion(
                    "PARAMETER_EXPAND",
                    "Expand parameter space from entry signature / DTO fields; empty input already tried.",
                    trace.entryRef(),
                    "MOCK_CONTINUE",
                    "COVERAGE_POSTURE",
                    parameterCandidates(trace),
                    evidence,
                    "PARAMETER_BOUND_OR_EFFECT"));
        }
        if (trace.exitReason() == TraceExitReason.AUTH_POSTURE_GAP
                || trace.exitReason() == TraceExitReason.AUTH_CHALLENGE) {
            out.add(new Suggestion(
                    "POSTURE_REPLAY",
                    "Replay with COVERAGE_POSTURE or Docker-only FORCED_REACHABILITY on identified guards.",
                    trace.entryRef(),
                    "MOCK_CONTINUE",
                    "FORCED_REACHABILITY",
                    List.of(),
                    evidence,
                    "ENTRY_HIT_OR_AUTH_POSTURE_GAP"));
        }
        if (trace.exitReason() == TraceExitReason.LICENSE_UNAVAILABLE) {
            out.add(new Suggestion(
                    "WORLD_MATERIAL",
                    "Provide license material in World Pack or explore forced license guard under INSTRUMENTATION_REACHABILITY.",
                    trace.entryRef(),
                    "MOCK_CONTINUE",
                    "FORCED_REACHABILITY",
                    List.of(),
                    evidence,
                    "LICENSE_OR_FORCED_PAST_GUARD"));
        }
        boolean truncated = trace.events().stream()
                .anyMatch(e -> e.kind() == TraceEventKind.TRACE_TRUNCATED)
                || trace.exitReason() == TraceExitReason.TRACE_TRUNCATED;
        if (truncated) {
            out.add(new Suggestion(
                    "BUDGET_REPLAY",
                    "Trace truncated; replay with deeper hop budget on the same experimentPlanId.",
                    trace.entryRef(),
                    "",
                    trace.posture().postureKind().name(),
                    parameterCandidates(trace),
                    evidence,
                    "DEEPER_PATH_OR_BUDGET"));
        }
        if (out.isEmpty()) {
            out.add(new Suggestion(
                    "REPLAY",
                    "Replay PathTrace for confirmation; do not elevate verification from MOCK/forced alone.",
                    trace.entryRef(),
                    "",
                    trace.posture().postureKind().name(),
                    parameterCandidates(trace),
                    evidence,
                    "COMPLETED_OR_BUDGET"));
        }
        return List.copyOf(out);
    }

    private static List<String> parameterCandidates(PathTrace trace) {
        List<String> out = new ArrayList<>();
        for (PathTrace.ParameterFlowStep step : trace.parameterFlow()) {
            if (step.source() != null && !step.source().isBlank()) {
                out.add(step.source());
            }
        }
        return List.copyOf(out);
    }
}

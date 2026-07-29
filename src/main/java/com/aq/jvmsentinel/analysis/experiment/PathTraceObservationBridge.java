package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.ObservationKind;
import com.aq.jvmsentinel.domain.experiment.RuntimeObservation;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * P0-21: project PathTrace events into RuntimeObservation kinds for hypothesis lifecycle.
 * FORCED_REACHABILITY / INSTRUMENTATION_REACHABILITY cannot alone become DYNAMIC_CONFIRMED.
 */
public final class PathTraceObservationBridge {
    private PathTraceObservationBridge() {
    }

    public static RuntimeObservation fromPathTrace(
            PathTrace trace,
            String hypothesisId,
            ExperimentPlanKind planKind,
            List<String> evidenceRefs) {
        Objects.requireNonNull(trace, "trace");
        if (trace.legacyIncomplete() || trace.events().isEmpty()) {
            return RuntimeObservationProjector.emptyOrFailed(hypothesisId, planKind, "LEGACY_OR_EMPTY_TRACE");
        }
        ObservationKind kind = dominantKind(trace);
        String signal = trace.exitReason().name();
        boolean forcedOnly = trace.posture().postureKind().name().equals("FORCED_REACHABILITY")
                || RuntimePosture.PROVENANCE_INSTRUMENTATION.equals(trace.posture().postureProvenance());
        if (forcedOnly) {
            signal = "INSTRUMENTATION_REACHABILITY:" + signal;
        }
        List<String> refs = evidenceRefs == null || evidenceRefs.isEmpty()
                ? List.of("pathtrace:" + trace.pathTraceId())
                : List.copyOf(evidenceRefs);
        return new RuntimeObservation(
                "obs:pathtrace:" + trace.pathTraceId(),
                trace.pathRunId(),
                hypothesisId == null ? "" : hypothesisId,
                planKind,
                kind,
                signal,
                trace.exitReason().name(),
                !trace.effectRefs().isEmpty() || kind == ObservationKind.EFFECT,
                refs,
                "RUNTIME_OBSERVED",
                incrementalSubjects(trace));
    }

    public static List<RuntimeObservation> fromPathTraceEvents(
            PathTrace trace,
            String hypothesisId,
            ExperimentPlanKind planKind,
            List<String> evidenceRefs) {
        if (trace == null || trace.events().isEmpty()) {
            return List.of(RuntimeObservationProjector.emptyOrFailed(
                    hypothesisId, planKind, "EMPTY_TRACE"));
        }
        List<RuntimeObservation> out = new ArrayList<>();
        for (TraceEvent event : trace.events()) {
            ObservationKind kind = kindForEvent(event.kind());
            if (kind == ObservationKind.UNKNOWN) continue;
            boolean forced = event.forced()
                    || trace.posture().postureKind().name().equals("FORCED_REACHABILITY");
            String signal = event.detailCode().isBlank() ? event.kind().name() : event.detailCode();
            if (forced) {
                signal = "INSTRUMENTATION_REACHABILITY:" + signal;
            }
            out.add(new RuntimeObservation(
                    "obs:pathtrace-event:" + trace.pathTraceId() + ":" + event.sequence(),
                    trace.pathRunId(),
                    hypothesisId == null ? "" : hypothesisId,
                    planKind,
                    kind,
                    signal,
                    trace.exitReason().name(),
                    kind == ObservationKind.EFFECT || kind == ObservationKind.ENTRY,
                    evidenceRefs == null ? List.of("pathtrace:" + trace.pathTraceId()) : evidenceRefs,
                    "RUNTIME_OBSERVED",
                    forced && kind == ObservationKind.EFFECT ? List.of() : List.of(kind)));
        }
        return List.copyOf(out);
    }

    private static ObservationKind dominantKind(PathTrace trace) {
        for (TraceEvent event : trace.events()) {
            ObservationKind kind = kindForEvent(event.kind());
            if (kind == ObservationKind.EFFECT) return kind;
        }
        for (TraceEvent event : trace.events()) {
            ObservationKind kind = kindForEvent(event.kind());
            if (kind == ObservationKind.GUARD || kind == ObservationKind.DEPENDENCY) return kind;
        }
        for (TraceEvent event : trace.events()) {
            ObservationKind kind = kindForEvent(event.kind());
            if (kind == ObservationKind.ENTRY) return kind;
        }
        return ObservationKind.EXCEPTION;
    }

    private static ObservationKind kindForEvent(TraceEventKind kind) {
        return switch (kind) {
            case ENTRY_HIT, PARAMETER_BOUND -> ObservationKind.ENTRY;
            case METHOD_HOP -> ObservationKind.ENTRY;
            case GUARD_DECISION -> ObservationKind.GUARD;
            case EFFECT_TRIGGERED -> ObservationKind.EFFECT;
            case DEPENDENCY_FAILURE -> ObservationKind.DEPENDENCY;
            case EXCEPTION_THROWN -> ObservationKind.EXCEPTION;
            case RETURN_EXIT, TRACE_TRUNCATED -> ObservationKind.EXCEPTION;
            default -> ObservationKind.UNKNOWN;
        };
    }

    private static List<ObservationKind> incrementalSubjects(PathTrace trace) {
        List<ObservationKind> subjects = new ArrayList<>();
        for (TraceEvent event : trace.events()) {
            ObservationKind kind = kindForEvent(event.kind());
            if (kind != ObservationKind.UNKNOWN && !subjects.contains(kind)) {
                subjects.add(kind);
            }
        }
        if (trace.posture().postureProvenance().toUpperCase(Locale.ROOT)
                .contains("INSTRUMENTATION")) {
            subjects.remove(ObservationKind.EFFECT);
        }
        return List.copyOf(subjects);
    }
}

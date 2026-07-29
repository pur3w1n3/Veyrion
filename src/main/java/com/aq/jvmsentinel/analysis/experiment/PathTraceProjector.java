package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.pathdebug.PathRunPathDebugView;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * P0-21: project agent-like event summaries and PathRun facts into PathTrace without full trace store.
 */
public final class PathTraceProjector {
    public static final String PRODUCER = "path-trace-projector/0.1";

    private PathTraceProjector() {
    }

    public record ProjectionInput(
            String pathTraceId,
            String pathRunId,
            String probeAttemptId,
            String experimentPlanId,
            String tracePlanId,
            String entryRef,
            String track,
            RuntimePosture posture,
            String worldPackId,
            String correlationId,
            int requestSeq,
            List<EventSummary> eventSummaries,
            List<PathTrace.ParameterFlowStep> parameterFlow,
            int maxEvents,
            String authRequirement
    ) {
        public ProjectionInput {
            Objects.requireNonNull(pathTraceId, "pathTraceId");
            eventSummaries = eventSummaries == null ? List.of() : List.copyOf(eventSummaries);
            parameterFlow = parameterFlow == null ? List.of() : List.copyOf(parameterFlow);
            posture = posture == null ? RuntimePosture.legacyIncomplete() : posture;
            maxEvents = maxEvents <= 0 ? 256 : maxEvents;
        }
    }

    public record EventSummary(
            TraceEventKind kind,
            String summary,
            String subjectRef,
            String detailCode,
            boolean forced,
            List<String> effectRefs
    ) {
        public EventSummary {
            Objects.requireNonNull(kind, "kind");
            summary = summary == null ? "" : summary;
            subjectRef = subjectRef == null ? "" : subjectRef;
            detailCode = detailCode == null ? "" : detailCode;
            effectRefs = effectRefs == null ? List.of() : List.copyOf(effectRefs);
        }
    }

    public static PathTrace project(ProjectionInput input) {
        Objects.requireNonNull(input, "input");
        List<TraceEvent> events = new ArrayList<>();
        Set<String> effectRefs = new LinkedHashSet<>();
        String lastBusinessHop = "";
        TraceExitReason exitReason = TraceExitReason.UNKNOWN;
        boolean truncated = false;
        int seq = 0;
        for (EventSummary summary : input.eventSummaries()) {
            if (events.size() >= input.maxEvents()) {
                truncated = true;
                events.add(new TraceEvent(
                        seq++,
                        TraceEventKind.TRACE_TRUNCATED,
                        "Trace budget exceeded",
                        "",
                        "PROBE_BUDGET",
                        false,
                        Map.of(),
                        ""));
                exitReason = TraceExitReason.TRACE_TRUNCATED;
                break;
            }
            events.add(new TraceEvent(
                    seq++,
                    summary.kind(),
                    summary.summary(),
                    summary.subjectRef(),
                    summary.detailCode(),
                    summary.forced(),
                    Map.of(),
                    ""));
            if (summary.kind() == TraceEventKind.METHOD_HOP && !summary.subjectRef().isBlank()) {
                lastBusinessHop = summary.subjectRef();
            }
            if (summary.kind() == TraceEventKind.EFFECT_TRIGGERED) {
                for (String ref : summary.effectRefs()) {
                    if (ref != null && !ref.isBlank()) {
                        effectRefs.add(ref.trim());
                    }
                }
                if (summary.subjectRef() != null && !summary.subjectRef().isBlank()) {
                    effectRefs.add(summary.subjectRef().trim());
                }
            }
            if (summary.kind() == TraceEventKind.DEPENDENCY_FAILURE) {
                exitReason = WorldPackPlanner.classifyDependencyFailure(
                        summary.summary() + " " + summary.detailCode());
            }
            if (summary.kind() == TraceEventKind.RETURN_EXIT) {
                exitReason = TraceExitReason.COMPLETED;
            }
            if (summary.kind() == TraceEventKind.GUARD_DECISION
                    && "AUTH_CHALLENGE".equalsIgnoreCase(summary.detailCode())) {
                exitReason = TraceExitReason.AUTH_CHALLENGE;
            }
        }
        if (truncated) {
            // preserve effects observed before truncation
        } else if (exitReason == TraceExitReason.UNKNOWN && hasEffectBeforeExit(events, effectRefs)) {
            exitReason = TraceExitReason.DEPENDENCY_UNAVAILABLE;
        }
        return new PathTrace(
                PathTrace.SCHEMA_VERSION,
                input.pathTraceId(),
                input.pathRunId(),
                input.probeAttemptId(),
                input.experimentPlanId(),
                input.tracePlanId(),
                input.entryRef(),
                input.track(),
                input.posture(),
                input.worldPackId(),
                input.correlationId(),
                input.requestSeq(),
                events,
                input.parameterFlow(),
                exitReason,
                lastBusinessHop,
                List.copyOf(effectRefs),
                false);
    }

    public static PathTrace fromLegacyPathRun(Map<String, Object> pathRunWire) {
        PathRunPathDebugView view = PathRunPathDebugView.fromPathRunWire(pathRunWire);
        if (pathRunWire != null && pathRunWire.get("pathTrace") instanceof Map<?, ?> nested) {
            @SuppressWarnings("unchecked")
            PathTrace trace = PathTrace.fromMap((Map<String, Object>) nested);
            if (trace.legacyIncomplete()) {
                return trace;
            }
            return trace;
        }
        String pathRunId = string(pathRunWire, "pathRunId");
        String pathTraceId = view.pathTraceId().isBlank()
                ? (pathRunId.isBlank() ? "pathtrace:legacy" : "pathtrace:" + pathRunId)
                : view.pathTraceId();
        RuntimePosture posture = RuntimePosture.fromMap(extractPostureMap(pathRunWire, view));
        return new PathTrace(
                PathTrace.SCHEMA_VERSION,
                pathTraceId,
                pathRunId,
                string(pathRunWire, "probeAttemptId"),
                string(pathRunWire, "experimentPlanId"),
                view.tracePlanId(),
                string(pathRunWire, "entryRef"),
                string(pathRunWire, "track"),
                posture,
                view.worldPackId(),
                string(pathRunWire, "correlationId"),
                number(pathRunWire, "requestSeq"),
                List.of(),
                List.of(),
                TraceExitReason.LEGACY_DYNAMIC_INCOMPLETE,
                "",
                List.of(),
                true);
    }

    public static String authRequirementFor(PathTrace trace, int httpStatus) {
        if (trace == null) {
            return "";
        }
        if (trace.exitReason() == TraceExitReason.AUTH_CHALLENGE || httpStatus == 401 || httpStatus == 403) {
            return "AUTH_REQUIRED";
        }
        if (trace.posture().postureKind().name().equals("COVERAGE_POSTURE")) {
            return "SCAN_AUTH_POSTURE";
        }
        if (trace.posture().postureKind().name().equals("FORCED_REACHABILITY")) {
            return "INSTRUMENTATION_REACHABILITY";
        }
        return "";
    }

    private static boolean hasEffectBeforeExit(List<TraceEvent> events, Set<String> effectRefs) {
        return !effectRefs.isEmpty()
                || events.stream().anyMatch(e -> e.kind() == TraceEventKind.EFFECT_TRIGGERED);
    }

    private static Map<String, Object> extractPostureMap(
            Map<String, Object> pathRunWire,
            PathRunPathDebugView view) {
        if (pathRunWire != null && pathRunWire.get("posture") instanceof Map<?, ?> nested) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) nested;
            return map;
        }
        Map<String, Object> map = new LinkedHashMap<>();
        if (!view.postureKind().isBlank()) {
            map.put("postureKind", view.postureKind());
        }
        if (!view.postureProvenance().isBlank()) {
            map.put("postureProvenance", view.postureProvenance());
        }
        if (!view.forcedGuardRefs().isEmpty()) {
            map.put("forcedGuardRefs", view.forcedGuardRefs());
        }
        return map;
    }

    private static String string(Map<String, Object> map, String key) {
        if (map == null) {
            return "";
        }
        Object value = map.get(key);
        return value == null ? "" : value.toString().trim();
    }

    private static int number(Map<String, Object> map, String key) {
        if (map == null) {
            return 0;
        }
        Object value = map.get(key);
        return value instanceof Number n ? n.intValue() : 0;
    }

    /** Fixture helper: GET /code?code=x effect then DB unavailable. */
    public static PathTrace projectCodeQueryDbUnavailable(ProjectionInput base) {
        List<EventSummary> summaries = List.of(
                new EventSummary(TraceEventKind.ENTRY_HIT, "GET /code", "entry:code", "", false, List.of()),
                new EventSummary(TraceEventKind.PARAMETER_BOUND, "query.code=x", "CodeController#code", "", false, List.of()),
                new EventSummary(TraceEventKind.METHOD_HOP, "CodeService#handle", "CodeService#handle", "", false, List.of()),
                new EventSummary(TraceEventKind.EFFECT_TRIGGERED, "EXPRESSION_EXECUTION", "ExprUtil#eval",
                        "EFFECT:EXPRESSION", false, List.of("EFFECT:EXPRESSION_EXECUTION")),
                new EventSummary(TraceEventKind.DEPENDENCY_FAILURE, "Connection refused", "JdbcTemplate#query",
                        "DEPENDENCY_UNAVAILABLE", false, List.of()));
        return project(new ProjectionInput(
                base.pathTraceId(),
                base.pathRunId(),
                base.probeAttemptId(),
                base.experimentPlanId(),
                base.tracePlanId(),
                base.entryRef(),
                base.track(),
                base.posture(),
                base.worldPackId(),
                base.correlationId(),
                base.requestSeq(),
                summaries,
                base.parameterFlow(),
                base.maxEvents(),
                base.authRequirement()));
    }
}

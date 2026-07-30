package com.aq.jvmsentinel.domain.pathdebug;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 单次 PathRun attempt 的有序 dynamic path（P0-21）。
 * 即使 request 因 dependency failure 退出，仍保留 failure 前 hop/effect。
 */
public record PathTrace(
        int schemaVersion,
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
        List<TraceEvent> events,
        List<ParameterFlowStep> parameterFlow,
        TraceExitReason exitReason,
        String lastBusinessHop,
        List<String> effectRefs,
        boolean legacyIncomplete
) {
    public static final int SCHEMA_VERSION = 1;
    public static final String LEGACY_MARKER = "LEGACY_DYNAMIC_INCOMPLETE";

    public record ParameterFlowStep(
            String source,
            String boundTo,
            String flowedTo,
            String effectRef
    ) {
        public ParameterFlowStep {
            source = source == null ? "" : source;
            boundTo = boundTo == null ? "" : boundTo;
            flowedTo = flowedTo == null ? "" : flowedTo;
            effectRef = effectRef == null ? "" : effectRef;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("source", source);
            map.put("boundTo", boundTo);
            map.put("flowedTo", flowedTo);
            map.put("effectRef", effectRef);
            return map;
        }

        @SuppressWarnings("unchecked")
        public static ParameterFlowStep fromMap(Map<String, Object> map) {
            if (map == null) {
                return new ParameterFlowStep("", "", "", "");
            }
            return new ParameterFlowStep(
                    string(map.get("source")),
                    string(map.get("boundTo")),
                    string(map.get("flowedTo")),
                    string(map.get("effectRef")));
        }

        private static String string(Object value) {
            return value == null ? "" : value.toString().trim();
        }
    }

    public PathTrace {
        if (schemaVersion != SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported PathTrace schemaVersion=" + schemaVersion);
        }
        Objects.requireNonNull(pathTraceId, "pathTraceId");
        if (pathTraceId.isBlank()) {
            throw new IllegalArgumentException("pathTraceId must not be blank");
        }
        pathRunId = pathRunId == null ? "" : pathRunId;
        probeAttemptId = probeAttemptId == null ? "" : probeAttemptId;
        experimentPlanId = experimentPlanId == null ? "" : experimentPlanId;
        tracePlanId = tracePlanId == null ? "" : tracePlanId;
        entryRef = entryRef == null ? "" : entryRef;
        track = track == null || track.isBlank() ? "UNAUTH" : track;
        posture = posture == null ? RuntimePosture.legacyIncomplete() : posture;
        worldPackId = worldPackId == null ? "" : worldPackId;
        correlationId = correlationId == null ? "" : correlationId;
        events = List.copyOf(events == null ? List.of() : events);
        parameterFlow = List.copyOf(parameterFlow == null ? List.of() : parameterFlow);
        exitReason = exitReason == null ? TraceExitReason.UNKNOWN : exitReason;
        lastBusinessHop = lastBusinessHop == null ? "" : lastBusinessHop;
        effectRefs = List.copyOf(effectRefs == null ? List.of() : effectRefs);
        if (legacyIncomplete && exitReason == TraceExitReason.UNKNOWN) {
            exitReason = TraceExitReason.LEGACY_DYNAMIC_INCOMPLETE;
        }
    }

    public boolean hasEffectBeforeExit() {
        return !effectRefs.isEmpty()
                || events.stream().anyMatch(e -> e.kind() == TraceEventKind.EFFECT_TRIGGERED);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("pathTraceId", pathTraceId);
        map.put("pathRunId", pathRunId);
        map.put("probeAttemptId", probeAttemptId);
        map.put("experimentPlanId", experimentPlanId);
        map.put("tracePlanId", tracePlanId);
        map.put("entryRef", entryRef);
        map.put("track", track);
        map.put("posture", posture.toMap());
        map.put("worldPackId", worldPackId);
        map.put("correlationId", correlationId);
        map.put("requestSeq", requestSeq);
        map.put("events", events.stream().map(TraceEvent::toMap).toList());
        map.put("parameterFlow", parameterFlow.stream().map(ParameterFlowStep::toMap).toList());
        map.put("exitReason", exitReason.name());
        map.put("lastBusinessHop", lastBusinessHop);
        map.put("effectRefs", new ArrayList<>(effectRefs));
        map.put("legacyIncomplete", legacyIncomplete);
        if (legacyIncomplete) {
            map.put("compatibilityMarker", LEGACY_MARKER);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    public static PathTrace fromMap(Map<String, Object> map) {
        Objects.requireNonNull(map, "map");
        int version = map.get("schemaVersion") instanceof Number n ? n.intValue() : SCHEMA_VERSION;
        List<TraceEvent> events = new ArrayList<>();
        Object rawEvents = map.get("events");
        if (rawEvents instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?> nested) {
                    events.add(TraceEvent.fromMap((Map<String, Object>) nested));
                }
            }
        }
        List<ParameterFlowStep> flows = new ArrayList<>();
        Object rawFlows = map.get("parameterFlow");
        if (rawFlows instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?> nested) {
                    flows.add(ParameterFlowStep.fromMap((Map<String, Object>) nested));
                }
            }
        }
        RuntimePosture posture = RuntimePosture.legacyIncomplete();
        Object rawPosture = map.get("posture");
        if (rawPosture instanceof Map<?, ?> nested) {
            posture = RuntimePosture.fromMap((Map<String, Object>) nested);
        }
        boolean legacy = map.get("legacyIncomplete") instanceof Boolean b && b
                || LEGACY_MARKER.equals(string(map.get("compatibilityMarker")));
        return new PathTrace(
                version,
                string(map.get("pathTraceId")),
                string(map.get("pathRunId")),
                string(map.get("probeAttemptId")),
                string(map.get("experimentPlanId")),
                string(map.get("tracePlanId")),
                string(map.get("entryRef")),
                string(map.get("track")),
                posture,
                string(map.get("worldPackId")),
                string(map.get("correlationId")),
                map.get("requestSeq") instanceof Number n ? n.intValue() : 0,
                events,
                flows,
                TraceExitReason.parseOrUnknown(string(map.get("exitReason"))),
                string(map.get("lastBusinessHop")),
                stringList(map.get("effectRefs")),
                legacy);
    }

    private static String string(Object value) {
        return value == null ? "" : value.toString().trim();
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (item != null && !item.toString().isBlank()) {
                out.add(item.toString());
            }
        }
        return out;
    }
}

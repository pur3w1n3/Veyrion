package com.aq.jvmsentinel.domain.pathdebug;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** One ordered PathTrace event (P0-21). */
public record TraceEvent(
        int sequence,
        TraceEventKind kind,
        String summary,
        String subjectRef,
        String detailCode,
        boolean forced,
        Map<String, Object> attributes,
        String evidenceRef
) {
    public TraceEvent {
        Objects.requireNonNull(kind, "kind");
        if (sequence < 0) {
            throw new IllegalArgumentException("sequence must be >= 0");
        }
        summary = summary == null ? "" : summary;
        subjectRef = subjectRef == null ? "" : subjectRef;
        detailCode = detailCode == null ? "" : detailCode;
        attributes = Map.copyOf(attributes == null ? Map.of() : attributes);
        evidenceRef = evidenceRef == null ? "" : evidenceRef;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("sequence", sequence);
        map.put("kind", kind.name());
        map.put("summary", summary);
        map.put("subjectRef", subjectRef);
        map.put("detailCode", detailCode);
        map.put("forced", forced);
        map.put("attributes", new LinkedHashMap<>(attributes));
        map.put("evidenceRef", evidenceRef);
        return map;
    }

    @SuppressWarnings("unchecked")
    public static TraceEvent fromMap(Map<String, Object> map) {
        Objects.requireNonNull(map, "map");
        TraceEventKind kind = TraceEventKind.tryParse(string(map.get("kind")))
                .orElse(TraceEventKind.METHOD_HOP);
        Map<String, Object> attrs = new LinkedHashMap<>();
        Object rawAttrs = map.get("attributes");
        if (rawAttrs instanceof Map<?, ?> nested) {
            nested.forEach((k, v) -> {
                if (k != null) {
                    attrs.put(k.toString(), v);
                }
            });
        }
        return new TraceEvent(
                map.get("sequence") instanceof Number n ? n.intValue() : 0,
                kind,
                string(map.get("summary")),
                string(map.get("subjectRef")),
                string(map.get("detailCode")),
                map.get("forced") instanceof Boolean b && b,
                attrs,
                string(map.get("evidenceRef")));
    }

    private static String string(Object value) {
        return value == null ? "" : value.toString().trim();
    }
}

package com.aq.jvmsentinel.domain.pathdebug;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Static bridge from Entry/Guard/Effect facts to dynamic observation targets (P0-21).
 */
public record TracePlan(
        int schemaVersion,
        String tracePlanId,
        String entryRef,
        String method,
        String route,
        String handler,
        List<ParameterSpec> parameters,
        List<String> expectedHops,
        List<String> expectedEffectRefs,
        List<String> expectedGuardRefs,
        List<String> unresolvedPoints,
        String emptyInputRationale,
        int maxHops,
        int maxEvents,
        int maxResponseMillis
) {
    public static final int SCHEMA_VERSION = 1;
    public static final String PRODUCER = "trace-plan-compiler/0.1";

    public record ParameterSpec(
            String name,
            String source,
            String provenance,
            boolean emptyLegal,
            String emptyInputRationale
    ) {
        public ParameterSpec {
            name = name == null ? "" : name.trim();
            source = source == null || source.isBlank() ? "QUERY" : source.trim().toUpperCase();
            provenance = provenance == null || provenance.isBlank() ? "STATIC_SIGNATURE" : provenance.trim();
            emptyInputRationale = emptyInputRationale == null ? "" : emptyInputRationale;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("name", name);
            map.put("source", source);
            map.put("provenance", provenance);
            map.put("emptyLegal", emptyLegal);
            map.put("emptyInputRationale", emptyInputRationale);
            return map;
        }

        @SuppressWarnings("unchecked")
        public static ParameterSpec fromMap(Map<String, Object> map) {
            if (map == null) {
                return new ParameterSpec("", "QUERY", "STATIC_SIGNATURE", true, "");
            }
            return new ParameterSpec(
                    string(map.get("name")),
                    string(map.get("source")),
                    string(map.get("provenance")),
                    map.get("emptyLegal") instanceof Boolean b ? b : true,
                    string(map.get("emptyInputRationale")));
        }
    }

    public TracePlan {
        if (schemaVersion != SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported TracePlan schemaVersion=" + schemaVersion);
        }
        Objects.requireNonNull(tracePlanId, "tracePlanId");
        if (tracePlanId.isBlank()) {
            throw new IllegalArgumentException("tracePlanId must not be blank");
        }
        entryRef = entryRef == null ? "" : entryRef.trim();
        method = method == null || method.isBlank() ? "GET" : method.trim().toUpperCase();
        route = route == null ? "/" : route.trim();
        handler = handler == null ? "" : handler.trim();
        parameters = List.copyOf(parameters == null ? List.of() : parameters);
        expectedHops = List.copyOf(expectedHops == null ? List.of() : expectedHops);
        expectedEffectRefs = List.copyOf(expectedEffectRefs == null ? List.of() : expectedEffectRefs);
        expectedGuardRefs = List.copyOf(expectedGuardRefs == null ? List.of() : expectedGuardRefs);
        unresolvedPoints = List.copyOf(unresolvedPoints == null ? List.of() : unresolvedPoints);
        emptyInputRationale = emptyInputRationale == null ? "" : emptyInputRationale;
        maxHops = maxHops <= 0 ? 64 : Math.min(maxHops, 512);
        maxEvents = maxEvents <= 0 ? 256 : Math.min(maxEvents, 4096);
        maxResponseMillis = maxResponseMillis <= 0 ? 15_000 : Math.min(maxResponseMillis, 120_000);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("tracePlanId", tracePlanId);
        map.put("entryRef", entryRef);
        map.put("method", method);
        map.put("route", route);
        map.put("handler", handler);
        map.put("parameters", parameters.stream().map(ParameterSpec::toMap).toList());
        map.put("expectedHops", new ArrayList<>(expectedHops));
        map.put("expectedEffectRefs", new ArrayList<>(expectedEffectRefs));
        map.put("expectedGuardRefs", new ArrayList<>(expectedGuardRefs));
        map.put("unresolvedPoints", new ArrayList<>(unresolvedPoints));
        map.put("emptyInputRationale", emptyInputRationale);
        map.put("maxHops", maxHops);
        map.put("maxEvents", maxEvents);
        map.put("maxResponseMillis", maxResponseMillis);
        map.put("producer", PRODUCER);
        return map;
    }

    @SuppressWarnings("unchecked")
    public static TracePlan fromMap(Map<String, Object> map) {
        Objects.requireNonNull(map, "map");
        int version = map.get("schemaVersion") instanceof Number n ? n.intValue() : SCHEMA_VERSION;
        List<ParameterSpec> params = new ArrayList<>();
        Object rawParams = map.get("parameters");
        if (rawParams instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?> nested) {
                    params.add(ParameterSpec.fromMap((Map<String, Object>) nested));
                }
            }
        }
        return new TracePlan(
                version,
                string(map.get("tracePlanId")),
                string(map.get("entryRef")),
                string(map.get("method")),
                string(map.get("route")),
                string(map.get("handler")),
                params,
                stringList(map.get("expectedHops")),
                stringList(map.get("expectedEffectRefs")),
                stringList(map.get("expectedGuardRefs")),
                stringList(map.get("unresolvedPoints")),
                string(map.get("emptyInputRationale")),
                map.get("maxHops") instanceof Number n ? n.intValue() : 64,
                map.get("maxEvents") instanceof Number n ? n.intValue() : 256,
                map.get("maxResponseMillis") instanceof Number n ? n.intValue() : 15_000);
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

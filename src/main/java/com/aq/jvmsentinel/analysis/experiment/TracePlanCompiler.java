package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * P0-21: compile static Entry/Guard/Effect facts into TracePlan observation targets.
 */
public final class TracePlanCompiler {
    public static final String PRODUCER = TracePlan.PRODUCER;
    private static final int MAX_HOPS_PER_ENTRY = 24;
    private static final int MAX_EFFECTS_PER_ENTRY = 16;
    private static final int MAX_GUARDS_PER_ENTRY = 24;

    private TracePlanCompiler() {
    }

    public static TracePlan compile(
            ApiDtos.EntryDto entry,
            List<String> callEdgeHints,
            List<String> effectHints,
            List<String> guardHints,
            List<String> unresolvedHints) {
        Objects.requireNonNull(entry, "entry");
        String method = entry.method() == null || entry.method().isBlank()
                || "UNKNOWN".equalsIgnoreCase(entry.method())
                ? "GET" : entry.method().trim().toUpperCase(Locale.ROOT);
        String route = entry.route() == null || entry.route().isBlank() ? "/" : entry.route().trim();
        String handler = entry.declaringClass() == null ? "" : entry.declaringClass().trim();
        List<TracePlan.ParameterSpec> parameters = inferParameters(entry, method);
        boolean emptyShape = parameters.stream().allMatch(p -> p.name().isBlank());
        String emptyRationale = emptyShape
                ? "Entry accepts 0 parameters / empty query/body as a legal shape; "
                + "observe downstream Entry/Guard/Effect/State/Dependency rather than HTTP status alone."
                : "";
        List<String> expectedHops = normalizeHints(callEdgeHints);
        List<String> expectedEffects = normalizeEffectHints(effectHints);
        List<String> expectedGuards = normalizeHints(guardHints);
        List<String> unresolved = mergeUnresolved(unresolvedHints, effectHints, callEdgeHints);
        String tracePlanId = "traceplan:" + entry.id();
        return new TracePlan(
                TracePlan.SCHEMA_VERSION,
                tracePlanId,
                entry.id(),
                method,
                route,
                handler,
                parameters,
                expectedHops,
                expectedEffects,
                expectedGuards,
                unresolved,
                emptyRationale,
                64,
                256,
                15_000);
    }

    /**
     * Fill expectedGuards / effects / hops / parameter specs from static IR bindings.
     * Never invents runtime FACT — provenance remains RULE_GENERATED / STATIC_SIGNATURE.
     */
    public static TracePlan compileFromStaticIr(
            ApiDtos.EntryDto entry,
            List<ApiDtos.SinkDto> sinks,
            Map<String, ApiDtos.EvidenceDto> evidence,
            List<BytecodeFactIndex.TaintPath> taintPaths,
            List<String> guardHints) {
        Objects.requireNonNull(entry, "entry");
        Map<String, ApiDtos.EvidenceDto> evid = evidence == null ? Map.of() : evidence;
        List<BytecodeFactIndex.TaintPath> paths = taintPaths == null ? List.of() : taintPaths;
        List<ApiDtos.SinkDto> sinkList = sinks == null ? List.of() : sinks;

        List<String> hops = new ArrayList<>();
        List<String> effects = new ArrayList<>();
        List<String> unresolved = new ArrayList<>();
        Set<String> seenHop = new LinkedHashSet<>();
        Set<String> seenEffect = new LinkedHashSet<>();

        for (BytecodeFactIndex.TaintPath path : paths) {
            if (path == null) {
                continue;
            }
            ApiDtos.EntryDto bound = StaticFactSnapshot.findEntryForTaintSource(
                    List.of(entry), evid, path);
            if (bound == null || !entry.id().equals(bound.id())) {
                // Also accept owner-class match when annotation binding is incomplete.
                if (!ownerMatchesEntry(entry, path.sourceOwner())) {
                    continue;
                }
            }
            String effect = "effect:" + (path.category() == null || path.category().isBlank()
                    ? "TAINT" : path.category())
                    + ":" + StaticFactSnapshot.normalizeClassRef(path.sinkOwner())
                    + "#" + path.sinkMethod();
            if (seenEffect.add(effect) && effects.size() < MAX_EFFECTS_PER_ENTRY) {
                effects.add(effect);
            }
            String taintRef = "TAINT:" + path.id();
            if (seenEffect.add(taintRef) && effects.size() < MAX_EFFECTS_PER_ENTRY) {
                effects.add(taintRef);
            }
            if (path.steps() != null) {
                for (BytecodeFactIndex.TaintStep step : path.steps()) {
                    if (step == null || step.symbol() == null || step.symbol().isBlank()) {
                        continue;
                    }
                    String hop = step.symbol().trim();
                    if (seenHop.add(hop) && hops.size() < MAX_HOPS_PER_ENTRY) {
                        hops.add(hop);
                    }
                    String kind = step.kind() == null ? "" : step.kind().toUpperCase(Locale.ROOT);
                    if (kind.contains("UNRESOLVED") || kind.contains("REFLECTION")
                            || kind.contains("DYNAMIC")) {
                        unresolved.add(hop);
                    }
                }
            }
            String sinkHop = StaticFactSnapshot.normalizeClassRef(path.sinkOwner())
                    + "#" + path.sinkMethod();
            if (seenHop.add(sinkHop) && hops.size() < MAX_HOPS_PER_ENTRY) {
                hops.add(sinkHop);
            }
        }

        Map<String, BytecodeFactIndex.TaintPath> pathsById = indexPaths(paths);
        for (ApiDtos.SinkDto sink : sinkList) {
            if (sink == null || !sinkLinkedToEntry(sink, entry, evid, pathsById)) {
                continue;
            }
            String sinkEffect = "SINK:" + sink.category() + ":" + sink.id();
            if (seenEffect.add(sinkEffect) && effects.size() < MAX_EFFECTS_PER_ENTRY) {
                effects.add(sinkEffect);
            }
            if (sink.symbol() != null && !sink.symbol().isBlank()
                    && seenHop.add(sink.symbol()) && hops.size() < MAX_HOPS_PER_ENTRY) {
                hops.add(sink.symbol().trim());
            }
        }

        List<String> guards = new ArrayList<>(capHints(guardHints, MAX_GUARDS_PER_ENTRY));
        // Entry-local preconditions (ROLE=…) are static guard expectations.
        if (entry.preconditions() != null) {
            for (String pre : entry.preconditions()) {
                if (pre == null || pre.isBlank() || guards.size() >= MAX_GUARDS_PER_ENTRY) {
                    continue;
                }
                String upper = pre.toUpperCase(Locale.ROOT);
                if (upper.contains("ROLE") || upper.contains("AUTH") || upper.contains("PERMISSION")
                        || upper.contains("LOGIN") || upper.contains("JWT")) {
                    String guard = pre.startsWith("GUARD:") ? pre.trim() : "GUARD:" + pre.trim();
                    if (!guards.contains(guard)) {
                        guards.add(guard);
                    }
                }
            }
        }

        return compile(entry, hops, effects, guards, unresolved);
    }

    /** Entry ids that have at least one expected effect after static IR compile. */
    public static List<String> entryIdsWithExpectedEffects(
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.SinkDto> sinks,
            Map<String, ApiDtos.EvidenceDto> evidence,
            List<BytecodeFactIndex.TaintPath> taintPaths) {
        if (entries == null || entries.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        for (ApiDtos.EntryDto entry : entries) {
            if (entry == null) {
                continue;
            }
            TracePlan plan = compileFromStaticIr(entry, sinks, evidence, taintPaths, List.of());
            if (!plan.expectedEffectRefs().isEmpty()) {
                ids.add(entry.id());
            }
        }
        return List.copyOf(ids);
    }

    private static boolean ownerMatchesEntry(ApiDtos.EntryDto entry, String owner) {
        if (entry == null || entry.declaringClass() == null || owner == null) {
            return false;
        }
        String left = StaticFactSnapshot.normalizeClassRef(entry.declaringClass()).toLowerCase(Locale.ROOT);
        String right = StaticFactSnapshot.normalizeClassRef(owner).toLowerCase(Locale.ROOT);
        return !left.isBlank() && left.equals(right);
    }

    private static Map<String, BytecodeFactIndex.TaintPath> indexPaths(
            List<BytecodeFactIndex.TaintPath> paths) {
        Map<String, BytecodeFactIndex.TaintPath> byId = new LinkedHashMap<>();
        if (paths == null) {
            return byId;
        }
        for (BytecodeFactIndex.TaintPath path : paths) {
            if (path != null && path.id() != null && !path.id().isBlank()) {
                byId.putIfAbsent(path.id(), path);
            }
        }
        return byId;
    }

    private static boolean sinkLinkedToEntry(
            ApiDtos.SinkDto sink,
            ApiDtos.EntryDto entry,
            Map<String, ApiDtos.EvidenceDto> evidence,
            Map<String, BytecodeFactIndex.TaintPath> pathsById) {
        if (sink == null || entry == null) {
            return false;
        }
        if (sink.evidenceRefs() != null) {
            for (String ref : sink.evidenceRefs()) {
                if (ref != null && (ref.contains(entry.id()) || ref.equals(entry.id()))) {
                    return true;
                }
            }
        }
        String taintPathId = StaticFactSnapshot.taintPathIdFromSink(sink, evidence);
        if (!taintPathId.isBlank()) {
            BytecodeFactIndex.TaintPath path = pathsById.get(taintPathId);
            if (path != null) {
                ApiDtos.EntryDto bound = StaticFactSnapshot.findEntryForTaintSource(
                        List.of(entry), evidence, path);
                if (bound != null && entry.id().equals(bound.id())) {
                    return true;
                }
                if (ownerMatchesEntry(entry, path.sourceOwner())) {
                    return true;
                }
            }
        }
        String symbol = sink.symbol() == null ? "" : sink.symbol();
        String clazz = entry.declaringClass() == null ? "" : entry.declaringClass();
        if (!clazz.isBlank() && symbol.contains(clazz)) {
            String route = entry.route() == null ? "" : entry.route();
            if (route.isBlank() || symbol.contains(route)
                    || (entry.method() != null && !entry.method().isBlank()
                    && symbol.toUpperCase(Locale.ROOT).contains(
                    " " + entry.method().toUpperCase(Locale.ROOT) + " "))) {
                return true;
            }
        }
        return false;
    }

    private static List<String> capHints(List<String> hints, int max) {
        if (hints == null || hints.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String hint : hints) {
            if (hint == null || hint.isBlank()) {
                continue;
            }
            out.add(hint.trim());
            if (out.size() >= max) {
                break;
            }
        }
        return List.copyOf(out);
    }

    public static List<TracePlan> compileAll(
            List<ApiDtos.EntryDto> entries,
            List<String> callEdgeHints,
            List<String> effectHints,
            List<String> guardHints,
            List<String> unresolvedHints,
            int budget) {
        int limit = Math.max(1, Math.min(budget <= 0 ? 64 : budget, 256));
        List<ApiDtos.EntryDto> entryList = entries == null ? List.of() : entries;
        List<TracePlan> out = new ArrayList<>();
        for (ApiDtos.EntryDto entry : entryList) {
            if (entry == null || entry.route() == null || entry.route().isBlank()) {
                continue;
            }
            if (out.size() >= limit) {
                break;
            }
            out.add(compile(entry, callEdgeHints, effectHints, guardHints, unresolvedHints));
        }
        return List.copyOf(out);
    }

    /**
     * Compatible projection of legacy sink/taint path strings into expected hops/effects.
     * Never invents FACT — provenance remains RULE_GENERATED / STATIC_SIGNATURE in TracePlan.
     */
    public static TracePlan compileWithLegacySinkPaths(
            ApiDtos.EntryDto entry,
            List<String> legacySinkOrTaintPaths,
            List<String> guardHints,
            List<String> unresolvedHints) {
        List<String> hops = new ArrayList<>();
        List<String> effects = new ArrayList<>();
        if (legacySinkOrTaintPaths != null) {
            for (String path : legacySinkOrTaintPaths) {
                if (path == null || path.isBlank()) {
                    continue;
                }
                String trimmed = path.trim();
                if (trimmed.contains("->") || trimmed.contains("→")) {
                    String[] parts = trimmed.split("\\s*(->|→)\\s*");
                    for (int i = 0; i < parts.length; i++) {
                        String hop = parts[i].trim();
                        if (hop.isBlank()) {
                            continue;
                        }
                        if (i == parts.length - 1 && looksLikeEffect(hop)) {
                            effects.add(normalizeLegacyEffect(hop));
                        } else {
                            hops.add(hop);
                        }
                    }
                } else if (looksLikeEffect(trimmed)) {
                    effects.add(normalizeLegacyEffect(trimmed));
                } else {
                    hops.add(trimmed);
                }
            }
        }
        return compile(entry, hops, effects, guardHints, unresolvedHints);
    }

    private static boolean looksLikeEffect(String value) {
        String upper = value.toUpperCase(Locale.ROOT);
        return upper.contains("SINK") || upper.contains("SQL") || upper.contains("EXEC")
                || upper.contains("EXPRESSION") || upper.contains("DESERIAL")
                || upper.contains("JNDI") || upper.contains("FILE_WRITE")
                || upper.contains("COMMAND") || upper.contains("SCRIPT");
    }

    private static String normalizeLegacyEffect(String value) {
        String upper = value.toUpperCase(Locale.ROOT);
        if (upper.contains("SQL")) return "effect:SQL_EXECUTION:" + value;
        if (upper.contains("EXPRESSION") || upper.contains("SPEL") || upper.contains("OGNL")) {
            return "effect:EXPRESSION_EXECUTION:" + value;
        }
        if (upper.contains("COMMAND") || upper.contains("RUNTIME.EXEC") || upper.contains("PROCESS")) {
            return "effect:COMMAND_EXECUTION:" + value;
        }
        if (upper.contains("DESERIAL")) return "effect:DESERIALIZATION:" + value;
        if (upper.contains("JNDI")) return "effect:JNDI_LOOKUP:" + value;
        if (upper.contains("FILE")) return "effect:FILE_WRITE:" + value;
        return "effect:LEGACY_SINK:" + value;
    }

    private static List<TracePlan.ParameterSpec> inferParameters(ApiDtos.EntryDto entry, String method) {
        List<TracePlan.ParameterSpec> parameters = new ArrayList<>();
        List<String> declared = entry.parameters();
        if (declared == null || declared.isEmpty()) {
            parameters.add(new TracePlan.ParameterSpec(
                    "",
                    "QUERY",
                    "EMPTY_INPUT",
                    true,
                    "Empty query is legal for " + method + " " + entry.route()
                            + "; record empty-input rationale and observe downstream effects."));
        } else {
            Set<String> seenNames = new LinkedHashSet<>();
            for (String raw : declared) {
                if (raw == null || raw.isBlank()) {
                    continue;
                }
                String name = ProbeParameterHeuristics.resolveName(raw);
                if (name.isBlank()) {
                    name = raw.contains("=") ? raw.substring(0, raw.indexOf('=')).trim() : raw.trim();
                }
                if (name.isBlank() || !seenNames.add(name)) {
                    continue;
                }
                String source = inferParamSource(raw, method);
                parameters.add(new TracePlan.ParameterSpec(
                        name,
                        source,
                        "ENTRY_SIGNATURE",
                        true,
                        "Empty value for parameter '" + name + "' remains a legal exploration input; "
                                + "prefer honest sample via ProbeParameterHeuristics when probing."));
            }
            if (parameters.isEmpty()) {
                parameters.add(new TracePlan.ParameterSpec(
                        "",
                        "QUERY",
                        "EMPTY_INPUT",
                        true,
                        "Declared parameters could not be parsed; empty query remains legal."));
            }
        }
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            boolean hasBody = parameters.stream().anyMatch(p -> "BODY".equals(p.source()));
            if (!hasBody) {
                parameters.add(new TracePlan.ParameterSpec(
                        "body",
                        "BODY",
                        "EMPTY_INPUT",
                        true,
                        "Empty body is a legal input shape for " + method
                                + "; do not treat missing body as probe failure by itself."));
            }
        }
        return parameters;
    }

    private static String inferParamSource(String raw, String method) {
        if (raw == null) {
            return "QUERY";
        }
        String lower = raw.toLowerCase(Locale.ROOT);
        if (lower.contains("source=body") || lower.contains("in=body")
                || lower.contains("@requestbody") || lower.contains("type=body")) {
            return "BODY";
        }
        if (lower.contains("source=header") || lower.contains("in=header")) {
            return "HEADER";
        }
        if (lower.contains("source=path") || lower.contains("in=path")
                || lower.contains("pathvariable")) {
            return "PATH";
        }
        if (("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))
                && (lower.contains("json") || lower.contains("body"))) {
            return "BODY";
        }
        return "QUERY";
    }

    private static List<String> normalizeHints(List<String> hints) {
        if (hints == null || hints.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String hint : hints) {
            if (hint == null || hint.isBlank()) {
                continue;
            }
            out.add(hint.trim());
        }
        return List.copyOf(out);
    }

    private static List<String> normalizeEffectHints(List<String> effectHints) {
        if (effectHints == null || effectHints.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String hint : effectHints) {
            if (hint == null || hint.isBlank()) {
                continue;
            }
            String normalized = hint.trim();
            if (normalized.toUpperCase(Locale.ROOT).startsWith("SINK:")
                    || normalized.toUpperCase(Locale.ROOT).startsWith("TAINT:")) {
                out.add(normalized);
            } else if (normalized.toUpperCase(Locale.ROOT).contains("SQL")
                    || normalized.toUpperCase(Locale.ROOT).contains("JDBC")
                    || normalized.toUpperCase(Locale.ROOT).contains("EXEC")
                    || normalized.toUpperCase(Locale.ROOT).contains("FILE")
                    || normalized.toUpperCase(Locale.ROOT).contains("EXPRESSION")) {
                out.add("EFFECT:" + normalized);
            } else {
                out.add(normalized);
            }
        }
        return List.copyOf(out);
    }

    private static List<String> mergeUnresolved(
            List<String> unresolvedHints,
            List<String> effectHints,
            List<String> callEdgeHints) {
        Set<String> merged = new LinkedHashSet<>(normalizeHints(unresolvedHints));
        appendUnresolvedFrom(merged, effectHints);
        appendUnresolvedFrom(merged, callEdgeHints);
        return List.copyOf(merged);
    }

    private static void appendUnresolvedFrom(Set<String> merged, List<String> hints) {
        if (hints == null) {
            return;
        }
        for (String hint : hints) {
            if (hint == null || hint.isBlank()) {
                continue;
            }
            String upper = hint.toUpperCase(Locale.ROOT);
            if (upper.contains("REFLECTION")
                    || upper.contains("DYNAMIC_DISPATCH")
                    || upper.contains("UNRESOLVED")
                    || upper.contains("PROXY")
                    || upper.contains("INVOKEVIRTUAL")) {
                merged.add(hint.trim());
            }
        }
    }
}

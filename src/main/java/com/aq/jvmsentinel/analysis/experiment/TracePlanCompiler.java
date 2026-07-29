package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * P0-21: compile static Entry/Guard/Effect facts into TracePlan observation targets.
 */
public final class TracePlanCompiler {
    public static final String PRODUCER = TracePlan.PRODUCER;

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
            for (String raw : declared) {
                if (raw == null || raw.isBlank()) {
                    continue;
                }
                String name = raw.contains("=") ? raw.substring(0, raw.indexOf('=')).trim() : raw.trim();
                parameters.add(new TracePlan.ParameterSpec(
                        name,
                        "QUERY",
                        "ENTRY_SIGNATURE",
                        true,
                        "Empty value for parameter '" + name + "' remains a legal exploration input."));
            }
        }
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            parameters.add(new TracePlan.ParameterSpec(
                    "body",
                    "BODY",
                    "EMPTY_INPUT",
                    true,
                    "Empty body is a legal input shape for " + method
                            + "; do not treat missing body as probe failure by itself."));
        }
        return parameters;
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

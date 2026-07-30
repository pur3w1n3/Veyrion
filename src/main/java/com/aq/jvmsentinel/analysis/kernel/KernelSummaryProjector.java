package com.aq.jvmsentinel.analysis.kernel;

import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.Sink;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 将 IR / sink / guard 启发式投影为 MethodSummary 与 sanitizer seed。
 * Provenance 仅 inference；永非 FACT 或 verification 提升。
 */
public final class KernelSummaryProjector {
    public static final int MAX_SANITIZER_SEEDS = 256;
    public static final int MAX_SUMMARY_SEEDS = 512;

    private KernelSummaryProjector() {
    }

    public record SanitizerSeed(String sanitizerKind, String symbol, List<String> evidenceRefs) {
        public SanitizerSeed {
            sanitizerKind = sanitizerKind == null || sanitizerKind.isBlank() ? "UNKNOWN" : sanitizerKind;
            symbol = symbol == null ? "" : symbol;
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        }
    }

    public record MethodSummarySeed(
            String methodKey,
            String summaryKind,
            List<String> effects,
            List<String> guards,
            List<String> sanitizers,
            List<String> evidenceRefs,
            String coverageStatus,
            String stopReason
    ) {
        public MethodSummarySeed {
            methodKey = methodKey == null ? "" : methodKey;
            summaryKind = summaryKind == null || summaryKind.isBlank() ? "KERNEL_HEURISTIC" : summaryKind;
            effects = List.copyOf(effects == null ? List.of() : effects);
            guards = List.copyOf(guards == null ? List.of() : guards);
            sanitizers = List.copyOf(sanitizers == null ? List.of() : sanitizers);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            coverageStatus = coverageStatus == null || coverageStatus.isBlank() ? "PARTIAL" : coverageStatus;
            stopReason = stopReason == null ? "" : stopReason;
        }
    }

    public static List<SanitizerSeed> sanitizerSeeds(BytecodeFactIndex index, List<Sink> sinks) {
        LinkedHashMap<String, SanitizerSeed> byKey = new LinkedHashMap<>();
        BytecodeFactIndex facts = index == null ? BytecodeFactIndex.EMPTY : index;
        Map<String, MethodSummary> summaries = MethodSummaryBuilder.build(
                facts.methods(), facts.callEdges(), facts.memberAccesses(), facts.artifactCallGraph());
        for (MethodSummary summary : summaries.values()) {
            if (byKey.size() >= MAX_SANITIZER_SEEDS) break;
            for (String marker : summary.sanitizers()) {
                if (marker == null || marker.isBlank() || marker.startsWith("VIA:")) continue;
                String symbol = summary.owner().replace('/', '.') + "#" + summary.name();
                String key = marker + "|" + symbol;
                byKey.putIfAbsent(key, new SanitizerSeed(
                        marker, symbol, List.of("kernel:sanitizer:" + marker)));
            }
        }
        for (BytecodeFactIndex.CallEdge edge : facts.callEdges()) {
            if (byKey.size() >= MAX_SANITIZER_SEEDS) break;
            SanitizerCatalog.match(edge.targetOwner(), edge.targetName()).ifPresent(marker -> {
                String symbol = normalize(edge.targetOwner()) + "#" + edge.targetName();
                String evidence = edge.evidence() == null ? "" : edge.evidence().stableKey();
                byKey.putIfAbsent(marker + "|" + symbol, new SanitizerSeed(
                        marker, symbol, evidence.isBlank() ? List.of() : List.of(evidence)));
            });
        }
        for (Sink sink : nullSafeSinks(sinks)) {
            if (byKey.size() >= MAX_SANITIZER_SEEDS) break;
            String symbol = sink.symbol() == null ? "" : sink.symbol();
            String hay = symbol.toLowerCase(Locale.ROOT);
            if (!(hay.contains("sanitize") || hay.contains("escape") || hay.contains("encode")
                    || hay.contains("validate"))) {
                continue;
            }
            String name = extractMethodName(symbol);
            SanitizerCatalog.match(extractOwner(symbol), name).ifPresent(marker ->
                    byKey.putIfAbsent(marker + "|" + symbol,
                            new SanitizerSeed(marker, symbol, sink.evidenceRefs())));
        }
        return List.copyOf(byKey.values());
    }

    public static List<MethodSummarySeed> methodSummarySeeds(BytecodeFactIndex index, List<Sink> sinks) {
        BytecodeFactIndex facts = index == null ? BytecodeFactIndex.EMPTY : index;
        Map<String, MethodSummary> summaries = MethodSummaryBuilder.build(
                facts.methods(), facts.callEdges(), facts.memberAccesses(), facts.artifactCallGraph());
        LinkedHashMap<String, MethodSummarySeed> seeds = new LinkedHashMap<>();
        for (MethodSummary summary : summaries.values()) {
            if (seeds.size() >= MAX_SUMMARY_SEEDS) break;
            if (summary.effects().isEmpty() && summary.guards().isEmpty() && summary.sanitizers().isEmpty()) {
                continue;
            }
            seeds.put(summary.methodKey(), toSeed(summary));
        }
        for (Sink sink : nullSafeSinks(sinks)) {
            if (seeds.size() >= MAX_SUMMARY_SEEDS) break;
            String symbol = sink.symbol() == null ? "" : sink.symbol();
            String owner = extractOwner(symbol);
            String name = extractMethodName(symbol);
            if (owner.isBlank() && name.isBlank()) continue;
            LinkedHashSet<String> effects = new LinkedHashSet<>();
            LinkedHashSet<String> guards = new LinkedHashSet<>();
            LinkedHashSet<String> sanitizers = new LinkedHashSet<>();
            PrimitiveEffectCatalog.match(owner, name).ifPresent(effects::add);
            if (sink.category() != null && !sink.category().isBlank()
                    && !"AUTH_GAP".equalsIgnoreCase(sink.category())) {
                effects.add("EFFECT:" + sink.category().trim().toUpperCase(Locale.ROOT));
            }
            SanitizerCatalog.matchGuard(owner, name).ifPresent(guards::add);
            SanitizerCatalog.match(owner, name).ifPresent(sanitizers::add);
            if (effects.isEmpty() && guards.isEmpty() && sanitizers.isEmpty()) continue;
            String key = CfgBuilder.methodIdentity(owner, name, "()V");
            if (seeds.containsKey(key)) continue;
            List<String> merged = new ArrayList<>(effects);
            for (String g : guards) merged.add("GUARD:" + g);
            for (String s : sanitizers) merged.add("SANITIZER:" + s);
            seeds.put(key, new MethodSummarySeed(
                    key,
                    "KERNEL_HEURISTIC",
                    List.copyOf(merged),
                    List.copyOf(guards),
                    List.copyOf(sanitizers),
                    sink.evidenceRefs() == null ? List.of() : sink.evidenceRefs(),
                    "PARTIAL",
                    "SINK_CATALOG_SEED"));
        }
        return List.copyOf(seeds.values());
    }

    private static MethodSummarySeed toSeed(MethodSummary summary) {
        LinkedHashSet<String> merged = new LinkedHashSet<>(summary.effects());
        for (String g : summary.guards()) {
            merged.add("GUARD:" + g);
        }
        for (String s : summary.sanitizers()) {
            merged.add("SANITIZER:" + s);
        }
        String coverage = summary.complete() ? "COMPLETE" : "PARTIAL";
        String stop = summary.stopReasons().isEmpty() ? "" : summary.stopReasons().get(0);
        return new MethodSummarySeed(
                summary.methodKey(),
                "KERNEL_HEURISTIC",
                List.copyOf(merged),
                summary.guards(),
                summary.sanitizers(),
                List.of("kernel:method-summary:" + summary.methodKey()),
                coverage,
                stop);
    }

    private static String extractOwner(String symbol) {
        if (symbol == null || symbol.isBlank()) return "";
        int hash = symbol.indexOf('#');
        if (hash > 0) return symbol.substring(0, hash).replace('.', '/');
        int lastDot = symbol.lastIndexOf('.');
        if (lastDot > 0) return symbol.substring(0, lastDot).replace('.', '/');
        return "";
    }

    private static String extractMethodName(String symbol) {
        if (symbol == null || symbol.isBlank()) return "";
        int hash = symbol.indexOf('#');
        if (hash >= 0 && hash + 1 < symbol.length()) {
            String rest = symbol.substring(hash + 1);
            int paren = rest.indexOf('(');
            return paren >= 0 ? rest.substring(0, paren) : rest;
        }
        int lastDot = symbol.lastIndexOf('.');
        if (lastDot >= 0 && lastDot + 1 < symbol.length()) {
            String rest = symbol.substring(lastDot + 1);
            int paren = rest.indexOf('(');
            return paren >= 0 ? rest.substring(0, paren) : rest;
        }
        return symbol;
    }

    private static String normalize(String owner) {
        return owner == null ? "" : owner.replace('/', '.');
    }

    private static List<Sink> nullSafeSinks(List<Sink> sinks) {
        return sinks == null ? List.of() : sinks;
    }
}

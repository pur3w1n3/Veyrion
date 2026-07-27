package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Deterministic sink ranking for PRE_ANALYSIS / dashboard. Scores are bounded heuristics,
 * not exploitability proof and never alone justify VERIFIED.
 */
public final class CandidateRanker {
    public static final int MAX_RANKED = 64;
    private static final Set<String> HIGH_RISK = Set.of(
            "JNDI", "COMMAND", "RCE", "DESERIALIZATION", "SQL", "SSRF");

    private CandidateRanker() {
    }

    public record RankedSinkView(
            String sinkId,
            int rank,
            double score,
            String category,
            String symbol,
            List<String> rankReasons
    ) {
        public RankedSinkView {
            Objects.requireNonNull(sinkId, "sinkId");
            rankReasons = List.copyOf(rankReasons == null ? List.of() : rankReasons);
            category = category == null ? "" : category;
            symbol = symbol == null ? "" : symbol;
            if (rank < 1) throw new IllegalArgumentException("rank must be >= 1");
            if (!Double.isFinite(score) || score < 0) {
                throw new IllegalArgumentException("score must be a non-negative finite number");
            }
        }
    }

    public static List<RankedSinkView> rank(
            List<ApiDtos.SinkDto> sinks,
            List<BytecodeFactIndex.TaintPath> taintPaths,
            List<ApiDtos.EntryDto> entries,
            List<StaticContrastRow> contrastRows) {
        List<ApiDtos.SinkDto> sinkList = sinks == null ? List.of() : sinks;
        Set<String> taintCovered = taintCoveredSinkIds(taintPaths, sinkList);
        Set<String> authGapEntries = authGapEntryIds(entries);
        Set<String> dynamicReached = dynamicReachedSinkIds(contrastRows);

        List<Scored> scored = new ArrayList<>();
        for (ApiDtos.SinkDto sink : sinkList) {
            if (sink == null || sink.id() == null || sink.id().isBlank()) continue;
            double score = Math.max(0.0, Math.min(1.0, sink.confidence()));
            List<String> reasons = new ArrayList<>();
            reasons.add(String.format(Locale.ROOT, "confidence=%.2f", sink.confidence()));
            if (taintCovered.contains(sink.id())) {
                score += 0.15;
                reasons.add("+0.15 taintPath");
            }
            String category = sink.category() == null ? "" : sink.category().toUpperCase(Locale.ROOT);
            if (HIGH_RISK.contains(category)) {
                score += 0.10;
                reasons.add("+0.10 highRisk:" + category);
            }
            if (sinkImpliesAuthGap(sink, authGapEntries)) {
                score += 0.05;
                reasons.add("+0.05 AUTH_GAP");
            }
            if (dynamicReached.contains(sink.id())) {
                score += 0.20;
                reasons.add("+0.20 dynamicReached");
            }
            scored.add(new Scored(sink, Math.min(score, 1.50), List.copyOf(reasons)));
        }
        scored.sort(Comparator
                .comparingDouble((Scored item) -> item.score).reversed()
                .thenComparing(item -> item.sink.id()));
        List<RankedSinkView> ranked = new ArrayList<>();
        int limit = Math.min(MAX_RANKED, scored.size());
        for (int i = 0; i < limit; i++) {
            Scored item = scored.get(i);
            ranked.add(new RankedSinkView(
                    item.sink.id(), i + 1, item.score, item.sink.category(),
                    item.sink.symbol(), item.reasons));
        }
        return List.copyOf(ranked);
    }

    private static Set<String> taintCoveredSinkIds(
            List<BytecodeFactIndex.TaintPath> taintPaths, List<ApiDtos.SinkDto> sinks) {
        Set<String> covered = new LinkedHashSet<>();
        if (taintPaths == null || taintPaths.isEmpty()) return covered;
        for (ApiDtos.SinkDto sink : sinks) {
            String source = sink.source() == null ? "" : sink.source();
            for (BytecodeFactIndex.TaintPath path : taintPaths) {
                if (source.contains("taint-path=" + path.id())
                        || symbolMatches(sink.symbol(), path)) {
                    covered.add(sink.id());
                    break;
                }
            }
        }
        return covered;
    }

    private static boolean symbolMatches(String symbol, BytecodeFactIndex.TaintPath path) {
        if (symbol == null || symbol.isBlank() || path == null) return false;
        String expected = path.sinkOwner() + "#" + path.sinkMethod() + path.sinkDescriptor();
        return symbol.replace('/', '.').contains(expected.replace('/', '.'));
    }

    private static Set<String> authGapEntryIds(List<ApiDtos.EntryDto> entries) {
        Set<String> ids = new LinkedHashSet<>();
        if (entries == null) return ids;
        for (ApiDtos.EntryDto entry : entries) {
            boolean secured = entry.preconditions().stream().anyMatch(pre -> {
                String lower = pre == null ? "" : pre.toLowerCase(Locale.ROOT);
                return lower.contains("role=") || lower.contains("preauthorize")
                        || lower.contains("secured") || lower.contains("rolesallowed");
            });
            if (!secured) ids.add(entry.id());
        }
        return ids;
    }

    private static boolean sinkImpliesAuthGap(ApiDtos.SinkDto sink, Set<String> authGapEntries) {
        if ("AUTH_GAP".equalsIgnoreCase(sink.category())) return true;
        String source = sink.source() == null ? "" : sink.source();
        for (String entryId : authGapEntries) {
            if (source.contains(entryId)) return true;
        }
        return false;
    }

    private static Set<String> dynamicReachedSinkIds(List<StaticContrastRow> contrastRows) {
        Set<String> ids = new LinkedHashSet<>();
        if (contrastRows == null) return ids;
        for (StaticContrastRow row : contrastRows) {
            if (row.contrastStatus() == ContrastStatus.DYNAMIC_REACHED
                    || row.contrastStatus() == ContrastStatus.MATCHED
                    || row.contrastStatus() == ContrastStatus.PARTIAL) {
                ids.add(row.sinkId());
            }
        }
        return ids;
    }

    private record Scored(ApiDtos.SinkDto sink, double score, List<String> reasons) {
    }
}

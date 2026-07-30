package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.Sink;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic sink-perspective projection of existing {@link BytecodeFactIndex.TaintPath}
 * plus unbound sinks into static contrast rows (status {@link ContrastStatus#UNKNOWN}
 * until {@link StaticDynamicContraster} joins PathRuns).
 *
 * <p>True reverse BFS from sinks is intentionally out of scope for this MVP slice.
 */
public final class StaticContrastProjector {
    /** Soft cap for ledger rows before truncation; hard-tested in acceptance. */
    public static final int MAX_ROWS = 64;
    public static final String STOP_BUDGET = "LEDGER_ROW_BUDGET_EXHAUSTED";
    public static final String STOP_UNBOUND = "UNBOUND_SINK";
    public static final String STOP_TAINT_PROJECTED = "TAINT_PATH_PROJECTED";

    private static final Pattern TAINT_PATH_ID = Pattern.compile("taint-path=([a-zA-Z0-9._\\-]+)");

    public record Projection(List<StaticContrastRow> rows, int totalCandidates, boolean truncated,
                             String stopReason) {
        public Projection {
            rows = List.copyOf(rows == null ? List.of() : rows);
            stopReason = stopReason == null ? "" : stopReason;
        }
    }

    public Projection projectFromTaint(
            List<BytecodeFactIndex.TaintPath> taintPaths,
            List<Sink> sinks,
            List<ApiDtos.EntryDto> entries,
            Map<String, ApiDtos.EvidenceDto> evidence) {
        Map<String, List<String>> entryRefsByHandler = indexEntriesByHandler(entries, evidence);
        List<StaticContrastRow> rows = new ArrayList<>();
        Set<String> coveredSinkIds = new LinkedHashSet<>();
        int total = 0;
        boolean truncated = false;
        String stopReason = "";

        List<BytecodeFactIndex.TaintPath> paths = taintPaths == null ? List.of() : taintPaths;
        for (BytecodeFactIndex.TaintPath path : paths) {
            total++;
            if (rows.size() >= MAX_ROWS) {
                truncated = true;
                stopReason = STOP_BUDGET;
                break;
            }
            String handler = path.sourceOwner() + "#" + path.sourceMethod();
            List<String> entryRefs = entryRefsByHandler.getOrDefault(handler, List.of());
            String sinkId = findSinkIdForTaint(sinks, path.id(), path.category());
            coveredSinkIds.add(sinkId);
            rows.add(new StaticContrastRow(
                    "contrast-" + (rows.size() + 1),
                    sinkId,
                    path.category(),
                    path.sinkOwner() + "#" + path.sinkMethod() + path.sinkDescriptor(),
                    entryRefs,
                    path.id(),
                    "",
                    ContrastStatus.UNKNOWN,
                    List.of(),
                    STOP_TAINT_PROJECTED,
                    false));
        }

        List<Sink> sinkList = sinks == null ? List.of() : sinks;
        for (Sink sink : sinkList) {
            if (coveredSinkIds.contains(sink.id())) continue;
            // AUTH_GAP stays secondary — still project so ledger can show STATIC_ONLY honesty,
            // but do not invent taint paths.
            total++;
            if (rows.size() >= MAX_ROWS) {
                truncated = true;
                stopReason = STOP_BUDGET;
                break;
            }
            String taintId = extractTaintPathId(sink.source());
            List<String> entryRefs = resolveEntryRefsForSink(sink, entries, evidence);
            if (!taintId.isBlank()) {
                coveredSinkIds.add(sink.id());
                rows.add(new StaticContrastRow(
                        "contrast-" + (rows.size() + 1),
                        sink.id(),
                        sink.category(),
                        sink.symbol(),
                        entryRefs,
                        taintId,
                        "",
                        ContrastStatus.UNKNOWN,
                        List.of(),
                        STOP_TAINT_PROJECTED,
                        false));
                continue;
            }
            rows.add(new StaticContrastRow(
                    "contrast-" + (rows.size() + 1),
                    sink.id(),
                    sink.category(),
                    sink.symbol(),
                    entryRefs,
                    "",
                    "",
                    ContrastStatus.UNKNOWN,
                    List.of(),
                    entryRefs.isEmpty() ? STOP_UNBOUND : "SINK_WITHOUT_TAINT_PATH",
                    false));
        }

        if (truncated) {
            List<StaticContrastRow> marked = new ArrayList<>(rows.size());
            for (StaticContrastRow row : rows) {
                marked.add(new StaticContrastRow(
                        row.rowId(), row.sinkId(), row.category(), row.sinkSymbol(),
                        row.entryRefs(), row.taintPathId(), row.track(), row.contrastStatus(),
                        row.pathRunRefs(), STOP_BUDGET, true));
            }
            rows = marked;
        }
        return new Projection(rows, total, truncated, stopReason);
    }

    /**
     * Runtime projection from persisted scan DTO (no BytecodeFactIndex in store).
     * Recovers taintPathId from sink.source {@code taint-path=} and evidence
     * {@code classfile-taint:*}.
     */
    public Projection projectFromScan(
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.SinkDto> sinks,
            Map<String, ApiDtos.EvidenceDto> evidence) {
        List<Sink> modelSinks = new ArrayList<>();
        if (sinks != null) {
            for (ApiDtos.SinkDto sink : sinks) {
                modelSinks.add(new Sink(
                        sink.id(), sink.category(), sink.symbol(), sink.source(),
                        sink.confidence(), sink.evidenceRefs(),
                        com.aq.jvmsentinel.model.VerificationStatus.STATIC_INFERRED));
            }
        }
        // Reconstruct minimal TaintPath stubs from evidence so entryRefs + taintPathId are filled.
        List<BytecodeFactIndex.TaintPath> reconstructed = new ArrayList<>();
        if (evidence != null) {
            for (ApiDtos.EvidenceDto item : evidence.values()) {
                if (item.source() == null || !item.source().startsWith("classfile-taint:")) continue;
                String pathId = item.source().substring("classfile-taint:".length());
                String summary = item.summary() == null ? "" : item.summary();
                String sinkOwner = "";
                String sinkMethod = "";
                String sinkDesc = "()V";
                int toIdx = summary.indexOf(" path to ");
                if (toIdx < 0) toIdx = summary.indexOf(" to ");
                if (toIdx >= 0) {
                    String tail = summary.substring(toIdx);
                    int hash = tail.indexOf('#');
                    if (hash > 0) {
                        // "... to owner#method(desc)"
                        String afterTo = tail.contains(" path to ")
                                ? tail.substring(" path to ".length()).trim()
                                : tail.substring(" to ".length()).trim();
                        int cut = afterTo.indexOf(';');
                        if (cut > 0) afterTo = afterTo.substring(0, cut).trim();
                        int h = afterTo.indexOf('#');
                        if (h > 0) {
                            sinkOwner = afterTo.substring(0, h);
                            String rest = afterTo.substring(h + 1);
                            int paren = rest.indexOf('(');
                            if (paren > 0) {
                                sinkMethod = rest.substring(0, paren);
                                sinkDesc = rest.substring(paren);
                            } else {
                                sinkMethod = rest;
                            }
                        }
                    }
                }
                String sourceOwner = "";
                String sourceMethod = "";
                // Prefer matching sink that references this taint path for category / handler.
                String category = "UNKNOWN";
                for (Sink sink : modelSinks) {
                    if (sink.source() != null && sink.source().contains("taint-path=" + pathId)) {
                        category = sink.category();
                        break;
                    }
                }
                // Source handler from annotation evidence on linked entry is resolved later;
                // leave empty source so projectFromTaint still creates the row via sink loop
                // when we only have evidence — emit a stub path with empty source that is
                // skipped by empty-handler entry lookup, then sink loop recovers taint-path=.
                reconstructed.add(new BytecodeFactIndex.TaintPath(
                        pathId,
                        sourceOwner.isBlank() ? "_" : sourceOwner,
                        sourceMethod.isBlank() ? "_" : sourceMethod,
                        "()V",
                        0,
                        sinkOwner.isBlank() ? "_" : sinkOwner,
                        sinkMethod.isBlank() ? "_" : sinkMethod,
                        sinkDesc.isBlank() ? "()V" : sinkDesc,
                        category,
                        List.of(),
                        "STATIC_INFERRED"));
            }
        }
        // When reconstructed paths have placeholder source, prefer sink-source projection only.
        if (!reconstructed.isEmpty()) {
            // Drop placeholder taint stubs — sink.source already carries taint-path=.
            reconstructed = List.of();
        }
        return projectFromTaint(reconstructed, modelSinks, entries, evidence);
    }

    private static String findSinkIdForTaint(List<Sink> sinks, String taintPathId, String category) {
        if (sinks != null) {
            for (Sink sink : sinks) {
                if (sink.source() != null && sink.source().contains("taint-path=" + taintPathId)) {
                    return sink.id();
                }
            }
            for (Sink sink : sinks) {
                if (category != null && category.equalsIgnoreCase(sink.category())
                        && sink.evidenceRefs().stream().anyMatch(ref -> ref.startsWith("flow-"))) {
                    return sink.id();
                }
            }
        }
        return "sink-taint-" + taintPathId;
    }

    static String extractTaintPathId(String source) {
        if (source == null || source.isBlank()) return "";
        Matcher matcher = TAINT_PATH_ID.matcher(source);
        return matcher.find() ? matcher.group(1) : "";
    }

    static List<String> resolveEntryRefsForSink(
            Sink sink, List<ApiDtos.EntryDto> entries, Map<String, ApiDtos.EvidenceDto> evidence) {
        if (entries == null || entries.isEmpty()) return List.of();
        String sinkKey = sinkBindingKey(sink, evidence);
        LinkedHashSet<String> refs = new LinkedHashSet<>();
        for (ApiDtos.EntryDto entry : entries) {
            if (entryBindingKey(entry, evidence).equals(sinkKey)) {
                addEntryAliases(refs, entry);
            }
        }
        // AUTH_GAP sinks encode "Class#method METHOD /route" in symbol — match declaring class#method.
        if (refs.isEmpty() && sink.symbol() != null && sink.symbol().contains("#")) {
            String symbol = sink.symbol();
            int hash = symbol.indexOf('#');
            String owner = symbol.substring(0, hash).trim();
            String after = symbol.substring(hash + 1).trim();
            String method = after.split("\\s+")[0];
            String handler = owner + "#" + method;
            for (ApiDtos.EntryDto entry : entries) {
                if (entryBindingKey(entry, evidence).equals(handler)
                        || (entry.declaringClass() != null
                        && entry.declaringClass().equals(owner))) {
                    addEntryAliases(refs, entry);
                }
            }
        }
        return List.copyOf(refs);
    }

    private static Map<String, List<String>> indexEntriesByHandler(
            List<ApiDtos.EntryDto> entries, Map<String, ApiDtos.EvidenceDto> evidence) {
        Map<String, List<String>> index = new LinkedHashMap<>();
        if (entries == null) return index;
        for (ApiDtos.EntryDto entry : entries) {
            String key = entryBindingKey(entry, evidence);
            LinkedHashSet<String> aliases = new LinkedHashSet<>();
            addEntryAliases(aliases, entry);
            index.computeIfAbsent(key, ignored -> new ArrayList<>()).addAll(aliases);
        }
        return index;
    }

    /** Canonical id plus METHOD:route alias so PathRun wire joins without catalog. */
    private static void addEntryAliases(Set<String> refs, ApiDtos.EntryDto entry) {
        if (entry == null || entry.id() == null || entry.id().isBlank()) return;
        refs.add(EntryRefResolver.canonicalRef(entry));
        if ("HTTP".equalsIgnoreCase(entry.protocol())) {
            refs.add(EntryRefResolver.methodRouteRef(entry));
        }
    }

    static String entryBindingKey(ApiDtos.EntryDto entry, Map<String, ApiDtos.EvidenceDto> evidence) {
        if (evidence != null) {
            for (String ref : entry.evidenceRefs()) {
                ApiDtos.EvidenceDto item = evidence.get(ref);
                if (item != null && item.source() != null
                        && item.source().startsWith("classfile-annotation:")) {
                    return item.source().substring("classfile-annotation:".length());
                }
            }
        }
        return entry.declaringClass() == null ? "" : entry.declaringClass();
    }

    static String sinkBindingKey(Sink sink, Map<String, ApiDtos.EvidenceDto> evidence) {
        if (evidence != null) {
            for (String ref : sink.evidenceRefs()) {
                ApiDtos.EvidenceDto item = evidence.get(ref);
                if (item != null && item.source() != null
                        && item.source().startsWith("classfile-call:")) {
                    String location = item.source().substring("classfile-call:".length());
                    int descriptor = location.indexOf('(');
                    return descriptor > 0 ? location.substring(0, descriptor) : location;
                }
            }
        }
        String symbol = sink.symbol() == null ? "" : sink.symbol();
        int hash = symbol.indexOf('#');
        if (hash > 0) return symbol.substring(0, hash);
        return symbol.toLowerCase(Locale.ROOT);
    }
}

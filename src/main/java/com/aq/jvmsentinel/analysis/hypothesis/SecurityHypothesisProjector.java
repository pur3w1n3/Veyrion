package com.aq.jvmsentinel.analysis.hypothesis;

import com.aq.jvmsentinel.analysis.detector.HypothesisMerge;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Compatible projection of legacy sink findings into SecurityHypothesis (P0-12).
 * Non-AUTH_GAP sinks → DATAFLOW; AUTH_GAP → GUARD_COVERAGE (no fake sink-none).
 */
public final class SecurityHypothesisProjector {
    public static final String DETECTOR_VERSION = "static-sink-compat/0.1";
    public static final String GUARD_COVERAGE_SINK_LABEL = "guard-coverage";

    private SecurityHypothesisProjector() {
    }

    public record Result(List<SecurityHypothesis> hypotheses, List<ApiDtos.FindingDto> findings) {
        public Result {
            hypotheses = List.copyOf(hypotheses == null ? List.of() : hypotheses);
            findings = List.copyOf(findings == null ? List.of() : findings);
        }
    }

    public static Result project(String projectId,
                                 String artifactDigest,
                                 String scanId,
                                 List<ApiDtos.EntryDto> entries,
                                 List<ApiDtos.DependencyDto> dependencies,
                                 List<ApiDtos.SinkDto> sinks,
                                 Map<String, ApiDtos.EvidenceDto> evidence,
                                 List<BytecodeFactIndex.TaintPath> taintPaths,
                                 BiFunction<ApiDtos.SinkDto, Map<String, ApiDtos.EvidenceDto>, String> sinkBindingKey,
                                 BiFunction<ApiDtos.EntryDto, Map<String, ApiDtos.EvidenceDto>, String> entryBindingKey,
                                 SeverityFn severityFor,
                                 Function<String, String> categoryLabel) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(sinkBindingKey, "sinkBindingKey");
        Objects.requireNonNull(entryBindingKey, "entryBindingKey");
        Objects.requireNonNull(severityFor, "severityFor");
        Objects.requireNonNull(categoryLabel, "categoryLabel");

        List<SecurityHypothesis> hypotheses = new ArrayList<>();
        List<ApiDtos.FindingDto> findings = new ArrayList<>();
        String dependencyId = dependencies == null || dependencies.isEmpty() ? "none" : dependencies.get(0).id();
        String dependency = dependencies == null || dependencies.isEmpty() ? "none" : dependencies.get(0).target();
        Map<String, BytecodeFactIndex.TaintPath> pathsById = new LinkedHashMap<>();
        for (BytecodeFactIndex.TaintPath path : taintPaths == null ? List.<BytecodeFactIndex.TaintPath>of() : taintPaths) {
            pathsById.put(path.id(), path);
        }

        int findingIndex = 0;
        int dataflowIndex = 0;
        int guardIndex = 0;
        for (ApiDtos.SinkDto sink : sinks == null ? List.<ApiDtos.SinkDto>of() : sinks) {
            if (sink == null) continue;
            boolean authGap = sink.category() != null && "AUTH_GAP".equalsIgnoreCase(sink.category());
            BoundEntry bound = resolveEntry(sink, entries, evidence, pathsById, sinkBindingKey, entryBindingKey);
            List<String> refs = sink.evidenceRefs() == null ? List.of() : sink.evidenceRefs();

            if (authGap) {
                String hypothesisId = "hyp-gc-" + scanId + "-" + (++guardIndex);
                String entryId = bound.entryId();
                String route = bound.route();
                String sourceLabel = route.isBlank() || "UNBOUND".equals(route)
                        ? (sink.symbol() == null ? "auth-gap" : sink.symbol())
                        : route;
                SecurityHypothesis hypothesis = new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION,
                        hypothesisId,
                        scanId,
                        "AUTH_GAP",
                        HypothesisFamily.GUARD_COVERAGE,
                        HypothesisLifecycle.CANDIDATE,
                        DETECTOR_VERSION,
                        refs,
                        List.of(),
                        List.of(),
                        sourceLabel,
                        "missing-auth-guard"
                );
                hypotheses.add(hypothesis);
                String sinkId = "guard:" + hypothesisId;
                String title = "静态推断的" + categoryLabel.apply("AUTH_GAP") + "信号";
                findings.add(new ApiDtos.FindingDto(
                        ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                        "finding-" + scanId + "-" + (++findingIndex),
                        title,
                        severityFor.apply(sink.category(), sink.confidence(), bound.linked()),
                        ApiDtos.STATIC_INFERRED,
                        entryId,
                        route,
                        sinkId,
                        GUARD_COVERAGE_SINK_LABEL,
                        dependency,
                        List.of(dependencyId),
                        refs,
                        refs.size(),
                        sink.confidence(),
                        ApiDtos.MOCK,
                        null,
                        hypothesisId,
                        "AUTH_GAP"
                ));
                continue;
            }

            String hypothesisId = "hyp-df-" + scanId + "-" + (++dataflowIndex);
            String property = SecurityHypothesis.normalizeProperty(
                    sink.category() == null || sink.category().isBlank() ? "DATAFLOW_TAINT" : sink.category());
            String entryId = bound.entryId();
            String route = bound.route();
            String source = route.isBlank() || "UNBOUND".equals(route) ? "entry-unbound" : route;
            String effect = sink.symbol() == null || sink.symbol().isBlank() ? property : sink.symbol();
            SecurityHypothesis hypothesis = new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION,
                    hypothesisId,
                    scanId,
                    property,
                    HypothesisFamily.DATAFLOW,
                    HypothesisLifecycle.CANDIDATE,
                    DETECTOR_VERSION,
                    refs,
                    List.of(),
                    List.of(),
                    source,
                    effect
            );
            hypotheses.add(hypothesis);
            String title = "静态推断的" + categoryLabel.apply(sink.category()) + "信号";
            findings.add(new ApiDtos.FindingDto(
                    ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                    "finding-" + scanId + "-" + (++findingIndex),
                    title,
                    severityFor.apply(sink.category(), sink.confidence(), bound.linked()),
                    ApiDtos.STATIC_INFERRED,
                    entryId,
                    route,
                    sink.id(),
                    sink.symbol(),
                    dependency,
                    List.of(dependencyId),
                    refs,
                    refs.size(),
                    sink.confidence(),
                    ApiDtos.MOCK,
                    null,
                    hypothesisId,
                    property
            ));
        }
        return new Result(hypotheses, findings);
    }

    /** Merge projector output with non-taint detector hypotheses (P1-05); dedupe by family/property/source/effect. */
    public static List<SecurityHypothesis> mergeWithDetectors(
            List<SecurityHypothesis> projected,
            List<SecurityHypothesis> detected) {
        return HypothesisMerge.merge(projected, detected);
    }

    private static BoundEntry resolveEntry(ApiDtos.SinkDto sink,
                                           List<ApiDtos.EntryDto> entries,
                                           Map<String, ApiDtos.EvidenceDto> evidence,
                                           Map<String, BytecodeFactIndex.TaintPath> pathsById,
                                           BiFunction<ApiDtos.SinkDto, Map<String, ApiDtos.EvidenceDto>, String> sinkBindingKey,
                                           BiFunction<ApiDtos.EntryDto, Map<String, ApiDtos.EvidenceDto>, String> entryBindingKey) {
        ApiDtos.EntryDto linkedEntry = null;
        String taintPathId = StaticFactSnapshot.taintPathIdFromSink(sink, evidence);
        if (!taintPathId.isBlank()) {
            BytecodeFactIndex.TaintPath path = pathsById.get(taintPathId);
            if (path != null) {
                linkedEntry = StaticFactSnapshot.findEntryForTaintSource(entries, evidence, path);
            }
        }
        if (linkedEntry == null && entries != null) {
            String key = sinkBindingKey.apply(sink, evidence);
            linkedEntry = entries.stream()
                    .filter(entry -> entryBindingKey.apply(entry, evidence).equals(key))
                    .findFirst().orElse(null);
        }
        if (linkedEntry == null) {
            linkedEntry = matchAuthGapEntry(sink, entries);
        }
        String entryId = linkedEntry == null ? "entry-unbound" : linkedEntry.id();
        String route = linkedEntry == null ? "UNBOUND" : linkedEntry.route();
        return new BoundEntry(entryId, route == null ? "UNBOUND" : route, linkedEntry != null);
    }

    private static ApiDtos.EntryDto matchAuthGapEntry(ApiDtos.SinkDto sink, List<ApiDtos.EntryDto> entries) {
        if (entries == null || sink.symbol() == null) return null;
        String symbol = sink.symbol();
        for (ApiDtos.EntryDto entry : entries) {
            String classMethod = entry.declaringClass() + "#";
            if (symbol.contains(classMethod) && symbol.contains(entry.route())) {
                return entry;
            }
            if (entry.method() != null && !entry.method().isBlank()
                    && symbol.contains(entry.declaringClass() + "#")
                    && symbol.toUpperCase(Locale.ROOT).contains(" " + entry.method().toUpperCase(Locale.ROOT) + " ")) {
                return entry;
            }
        }
        return null;
    }

    private record BoundEntry(String entryId, String route, boolean linked) {
    }

    @FunctionalInterface
    public interface SeverityFn {
        String apply(String category, double confidence, boolean bound);
    }
}

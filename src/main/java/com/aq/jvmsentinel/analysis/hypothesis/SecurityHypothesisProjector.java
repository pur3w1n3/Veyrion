package com.aq.jvmsentinel.analysis.hypothesis;

import com.aq.jvmsentinel.analysis.detector.DetectorIds;
import com.aq.jvmsentinel.analysis.detector.HardcodedJwtSignKeyDetector;
import com.aq.jvmsentinel.analysis.detector.HardcodedRememberMeCipherDetector;
import com.aq.jvmsentinel.analysis.detector.HypothesisMerge;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * legacy sink finding 到 SecurityHypothesis 的兼容投影（P0-12）。
 * 非 AUTH_GAP sink → DATAFLOW；AUTH_GAP → GUARD_COVERAGE（无 fake sink-none）。
 * 高信号 non-taint detector hypothesis 亦可投影为 finding（仅 STATIC_INFERRED）。
 */
public final class SecurityHypothesisProjector {
    public static final String DETECTOR_VERSION = "static-sink-compat/0.1";
    public static final String GUARD_COVERAGE_SINK_LABEL = "guard-coverage";
    public static final String DETECTOR_CONFIG_SINK_LABEL = "detector-config";

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

    /**
     * 将选定高信号 non-taint detector hypothesis 投影为 finding，使 UI/report
     * 非仅 sink。始终 {@link ApiDtos#STATIC_INFERRED}；永非 DYNAMIC_CONFIRMED/VERIFIED。
     *
     * <p>Currently: {@code HARDCODED_REMEMBER_ME_CIPHER_KEY}, companion
     * {@code UNSAFE_DESERIALIZATION_SURFACE} from the rememberMe cipher detector, and
     * {@code HARDCODED_JWT_SIGN_KEY}.
     */
    public static List<ApiDtos.FindingDto> projectSelectedDetectorHypotheses(
            String projectId,
            String artifactDigest,
            String scanId,
            List<SecurityHypothesis> hypotheses,
            List<ApiDtos.FindingDto> existingFindings,
            List<ApiDtos.DependencyDto> dependencies) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        Objects.requireNonNull(scanId, "scanId");
        Set<String> alreadyBound = new LinkedHashSet<>();
        int findingIndex = 0;
        for (ApiDtos.FindingDto existing : existingFindings == null ? List.<ApiDtos.FindingDto>of() : existingFindings) {
            if (existing == null) continue;
            findingIndex++;
            if (existing.hypothesisId() != null && !existing.hypothesisId().isBlank()) {
                alreadyBound.add(existing.hypothesisId());
            }
        }
        String dependencyId = dependencies == null || dependencies.isEmpty() ? "none" : dependencies.get(0).id();
        String dependency = dependencies == null || dependencies.isEmpty() ? "none" : dependencies.get(0).target();
        List<ApiDtos.FindingDto> out = new ArrayList<>();
        for (SecurityHypothesis hyp : hypotheses == null ? List.<SecurityHypothesis>of() : hypotheses) {
            if (hyp == null || !isHighSignalDetectorHypothesis(hyp)) continue;
            if (alreadyBound.contains(hyp.hypothesisId())) continue;
            alreadyBound.add(hyp.hypothesisId());
            out.add(toDetectorFinding(
                    projectId, artifactDigest, scanId, hyp, ++findingIndex, dependency, dependencyId));
        }
        return List.copyOf(out);
    }

    /**
     * 合并 sink 投影 finding 与选定 detector-hypothesis finding（仅 append）。
     */
    public static List<ApiDtos.FindingDto> mergeFindingsWithDetectorHypotheses(
            String projectId,
            String artifactDigest,
            String scanId,
            List<ApiDtos.FindingDto> projectedFindings,
            List<SecurityHypothesis> mergedHypotheses,
            List<ApiDtos.DependencyDto> dependencies) {
        List<ApiDtos.FindingDto> merged = new ArrayList<>(
                projectedFindings == null ? List.of() : projectedFindings);
        merged.addAll(projectSelectedDetectorHypotheses(
                projectId, artifactDigest, scanId, mergedHypotheses, merged, dependencies));
        return List.copyOf(merged);
    }

    public static boolean isHighSignalDetectorHypothesis(SecurityHypothesis hyp) {
        if (hyp == null) return false;
        String property = hyp.securityProperty() == null ? "" : hyp.securityProperty();
        if (HardcodedRememberMeCipherDetector.PROP_HARDCODED_CIPHER.equals(property)) {
            return true;
        }
        if (HardcodedJwtSignKeyDetector.PROP_HARDCODED_JWT_SIGN_KEY.equals(property)) {
            return true;
        }
        if (HardcodedRememberMeCipherDetector.PROP_UNSAFE_DESER_SURFACE.equals(property)) {
            String version = hyp.detectorVersion() == null ? "" : hyp.detectorVersion();
            return version.startsWith(DetectorIds.REMEMBER_ME_CIPHER + "/");
        }
        return false;
    }

    private static ApiDtos.FindingDto toDetectorFinding(
            String projectId,
            String artifactDigest,
            String scanId,
            SecurityHypothesis hyp,
            int findingIndex,
            String dependency,
            String dependencyId) {
        String property = hyp.securityProperty();
        boolean cipherKey = HardcodedRememberMeCipherDetector.PROP_HARDCODED_CIPHER.equals(property);
        boolean jwtKey = HardcodedJwtSignKeyDetector.PROP_HARDCODED_JWT_SIGN_KEY.equals(property);
        String title = cipherKey
                ? "静态推断的硬编码 RememberMe 密钥信号"
                : jwtKey
                ? "静态推断的硬编码/默认 JWT 签名密钥信号"
                : "静态推断的 RememberMe 反序列化面信号";
        String severity = cipherKey || jwtKey ? "high" : "medium";
        double confidence = cipherKey || jwtKey ? 0.85d : 0.75d;
        List<String> refs = hyp.supportingEvidenceRefs();
        String source = hyp.source() == null || hyp.source().isBlank() ? "CONFIG" : hyp.source();
        String effect = hyp.effect() == null || hyp.effect().isBlank()
                ? DETECTOR_CONFIG_SINK_LABEL : hyp.effect();
        String sinkId = "hypothesis:" + hyp.hypothesisId();
        return new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                "finding-" + scanId + "-" + findingIndex,
                title,
                severity,
                ApiDtos.STATIC_INFERRED,
                "entry-unbound",
                truncateLabel(source, 160),
                sinkId,
                effect,
                dependency,
                List.of(dependencyId),
                refs,
                refs.size(),
                confidence,
                ApiDtos.MOCK,
                null,
                hyp.hypothesisId(),
                property
        );
    }

    private static String truncateLabel(String value, int max) {
        if (value == null) return "";
        String trimmed = value.trim();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max);
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

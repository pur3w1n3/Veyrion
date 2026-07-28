package com.aq.jvmsentinel.analysis.coverage;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.domain.universe.CoverageGap;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * Read-only projection of scan facts into {@link CoverageMatrix}.
 * unknown / unresolved / truncated / unreached are gaps and never counted as covered.
 */
public final class CoverageMatrixProjector {
    /** Test/hook: suppress detector families so recall gate can fail deliberately. */
    public enum SuppressMode {
        NONE,
        SUPPRESS_DATAFLOW,
        SUPPRESS_GUARD_COVERAGE,
        SUPPRESS_ALL_DETECTORS
    }

    private CoverageMatrixProjector() {
    }

    public static CoverageMatrix project(
            String scanId,
            Optional<StaticFactSnapshot> facts,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.DependencyDto> dependencies,
            List<ApiDtos.SinkDto> sinks,
            List<SecurityHypothesis> hypotheses,
            List<ApiDtos.PathRunDto> pathRuns) {
        return project(scanId, facts, entries, dependencies, sinks, hypotheses, pathRuns, SuppressMode.NONE);
    }

    public static CoverageMatrix project(
            String scanId,
            Optional<StaticFactSnapshot> facts,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.DependencyDto> dependencies,
            List<ApiDtos.SinkDto> sinks,
            List<SecurityHypothesis> hypotheses,
            List<ApiDtos.PathRunDto> pathRuns,
            SuppressMode suppressMode) {
        Objects.requireNonNull(scanId, "scanId");
        SuppressMode mode = suppressMode == null ? SuppressMode.NONE : suppressMode;
        StaticFactSnapshot snapshot = facts == null ? null : facts.orElse(null);
        List<ApiDtos.EntryDto> entryList = entries == null ? List.of() : entries;
        List<ApiDtos.DependencyDto> depList = dependencies == null ? List.of() : dependencies;
        List<ApiDtos.SinkDto> sinkList = sinks == null ? List.of() : sinks;
        List<SecurityHypothesis> hypList = hypotheses == null ? List.of() : hypotheses;
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;

        CoverageMatrix.ArtifactUniverseSummary universe = projectUniverse(snapshot, depList);
        List<CoverageMatrix.NamedCount> entryFamilies = projectEntryFamilies(entryList);
        CoverageMatrix.CallResolutionCounts callResolution = projectCallResolution(snapshot);
        List<CoverageMatrix.DetectorCoverage> detectors = projectDetectors(sinkList, hypList, mode);
        CoverageMatrix.DynamicExperimentCoverage dynamic = projectDynamic(runs);
        List<CoverageMatrix.NamedCount> stopReasons = projectStopReasons(snapshot, runs);
        CoverageMatrix.GapCounts gaps = projectGaps(snapshot, callResolution, dynamic, universe);

        return new CoverageMatrix(
                CoverageMatrix.SCHEMA_VERSION,
                scanId,
                universe,
                entryFamilies,
                callResolution,
                detectors,
                dynamic,
                stopReasons,
                gaps,
                CoverageMatrix.HonestyFlags.defaults(),
                null);
    }

    /**
     * Recall gate: baseline expected covered detector families must appear with signals &gt; 0
     * and countedAsCovered=true. Gaps never satisfy the gate.
     */
    public static RecallGateResult evaluateRecallGate(
            CoverageMatrix matrix, Set<String> expectedCoveredFamilies) {
        Objects.requireNonNull(matrix, "matrix");
        Set<String> expected = expectedCoveredFamilies == null
                ? Set.of() : Set.copyOf(expectedCoveredFamilies);
        Map<String, CoverageMatrix.DetectorCoverage> byFamily = new LinkedHashMap<>();
        for (CoverageMatrix.DetectorCoverage detector : matrix.detectors()) {
            byFamily.put(detector.family().toUpperCase(Locale.ROOT), detector);
        }
        List<String> missing = new ArrayList<>();
        for (String family : expected) {
            String key = family.toUpperCase(Locale.ROOT);
            CoverageMatrix.DetectorCoverage detector = byFamily.get(key);
            if (detector == null || detector.signals() <= 0 || !detector.countedAsCovered()) {
                missing.add(key);
            }
        }
        return new RecallGateResult(missing.isEmpty(), List.copyOf(missing));
    }

    public record RecallGateResult(boolean passed, List<String> missingFamilies) {
        public RecallGateResult {
            missingFamilies = List.copyOf(missingFamilies == null ? List.of() : missingFamilies);
        }
    }

    private static CoverageMatrix.ArtifactUniverseSummary projectUniverse(
            StaticFactSnapshot snapshot, List<ApiDtos.DependencyDto> dependencies) {
        if (snapshot == null) {
            return new CoverageMatrix.ArtifactUniverseSummary(
                    0, 0, 0, dependencies.size(), true, "NO_STATIC_FACTS");
        }
        ArtifactUniverse universe = snapshot.effectiveArtifactUniverse();
        if (universe != null && universe.isMaterialized()) {
            int classCount = universe.applicationClassCount() > 0
                    ? universe.applicationClassCount() : universe.classes().size();
            int dependencyCount = Math.max(universe.thirdPartyDependencyCount(), dependencies.size());
            boolean incomplete = universe.incomplete()
                    || !StaticFactSnapshot.COMPLETE.equals(snapshot.coverageStatus())
                    || !snapshot.truncateReasons().isEmpty()
                    || !snapshot.analysisCoverage().complete();
            int gapCount = universe.coverageGaps().size();
            String note = incomplete
                    ? ("ARTIFACT_UNIVERSE;gaps=" + gapCount
                    + ";coverageStatus=" + snapshot.coverageStatus()
                    + (universe.truncateReasons().isEmpty()
                    ? "" : ";truncate=" + universe.truncateReasons()))
                    : ("ARTIFACT_UNIVERSE;gaps=" + gapCount);
            return new CoverageMatrix.ArtifactUniverseSummary(
                    classCount,
                    snapshot.methods().size(),
                    snapshot.fields().size(),
                    dependencyCount,
                    incomplete,
                    note);
        }
        boolean incomplete = !StaticFactSnapshot.COMPLETE.equals(snapshot.coverageStatus())
                || !snapshot.truncateReasons().isEmpty()
                || !snapshot.analysisCoverage().complete();
        String note = incomplete
                ? ("coverageStatus=" + snapshot.coverageStatus()
                + (snapshot.truncateReasons().isEmpty() ? "" : ";truncate=" + snapshot.truncateReasons()))
                : "BOUNDED_INDEX";
        return new CoverageMatrix.ArtifactUniverseSummary(
                snapshot.classes().size(),
                snapshot.methods().size(),
                snapshot.fields().size(),
                dependencies.size(),
                incomplete,
                note);
    }

    private static List<CoverageMatrix.NamedCount> projectEntryFamilies(List<ApiDtos.EntryDto> entries) {
        Map<String, Integer> counts = new TreeMap<>();
        for (ApiDtos.EntryDto entry : entries) {
            String protocol = entry.protocol() == null || entry.protocol().isBlank()
                    ? "UNKNOWN" : entry.protocol().trim().toUpperCase(Locale.ROOT);
            counts.merge(protocol, 1, Integer::sum);
        }
        List<CoverageMatrix.NamedCount> out = new ArrayList<>();
        for (Map.Entry<String, Integer> item : counts.entrySet()) {
            out.add(new CoverageMatrix.NamedCount(item.getKey(), item.getValue()));
        }
        return out;
    }

    private static CoverageMatrix.CallResolutionCounts projectCallResolution(StaticFactSnapshot snapshot) {
        if (snapshot == null) {
            return CoverageMatrix.CallResolutionCounts.empty();
        }
        int direct = 0;
        int cha = 0;
        int unresolved = 0;
        List<BytecodeFactIndex.ResolvedCallEdge> resolved = snapshot.artifactCallGraph();
        if (!resolved.isEmpty()) {
            for (BytecodeFactIndex.ResolvedCallEdge edge : resolved) {
                if (edge == null || edge.kind() == null) {
                    unresolved++;
                    continue;
                }
                switch (edge.kind()) {
                    case DIRECT -> direct++;
                    case CHA, CONSERVATIVE_CHA -> cha++;
                    case UNRESOLVED -> unresolved++;
                }
            }
        } else {
            for (BytecodeFactIndex.CallEdge edge : snapshot.callEdges()) {
                if (edge == null || edge.kind() == null) {
                    unresolved++;
                    continue;
                }
                switch (edge.kind()) {
                    case DIRECT -> direct++;
                    case CHA, CONSERVATIVE_CHA -> cha++;
                    case UNRESOLVED -> unresolved++;
                }
            }
        }
        unresolved += snapshot.unresolvedDynamics().size();
        return new CoverageMatrix.CallResolutionCounts(direct, cha, unresolved);
    }

    private static List<CoverageMatrix.DetectorCoverage> projectDetectors(
            List<ApiDtos.SinkDto> sinks,
            List<SecurityHypothesis> hypotheses,
            SuppressMode mode) {
        Map<String, Integer> signals = new LinkedHashMap<>();
        Map<String, String> versions = new LinkedHashMap<>();
        for (SecurityHypothesis hypothesis : hypotheses) {
            if (hypothesis == null) continue;
            String family = hypothesis.family() == null
                    ? HypothesisFamily.UNKNOWN.name() : hypothesis.family().name();
            if (shouldSuppress(family, mode)) continue;
            signals.merge(family, 1, Integer::sum);
            versions.putIfAbsent(family, hypothesis.detectorVersion());
        }
        // Sink categories fill families when hypotheses are empty/suppressed for inventory visibility.
        for (ApiDtos.SinkDto sink : sinks) {
            if (sink == null || sink.category() == null) continue;
            String category = sink.category().trim().toUpperCase(Locale.ROOT);
            String family = "AUTH_GAP".equals(category)
                    ? HypothesisFamily.GUARD_COVERAGE.name()
                    : HypothesisFamily.DATAFLOW.name();
            if (shouldSuppress(family, mode)) continue;
            if (hypotheses.isEmpty()) {
                signals.merge(family, 1, Integer::sum);
                versions.putIfAbsent(family, "static-sink-compat/0.1");
            }
        }
        // Always expose expected baseline families so suppress mode yields zero-signal gaps.
        ensureFamily(signals, versions, HypothesisFamily.DATAFLOW.name(), mode);
        ensureFamily(signals, versions, HypothesisFamily.GUARD_COVERAGE.name(), mode);

        List<CoverageMatrix.DetectorCoverage> out = new ArrayList<>();
        for (Map.Entry<String, Integer> item : signals.entrySet()) {
            int count = item.getValue();
            boolean covered = count > 0;
            String note = covered ? "signals_present" : "no_signals_gap";
            if (shouldSuppress(item.getKey(), mode) || (mode != SuppressMode.NONE && count == 0)) {
                note = "suppressed_or_empty";
            }
            out.add(new CoverageMatrix.DetectorCoverage(
                    item.getKey(),
                    versions.getOrDefault(item.getKey(), "unknown"),
                    count,
                    covered,
                    note));
        }
        out.sort((a, b) -> a.family().compareToIgnoreCase(b.family()));
        return out;
    }

    private static void ensureFamily(
            Map<String, Integer> signals,
            Map<String, String> versions,
            String family,
            SuppressMode mode) {
        if (shouldSuppress(family, mode)) {
            signals.putIfAbsent(family, 0);
            versions.putIfAbsent(family, "suppressed");
            return;
        }
        signals.putIfAbsent(family, 0);
        versions.putIfAbsent(family, "static-sink-compat/0.1");
    }

    private static boolean shouldSuppress(String family, SuppressMode mode) {
        if (mode == SuppressMode.NONE) return false;
        if (mode == SuppressMode.SUPPRESS_ALL_DETECTORS) return true;
        String key = family == null ? "" : family.toUpperCase(Locale.ROOT);
        if (mode == SuppressMode.SUPPRESS_DATAFLOW) {
            return HypothesisFamily.DATAFLOW.name().equals(key);
        }
        if (mode == SuppressMode.SUPPRESS_GUARD_COVERAGE) {
            return HypothesisFamily.GUARD_COVERAGE.name().equals(key);
        }
        return false;
    }

    private static CoverageMatrix.DynamicExperimentCoverage projectDynamic(List<ApiDtos.PathRunDto> runs) {
        int unreached = 0;
        int effective = 0;
        LinkedHashSet<String> samples = new LinkedHashSet<>();
        for (ApiDtos.PathRunDto run : runs) {
            if (run == null) continue;
            String status = run.verificationStatus() == null
                    ? "" : run.verificationStatus().trim().toUpperCase(Locale.ROOT);
            if (ApiDtos.UNREACHED.equals(status)) {
                unreached++;
            } else if (!status.isBlank() && !"FAILED".equals(status) && !"BUSY".equals(status)
                    && !"CANCELLED".equals(status)) {
                effective++;
            }
            if (run.stopReason() != null && !run.stopReason().isBlank() && samples.size() < 8) {
                samples.add(run.stopReason());
            }
        }
        return new CoverageMatrix.DynamicExperimentCoverage(
                runs.size(), effective, unreached, List.copyOf(samples));
    }

    private static List<CoverageMatrix.NamedCount> projectStopReasons(
            StaticFactSnapshot snapshot, List<ApiDtos.PathRunDto> runs) {
        Map<String, Integer> counts = new TreeMap<>();
        if (snapshot != null) {
            for (String reason : snapshot.analysisCoverage().stopReasons()) {
                if (reason == null || reason.isBlank()) continue;
                counts.merge(reason.trim(), 1, Integer::sum);
            }
            for (String reason : snapshot.truncateReasons()) {
                if (reason == null || reason.isBlank()) continue;
                counts.merge("TRUNCATE:" + reason.trim(), 1, Integer::sum);
            }
            if (StaticFactSnapshot.TRUNCATED.equals(snapshot.coverageStatus())) {
                counts.merge("COVERAGE_STATUS_TRUNCATED", 1, Integer::sum);
            }
            if (StaticFactSnapshot.LEGACY_INCOMPLETE.equals(snapshot.coverageStatus())) {
                counts.merge("COVERAGE_STATUS_LEGACY_INCOMPLETE", 1, Integer::sum);
            }
        }
        for (ApiDtos.PathRunDto run : runs) {
            if (run == null || run.stopReason() == null || run.stopReason().isBlank()) continue;
            counts.merge("PATH_RUN:" + run.stopReason().trim(), 1, Integer::sum);
        }
        List<CoverageMatrix.NamedCount> out = new ArrayList<>();
        for (Map.Entry<String, Integer> item : counts.entrySet()) {
            out.add(new CoverageMatrix.NamedCount(item.getKey(), item.getValue()));
        }
        return out;
    }

    private static CoverageMatrix.GapCounts projectGaps(
            StaticFactSnapshot snapshot,
            CoverageMatrix.CallResolutionCounts callResolution,
            CoverageMatrix.DynamicExperimentCoverage dynamic,
            CoverageMatrix.ArtifactUniverseSummary universe) {
        int unknown = 0;
        int unresolved = callResolution.unresolved();
        int truncated = 0;
        int unreached = dynamic.unreachedCount();

        if (snapshot == null) {
            unknown++;
        } else {
            if (!snapshot.analysisCoverage().complete()) {
                unknown++;
            }
            if (StaticFactSnapshot.LEGACY_INCOMPLETE.equals(snapshot.coverageStatus())) {
                unknown++;
            }
            if (StaticFactSnapshot.TRUNCATED.equals(snapshot.coverageStatus())
                    || !snapshot.truncateReasons().isEmpty()) {
                truncated += Math.max(1, snapshot.truncateReasons().size());
            }
            for (String reason : snapshot.analysisCoverage().stopReasons()) {
                if (reason == null) continue;
                String upper = reason.toUpperCase(Locale.ROOT);
                if (upper.contains("UNKNOWN") || upper.contains("BUDGET")) {
                    unknown++;
                }
                if (upper.contains("TRUNC")) {
                    truncated++;
                }
            }
        }
        if (universe.incomplete()) {
            // Incomplete universe is an unknown/gap signal (not covered).
            unknown = Math.max(unknown, 1);
        }
        if (snapshot != null && snapshot.effectiveArtifactUniverse() != null
                && snapshot.effectiveArtifactUniverse().isMaterialized()
                && !snapshot.effectiveArtifactUniverse().coverageGaps().isEmpty()) {
            boolean hasUniverseUnknown = false;
            int universeTruncated = 0;
            for (CoverageGap gap : snapshot.effectiveArtifactUniverse().coverageGaps()) {
                if (gap == null || gap.kind() == null) continue;
                String kind = gap.kind();
                if (CoverageGap.KIND_BUDGET_TRUNCATED.equals(kind)) {
                    universeTruncated++;
                } else if (CoverageGap.KIND_UNEXPANDED_DEPENDENCY.equals(kind)
                        || CoverageGap.KIND_UNKNOWN_PROTOCOL.equals(kind)
                        || CoverageGap.KIND_UNKNOWN_RESOURCE.equals(kind)
                        || CoverageGap.KIND_RUNTIME_ONLY_CLASS.equals(kind)
                        || CoverageGap.KIND_STATIC_NOT_LOADED.equals(kind)
                        || CoverageGap.KIND_MULTI_VERSION_CLASS.equals(kind)
                        || CoverageGap.KIND_REFLECTION.equals(kind)
                        || CoverageGap.KIND_PROXY.equals(kind)
                        || CoverageGap.KIND_INVOKEDYNAMIC.equals(kind)
                        || CoverageGap.KIND_UNRESOLVED_CALL.equals(kind)) {
                    hasUniverseUnknown = true;
                }
            }
            if (hasUniverseUnknown) {
                unknown = Math.max(unknown, 1);
            }
            truncated += universeTruncated;
        }
        return new CoverageMatrix.GapCounts(unknown, unresolved, truncated, unreached);
    }
}

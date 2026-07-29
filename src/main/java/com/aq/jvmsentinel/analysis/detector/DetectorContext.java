package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Bounded scan facts available to non-taint detectors. Configuration lines are
 * already redacted by {@code ArtifactMetadataReader}.
 */
public record DetectorContext(
        String scanId,
        ArtifactUniverse universe,
        StaticFactSnapshot staticFacts,
        List<ApiDtos.EntryDto> entries,
        List<ApiDtos.SinkDto> sinks,
        List<ApiDtos.DependencyDto> dependencies,
        Map<String, ApiDtos.EvidenceDto> evidence,
        List<String> configurationLines,
        Path artifactPath
) {
    public DetectorContext(
            String scanId,
            ArtifactUniverse universe,
            StaticFactSnapshot staticFacts,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.SinkDto> sinks,
            List<ApiDtos.DependencyDto> dependencies,
            Map<String, ApiDtos.EvidenceDto> evidence,
            List<String> configurationLines) {
        this(scanId, universe, staticFacts, entries, sinks, dependencies, evidence,
                configurationLines, null);
    }

    public DetectorContext {
        Objects.requireNonNull(scanId, "scanId");
        if (scanId.isBlank()) throw new IllegalArgumentException("scanId must not be blank");
        universe = universe == null ? ArtifactUniverse.empty() : universe;
        staticFacts = staticFacts == null
                ? new StaticFactSnapshot(StaticFactSnapshot.LEGACY_INCOMPLETE, List.of(), null)
                : staticFacts;
        entries = List.copyOf(entries == null ? List.of() : entries);
        sinks = List.copyOf(sinks == null ? List.of() : sinks);
        dependencies = List.copyOf(dependencies == null ? List.of() : dependencies);
        evidence = evidence == null ? Map.of() : Map.copyOf(evidence);
        configurationLines = List.copyOf(configurationLines == null ? List.of() : configurationLines);
    }
}

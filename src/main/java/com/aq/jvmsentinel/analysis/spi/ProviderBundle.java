package com.aq.jvmsentinel.analysis.spi;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Gated, deduped provider outputs for one collect pass. */
public record ProviderBundle(
        int schemaVersion,
        String projectId,
        String artifactDigest,
        String scanId,
        List<ProviderContribution.ArtifactNodes> artifacts,
        List<ProviderContribution.Entry> entries,
        List<ProviderContribution.TrustBoundary> trustBoundaries,
        List<ProviderContribution.Effect> effects,
        List<ProviderContribution.Guard> guards,
        List<ProviderContribution.Sanitizer> sanitizers,
        List<ProviderContribution.MethodSummary> methodSummaries,
        List<ProviderContribution.Detector> detectors,
        List<ProviderContribution.DynamicProbe> probes,
        List<String> rejected,
        List<String> truncateReasons
) {
    public ProviderBundle {
        if (schemaVersion < 1) {
            throw new IllegalArgumentException("schemaVersion must be >= 1");
        }
        artifacts = List.copyOf(artifacts == null ? List.of() : artifacts);
        entries = List.copyOf(entries == null ? List.of() : entries);
        trustBoundaries = List.copyOf(trustBoundaries == null ? List.of() : trustBoundaries);
        effects = List.copyOf(effects == null ? List.of() : effects);
        guards = List.copyOf(guards == null ? List.of() : guards);
        sanitizers = List.copyOf(sanitizers == null ? List.of() : sanitizers);
        methodSummaries = List.copyOf(methodSummaries == null ? List.of() : methodSummaries);
        detectors = List.copyOf(detectors == null ? List.of() : detectors);
        probes = List.copyOf(probes == null ? List.of() : probes);
        rejected = List.copyOf(rejected == null ? List.of() : rejected);
        truncateReasons = List.copyOf(truncateReasons == null ? List.of() : truncateReasons);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("projectId", projectId);
        map.put("artifactDigest", artifactDigest);
        map.put("scanId", scanId);
        map.put("entryCount", entries.size());
        map.put("effectCount", effects.size());
        map.put("guardCount", guards.size());
        map.put("detectorCount", detectors.size());
        map.put("probeCount", probes.size());
        map.put("rejected", rejected);
        map.put("truncateReasons", truncateReasons);
        return map;
    }

    public List<ProviderContribution.Entry> entriesFromScope(String scope) {
        return entries.stream().filter(e -> e.declaredScope().equals(scope)).toList();
    }

    public List<ProviderContribution.Effect> effectsFromScope(String scope) {
        return effects.stream().filter(e -> e.declaredScope().equals(scope)).toList();
    }

    public List<ProviderContribution.Guard> guardsFromScope(String scope) {
        return guards.stream().filter(g -> g.declaredScope().equals(scope)).toList();
    }

    public List<ProviderContribution.Detector> detectorsFromScope(String scope) {
        return detectors.stream().filter(d -> d.declaredScope().equals(scope)).toList();
    }
}

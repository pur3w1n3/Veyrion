package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 说明：AUDIT_FLOW IR2：PathTrace/PathRun observation 后对当前 scan fact 重跑完整 detector suite
 * 并合并 hypothesis。永不提升 verification status；
 * 保留先前 observation 的非 CANDIDATE lifecycle。
 */
public final class AffectedDetectorRecompute {
    private AffectedDetectorRecompute() {
    }

    public record Result(
            int detectorHypotheses,
            int mergedTotal,
            boolean ran,
            List<SecurityHypothesis> mergedHypotheses
    ) {
        public Result {
            mergedHypotheses = List.copyOf(
                    mergedHypotheses == null ? List.of() : mergedHypotheses);
        }
    }

    public static Result recompute(
            String scanId,
            ArtifactUniverse universe,
            StaticFactSnapshot staticFacts,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.SinkDto> sinks,
            List<ApiDtos.DependencyDto> dependencies,
            Map<String, ApiDtos.EvidenceDto> evidence,
            List<String> configurationLines,
            Path artifactPath,
            List<SecurityHypothesis> existing,
            DetectorRegistry registry) {
        Objects.requireNonNull(scanId, "scanId");
        DetectorRegistry detectors = registry == null ? DetectorRegistry.defaults() : registry;
        DetectorContext context = new DetectorContext(
                scanId,
                universe,
                staticFacts,
                entries,
                sinks,
                dependencies,
                evidence,
                configurationLines,
                artifactPath);
        List<SecurityHypothesis> detected = detectors.analyzeAll(context);
        List<SecurityHypothesis> prior = existing == null ? List.of() : existing;
        List<SecurityHypothesis> merged = SecurityHypothesisProjector.mergeWithDetectors(prior, detected);
        merged = preferObservedLifecycles(prior, merged);
        return new Result(detected.size(), merged.size(), true, merged);
    }

    /** Apply merge but keep SUPPORTED/CONTRADICTED (etc.) from prior when ids/keys collide. */
    public static List<SecurityHypothesis> preferObservedLifecycles(
            List<SecurityHypothesis> prior, List<SecurityHypothesis> merged) {
        Map<String, SecurityHypothesis> byKey = new LinkedHashMap<>();
        for (SecurityHypothesis item : prior == null ? List.<SecurityHypothesis>of() : prior) {
            if (item == null) {
                continue;
            }
            byKey.put(HypothesisMerge.dedupeKey(item), item);
        }
        List<SecurityHypothesis> out = new ArrayList<>();
        for (SecurityHypothesis item : merged == null ? List.<SecurityHypothesis>of() : merged) {
            if (item == null) {
                continue;
            }
            SecurityHypothesis old = byKey.get(HypothesisMerge.dedupeKey(item));
            if (old != null && old.lifecycle() != HypothesisLifecycle.CANDIDATE
                    && item.lifecycle() == HypothesisLifecycle.CANDIDATE) {
                out.add(old);
            } else {
                out.add(item);
            }
        }
        return List.copyOf(out);
    }
}

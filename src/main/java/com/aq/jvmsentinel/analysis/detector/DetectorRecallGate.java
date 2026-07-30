package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 说明：P1-05 non-taint detector 独立 recall gate。
 * 移除拥有期望 securityProperty 的 detector 须使 gate 失败。
 */
public final class DetectorRecallGate {
    private DetectorRecallGate() {
    }

    public record Result(boolean passed, List<String> missingProperties, int observedHits) {
        public Result {
            missingProperties = List.copyOf(missingProperties == null ? List.of() : missingProperties);
        }
    }

    /**
     * 每个期望 securityProperty 在 {@code hypotheses} 至少出现一次则 pass。
     */
    public static Result evaluate(List<SecurityHypothesis> hypotheses, Set<String> expectedProperties) {
        Objects.requireNonNull(expectedProperties, "expectedProperties");
        Set<String> observed = new LinkedHashSet<>();
        if (hypotheses != null) {
            for (SecurityHypothesis hypothesis : hypotheses) {
                if (hypothesis == null || hypothesis.securityProperty() == null) continue;
                observed.add(hypothesis.securityProperty().trim().toUpperCase(Locale.ROOT));
            }
        }
        List<String> missing = new ArrayList<>();
        for (String expected : expectedProperties) {
            if (expected == null || expected.isBlank()) continue;
            String key = expected.trim().toUpperCase(Locale.ROOT);
            if (!observed.contains(key)) {
                missing.add(key);
            }
        }
        return new Result(missing.isEmpty(), missing, observed.size());
    }

    /**
     * 对 {@code context} 运行 {@code registry} 并评估期望 property。
     */
    public static Result evaluate(DetectorRegistry registry,
                                  DetectorContext context,
                                  Set<String> expectedProperties) {
        Objects.requireNonNull(registry, "registry");
        Objects.requireNonNull(context, "context");
        return evaluate(registry.analyzeAll(context), expectedProperties);
    }

    /** Registry without the named detector id (for remove-detector → fail proof). */
    public static DetectorRegistry without(DetectorRegistry registry, String detectorId) {
        Objects.requireNonNull(registry, "registry");
        String needle = detectorId == null ? "" : detectorId.trim();
        List<Detector> kept = new ArrayList<>();
        for (Detector detector : registry.detectors()) {
            if (detector == null) continue;
            if (needle.equals(detector.id())) continue;
            kept.add(detector);
        }
        return new DetectorRegistry(kept);
    }
}

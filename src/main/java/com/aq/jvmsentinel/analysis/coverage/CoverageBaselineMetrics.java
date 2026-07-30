package com.aq.jvmsentinel.analysis.coverage;

import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 从 CoverageMatrix 对 baseline ground-truth family 计算真实 TP/FP/FN/TN。
 * Metric 永非 stub placeholder — suppress/clear positive family 产生 FN 与 recall failure。
 */
public final class CoverageBaselineMetrics {
    private CoverageBaselineMetrics() {
    }

    public record GroundTruth(
            Set<String> positiveFamilies,
            Set<String> negativeFamilies
    ) {
        public GroundTruth {
            positiveFamilies = normalize(positiveFamilies);
            negativeFamilies = normalize(negativeFamilies);
        }

        public static GroundTruth of(Set<String> positives, Set<String> negatives) {
            return new GroundTruth(positives, negatives);
        }
    }

    public record Metrics(
            int truePositives,
            int falsePositives,
            int falseNegatives,
            int trueNegatives,
            double recall,
            double precision,
            boolean stub,
            List<String> missingPositives,
            List<String> unexpectedNegatives
    ) {
        public Metrics {
            missingPositives = List.copyOf(missingPositives == null ? List.of() : missingPositives);
            unexpectedNegatives = List.copyOf(unexpectedNegatives == null ? List.of() : unexpectedNegatives);
            stub = false;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("truePositives", truePositives);
            map.put("falsePositives", falsePositives);
            map.put("falseNegatives", falseNegatives);
            map.put("trueNegatives", trueNegatives);
            map.put("recall", recall);
            map.put("precision", precision);
            map.put("stub", false);
            map.put("missingPositives", missingPositives);
            map.put("unexpectedNegatives", unexpectedNegatives);
            return map;
        }
    }

    public record GateResult(boolean passed, Metrics metrics, List<String> failures) {
        public GateResult {
            failures = List.copyOf(failures == null ? List.of() : failures);
        }
    }

    /** Evaluate TP/FP/FN/TN from detector coverage vs ground truth. */
    public static Metrics evaluate(CoverageMatrix matrix, GroundTruth truth) {
        Objects.requireNonNull(matrix, "matrix");
        Objects.requireNonNull(truth, "truth");
        Map<String, CoverageMatrix.DetectorCoverage> byFamily = new LinkedHashMap<>();
        for (CoverageMatrix.DetectorCoverage detector : matrix.detectors()) {
            if (detector == null || detector.family() == null) continue;
            byFamily.put(detector.family().toUpperCase(Locale.ROOT), detector);
        }

        int tp = 0;
        int fn = 0;
        int fp = 0;
        int tn = 0;
        List<String> missing = new ArrayList<>();
        List<String> unexpected = new ArrayList<>();

        for (String family : truth.positiveFamilies()) {
            if (isCovered(byFamily.get(family))) {
                tp++;
            } else {
                fn++;
                missing.add(family);
            }
        }
        for (String family : truth.negativeFamilies()) {
            if (isCovered(byFamily.get(family))) {
                fp++;
                unexpected.add(family);
            } else {
                tn++;
            }
        }

        double recall = (tp + fn) == 0 ? 1.0 : (double) tp / (tp + fn);
        double precision = (tp + fp) == 0 ? 1.0 : (double) tp / (tp + fp);
        return new Metrics(tp, fp, fn, tn, recall, precision, false, missing, unexpected);
    }

    /**
     * Gate：每个 positive family 须 covered（positive set recall == 1）
     * 且 negative family 不得 fire。suppress 必需 detector 则 gate 失败。
     */
    public static GateResult evaluateGate(CoverageMatrix matrix, GroundTruth truth) {
        Metrics metrics = evaluate(matrix, truth);
        List<String> failures = new ArrayList<>();
        if (metrics.falseNegatives() > 0) {
            failures.add("recall:missing=" + metrics.missingPositives());
        }
        if (metrics.falsePositives() > 0) {
            failures.add("precision:unexpected=" + metrics.unexpectedNegatives());
        }
        return new GateResult(failures.isEmpty(), metrics, failures);
    }

    public static GroundTruth fromBaselineFamilies(
            Iterable<String> expectedCovered,
            Iterable<String> expectedAbsent) {
        return GroundTruth.of(toSet(expectedCovered), toSet(expectedAbsent));
    }

    private static boolean isCovered(CoverageMatrix.DetectorCoverage detector) {
        return detector != null && detector.signals() > 0 && detector.countedAsCovered();
    }

    private static Set<String> normalize(Set<String> values) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (values == null) return Set.copyOf(out);
        for (String value : values) {
            if (value == null || value.isBlank()) continue;
            out.add(value.trim().toUpperCase(Locale.ROOT));
        }
        return Set.copyOf(out);
    }

    private static Set<String> toSet(Iterable<String> values) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (values == null) return Set.of();
        for (String value : values) {
            if (value == null || value.isBlank()) continue;
            out.add(value.trim().toUpperCase(Locale.ROOT));
        }
        return Set.copyOf(out);
    }
}

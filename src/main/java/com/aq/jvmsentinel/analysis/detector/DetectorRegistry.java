package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Built-in non-taint detector registry (P1-05). AI never participates. */
public final class DetectorRegistry {
    private final List<Detector> detectors;

    public DetectorRegistry(List<Detector> detectors) {
        this.detectors = List.copyOf(detectors == null ? List.of() : detectors);
    }

    public static DetectorRegistry defaults() {
        return new DetectorRegistry(List.of(
                new GuardConsistencyDetector(),
                new OwnershipIdorDetector(),
                new DangerousConfigDetector(),
                new DeserializationConfigDetector(),
                new HardcodedRememberMeCipherDetector(),
                new HardcodedJwtSignKeyDetector(),
                new DependencyVersionDetector(),
                new ResourceLifecycleDetector(),
                new StateSequenceDetector(),
                new ConcurrencyResourceDetector()
        ));
    }

    public List<Detector> detectors() {
        return detectors;
    }

    public List<SecurityHypothesis> analyzeAll(DetectorContext context) {
        Objects.requireNonNull(context, "context");
        List<SecurityHypothesis> out = new ArrayList<>();
        for (Detector detector : detectors) {
            List<SecurityHypothesis> batch = detector.analyze(context);
            if (batch == null || batch.isEmpty()) continue;
            out.addAll(batch);
        }
        return List.copyOf(out);
    }
}

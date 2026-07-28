package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.List;

/**
 * Non-taint (and general) static detector contract (P1-05).
 * Detectors emit {@link SecurityHypothesis} only — never elevate verification status.
 */
public interface Detector {
    String id();

    String version();

    HypothesisFamily family();

    List<SecurityHypothesis> analyze(DetectorContext context);
}

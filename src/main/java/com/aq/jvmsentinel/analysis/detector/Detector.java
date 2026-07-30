package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.List;

/**
 * non-taint（及通用）静态 detector contract（P1-05）。
 * Detector 仅 emit {@link SecurityHypothesis} — 永不提升 verification status。
 */
public interface Detector {
    String id();

    String version();

    HypothesisFamily family();

    List<SecurityHypothesis> analyze(DetectorContext context);
}

package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/**
 * Emits {@link com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis} candidates.
 * Must not write Findings or elevate verification status.
 */
public interface DetectorProvider extends AnalysisProvider {
    List<ProviderContribution.Detector> contributeDetectors(ProviderContext context);
}

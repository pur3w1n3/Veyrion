package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/**
 * 输出 {@link com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis} 候选。
 * 不得写 Finding 或提升 verification status。
 */
public interface DetectorProvider extends AnalysisProvider {
    List<ProviderContribution.Detector> contributeDetectors(ProviderContext context);
}

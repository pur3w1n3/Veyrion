package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/** Emits primitive/custom SensitiveEffect models (not Findings). */
public interface EffectModelProvider extends AnalysisProvider {
    List<ProviderContribution.Effect> contributeEffects(ProviderContext context);
}

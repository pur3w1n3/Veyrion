package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/** Emits guard / ownership / tenant / AuthCoverage signals. */
public interface GuardModelProvider extends AnalysisProvider {
    List<ProviderContribution.Guard> contributeGuards(ProviderContext context);
}

package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/** Emits framework/dependency method summaries for bottom-up effect inference. */
public interface MethodSummaryProvider extends AnalysisProvider {
    List<ProviderContribution.MethodSummary> contributeMethodSummaries(ProviderContext context);
}

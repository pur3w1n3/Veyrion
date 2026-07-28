package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/** Emits source/origin trust boundaries. */
public interface TrustBoundaryProvider extends AnalysisProvider {
    List<ProviderContribution.TrustBoundary> contributeTrustBoundaries(ProviderContext context);
}

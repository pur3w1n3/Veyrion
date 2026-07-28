package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/** Emits EntrySurface candidates with registration evidence. */
public interface EntryProvider extends AnalysisProvider {
    List<ProviderContribution.Entry> contributeEntries(ProviderContext context);
}

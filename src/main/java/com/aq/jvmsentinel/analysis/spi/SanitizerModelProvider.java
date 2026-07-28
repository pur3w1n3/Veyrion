package com.aq.jvmsentinel.analysis.spi;

import java.util.List;

/** Emits sanitizer/validator semantics. */
public interface SanitizerModelProvider extends AnalysisProvider {
    List<ProviderContribution.Sanitizer> contributeSanitizers(ProviderContext context);
}

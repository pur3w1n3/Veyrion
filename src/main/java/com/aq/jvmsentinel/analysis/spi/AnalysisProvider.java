package com.aq.jvmsentinel.analysis.spi;

import java.util.Set;

/**
 * Base contract for versioned analysis providers. Providers emit IR/hypothesis
 * contributions only; they must not write Findings or elevate verification status.
 */
public interface AnalysisProvider {
    int SCHEMA_VERSION = 1;

    String id();

    /** SPI schema version this provider emits. */
    default int schemaVersion() {
        return SCHEMA_VERSION;
    }

    /** Producer/analyzer version string for provenance. */
    String providerVersion();

    Set<ProviderKind> kinds();

    /** Stable scope key this provider owns (used for unload isolation). */
    default String declaredScope() {
        return id();
    }
}

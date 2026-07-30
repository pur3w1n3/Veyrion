package com.aq.jvmsentinel.analysis.spi;

import java.util.Set;

/**
 * 版本化 analysis provider 的基础 contract。Provider emit IR/hypothesis
 * contribution 仅；不得写 Finding 或提升 verification status。
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

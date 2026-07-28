package com.aq.jvmsentinel.analysis.spi;

/** Versioned Provider SPI kinds (P1-03 / EXTENSIBLE_ANALYSIS §3.6). */
public enum ProviderKind {
    ARTIFACT,
    ENTRY,
    TRUST_BOUNDARY,
    EFFECT_MODEL,
    GUARD_MODEL,
    SANITIZER_MODEL,
    METHOD_SUMMARY,
    DETECTOR,
    DYNAMIC_PROBE
}

package com.aq.jvmsentinel.domain.universe;

/**
 * Artifact Universe node 的 ownership / provenance scope（P1-01）。
 */
public enum UniverseScope {
    APPLICATION,
    THIRD_PARTY,
    GENERATED,
    UNKNOWN
}

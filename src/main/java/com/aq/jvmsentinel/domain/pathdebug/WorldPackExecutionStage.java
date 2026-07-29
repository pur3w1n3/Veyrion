package com.aq.jvmsentinel.domain.pathdebug;

/**
 * Stages a single Docker JVM World Pack dependency mode.
 *
 * <p>One sandbox JVM hosts one mode. Cold-start exploration and later confirmation
 * are separate stages so deny-all apps can bind HTTP under stubs before honest
 * dependency exits are re-run. Selection is stage-driven, never DB-vendor-driven.</p>
 */
public enum WorldPackExecutionStage {
    /** Primary dynamic task / cold start: stubs continue deeper path exploration. */
    EXPLORATION,
    /** TRIAGE / explicit observe replay: fail closed at dependency boundary. */
    CONFIRMATION
}

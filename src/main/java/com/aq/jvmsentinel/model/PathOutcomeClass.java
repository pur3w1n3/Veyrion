package com.aq.jvmsentinel.model;

/**
 * Probe/Agent outcome 分类。AI 仅能引用这些 code；不能发明新 code。
 */
public enum PathOutcomeClass {
    COLD_START,
    AUTH_CHALLENGE,
    REACHED_NO_BIND,
    BUSINESS_TIMEOUT,
    ENGINE_BUSY,
    DEPENDENCY_MOCK_GAP,
    TRANSPORT_ERROR,
    PROBE_BUDGET,
    UNKNOWN,
    /** 无法为本 track 合成 identity。 */
    IDENTITY_UNAVAILABLE,
    /** Probe 收到未另行分类的 HTTP 响应。 */
    HTTP_OBSERVED
}

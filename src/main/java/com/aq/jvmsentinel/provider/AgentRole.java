package com.aq.jvmsentinel.provider;

/** 固定模型职责。Role 描述工作，而非 operator 授权。 */
public enum AgentRole {
    PRE_ANALYSIS,
    /**
     * 静态 auth 模型、synthetic-identity 策略、track 集合与 experiment-plan 草稿。
     * 亦可在 dynamic 401/pass-gate 证据后做第二轮 bypass 确认。
     */
    AUTH_ANALYSIS,
    /** 解读 sandbox/runtime record 并提议可 replay 检查；单独永不声称 VERIFIED。 */
    DYNAMIC_VERIFICATION,
    PATH_EXPLORATION,
    VULNERABILITY_TRIAGE,
    REPORT_GENERATION
}

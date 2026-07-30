package com.aq.jvmsentinel.ai.context;

/** 用户 prompt 各上下文块的内联行数上限。 */
public final class AiPromptLimits {
    public static final int PRIOR_ROLE_SUMMARY_CHARS = 2_048;
    public static final int MAX_PRE_ENTRY_PROMPT_ROWS = 40;
    /** 紧凑默认；可通过 scan_memory_get / facts_search 加深。 */
    public static final int MAX_PATH_RUN_PROMPT_ROWS = 12;
    public static final int MAX_BYPASS_POC_PROMPT_ROWS = 16;
    public static final int MAX_CONSTRAINT_PROMPT_ROWS = 24;
    public static final int MAX_TAINT_PATH_SUMMARY_ROWS = 8;
    public static final int MAX_FUZZ_CATEGORY_PROMPT_ROWS = 6;
    public static final int MAX_COVERAGE_GAP_PROMPT_ROWS = 20;
    /** PATH/TRIAGE「计划 vs 实际」内联行数；过大易顶破 chat user text 128KiB 上限。 */
    public static final int MAX_TRACE_PLAN_DIFF_PROMPT_ROWS = 8;
    /**
     * FINDING_BINDINGS_FACTS prompt 内联上限（与交付报告分离）。
     * 交付全集见 {@link com.aq.jvmsentinel.ai.FindingBindings#assembleDetailed}。
     */
    public static final int MAX_FINDING_BINDINGS_PROMPT_ROWS =
            com.aq.jvmsentinel.ai.FindingBindings.MAX_PROMPT_BINDINGS;
    /** 现编 TracePlan 上限（无持久化计划时）。 */
    public static final int MAX_TRACE_PLAN_COMPILE_FOR_PROMPT = 24;

    private AiPromptLimits() {
    }
}

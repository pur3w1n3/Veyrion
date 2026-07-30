package com.aq.jvmsentinel.ai.prompt;

import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 从 job 快照解析输出语言，并生成 locale-pure 指令片段。
 */
public final class AiPromptLanguage {
    private static final ObjectMapper JSON = new ObjectMapper();

    private AiPromptLanguage() {
    }

    public static AiOutputLanguage parseOutputLanguage(String policySnapshotJson) {
        try {
            JsonNode policy = JSON.readTree(policySnapshotJson);
            return AiOutputLanguage.parse(policy.path("outputLanguage").asText(AiOutputLanguage.ZH_CN.name()));
        } catch (Exception invalid) {
            throw new IllegalArgumentException("AI_JOB_SNAPSHOT_INVALID");
        }
    }

    public static String languageInstruction(AiOutputLanguage language) {
        return language == AiOutputLanguage.ZH_CN
                ? "所有面向分析师的内容必须使用简体中文（locale-pure）；章节标题、说明、PoC 步骤不得夹杂英文 Markdown 标题"
                + "（禁止 ## Key Findings / ## Vulnerabilities / ## Executive Summary / ## Findings 等英文专章）。"
                + "类名、方法、路由、证据 ID、状态枚举与 JSON 字段名保持原文。\n"
                : "Write all analyst-facing content in English only (locale-pure); section titles, narration, and PoC "
                + "steps must not mix Chinese Markdown headers "
                + "(forbidden: ## 关键发现 / ## 漏洞相关 / ## 执行摘要 / ## 修复建议). "
                + "Preserve class names, methods, routes, evidence IDs, status enums, and JSON field names verbatim.\n";
    }

    public static String finalInstruction(AiOutputLanguage language) {
        return language == AiOutputLanguage.ZH_CN
                ? "服务端工具阶段已关闭。仅使用已返回证据，立即输出最终中文 Markdown 推断；"
                + "不得继续请求、假设或描述新的工具调用。"
                : "The server tool phase is closed. Use only the evidence already returned and provide the final "
                + "English Markdown inference now. Do not request, assume, or describe more tool calls.";
    }

    /** final-only 轮模型仍返回 tool_calls 后的有界 re-ask；不得重新开放工具。 */
    public static String toolPhaseClosedReask(AiOutputLanguage language) {
        return language == AiOutputLanguage.ZH_CN
                ? "上轮工具请求已被服务端拒绝（工具阶段已关闭，工具调用不会执行）。"
                + "请勿再发起任何工具调用；仅基于已返回证据直接输出最终中文 Markdown 推断。"
                : "Your previous tool request was rejected by the server (tool phase closed; tools will not run). "
                + "Do not request any more tools. Provide the final English Markdown inference from evidence "
                + "already returned.";
    }
}

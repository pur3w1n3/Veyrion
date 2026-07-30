package com.aq.jvmsentinel.ai.prompt;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.provider.AiOutputLanguage;

import java.util.List;

/** AUTH/DYNAMIC 补写轮次的 repair 用户指令。 */
public final class AiRepairPrompts {
    private AiRepairPrompts() {
    }

    public static String authBypassPocRepairInstruction(
            AiOutputLanguage language, AuthBypassFeasibility.AuthSurface surface) {
        if (language == AiOutputLanguage.ZH_CN) {
            return AuthBypassFeasibility.ENFORCEMENT_REQUIRED
                    + "：服务端检测到鉴权面（jwtSinks=" + surface.jwtSinkCount()
                    + ", authGapSinks=" + surface.authGapSinkCount()
                    + ", authAnnotatedEntries=" + surface.authAnnotatedEntryCount()
                    + "），但你的最终回答未包含有效 bypassPoCs。"
                    + "请立即输出含非空 bypassPoCs 数组的 JSON（entryRef、techniqueId、track、rationale、"
                    + "evidenceRefs、confidence，以及 authorizationHeader/JWT/query/bodyHint 假设）。"
                    + "对不可行入口须给出明确 infeasible 条目，不得再返回空数组。"
                    + "不得宣称已绕过或 VERIFIED；工具阶段已关闭。";
        }
        return AuthBypassFeasibility.ENFORCEMENT_REQUIRED
                + ": auth surface present (jwtSinks=" + surface.jwtSinkCount()
                + ", authGapSinks=" + surface.authGapSinkCount()
                + ", authAnnotatedEntries=" + surface.authAnnotatedEntryCount()
                + ") but your final answer had no valid bypassPoCs. "
                + "Immediately emit a JSON object with a non-empty bypassPoCs array "
                + "(entryRef, techniqueId, track, rationale, evidenceRefs, confidence, and "
                + "authorizationHeader/JWT/query/bodyHint hypotheses). "
                + "Per-entry infeasible rows are allowed; an empty array is not. "
                + "Do not claim bypass or VERIFIED. Tool phase is closed.";
    }

    public static String dynamicPocAttemptRepairInstruction(
            AiOutputLanguage language, List<AuthBypassCandidate> topTargets) {
        StringBuilder targets = new StringBuilder();
        int shown = 0;
        for (AuthBypassCandidate candidate : topTargets == null ? List.<AuthBypassCandidate>of() : topTargets) {
            if (shown >= AuthBypassFeasibility.DYNAMIC_POC_PROBE_MAX) break;
            targets.append("- ").append(candidate.entryRef())
                    .append(" techniqueId=").append(candidate.techniqueId())
                    .append(" hasAuthMaterial=").append(candidate.hasAuthMaterial())
                    .append('\n');
            shown++;
        }
        if (language == AiOutputLanguage.ZH_CN) {
            return AuthBypassFeasibility.DYNAMIC_ATTEMPT_REQUIRED
                    + "：AUTH_BYPASS_FEASIBILITY 非空，但本轮尚未调用 sandbox_probe。"
                    + "工具阶段已重新打开。请立即对下列 top-N PoC 逐条调用 sandbox_probe"
                    + "（entrypointRef + techniqueId，有 authorizationHeader 时必须传入），"
                    + "完成后再给证据对照结论。禁止纯叙事结案；不得宣称 VERIFIED。\n"
                    + targets;
        }
        return AuthBypassFeasibility.DYNAMIC_ATTEMPT_REQUIRED
                + ": AUTH_BYPASS_FEASIBILITY is non-empty but sandbox_probe was never called. "
                + "Tool phase is re-opened. Immediately call sandbox_probe for each top-N PoC below "
                + "(entrypointRef + techniqueId; include authorizationHeader when present), "
                + "then conclude with evidence comparison. Narrative-only is rejected; "
                + "do not claim VERIFIED.\n"
                + targets;
    }

    public static String authCodeQueryRepairInstruction(
            AiOutputLanguage language, AuthBypassFeasibility.AuthSurface surface) {
        if (language == AiOutputLanguage.ZH_CN) {
            return AuthBypassFeasibility.CODE_QUERY_REQUIRED
                    + "：鉴权面存在（jwtSinks=" + surface.jwtSinkCount()
                    + ", authGapSinks=" + surface.authGapSinkCount()
                    + ", authAnnotatedEntries=" + surface.authAnnotatedEntryCount()
                    + "），但本轮尚未成功调用 code_query。"
                    + "工具阶段已重新打开：请先 code_query 查询 Filter/Interceptor、鉴权注解、JWT/session/"
                    + "API key、skip URL、租户/角色分支，再用证据 ID 填写 bypassPoCs.evidenceRefs。"
                    + "不得宣称 VERIFIED。";
        }
        return AuthBypassFeasibility.CODE_QUERY_REQUIRED
                + ": auth surface present (jwtSinks=" + surface.jwtSinkCount()
                + ", authGapSinks=" + surface.authGapSinkCount()
                + ", authAnnotatedEntries=" + surface.authAnnotatedEntryCount()
                + ") but code_query has not succeeded. Tool phase is re-opened: call code_query first "
                + "for Filter/Interceptor, auth annotations, JWT/session/API key, skip URL, tenant/role "
                + "branches, then cite evidence IDs in bypassPoCs. Never claim VERIFIED.";
    }

    public static String authPocDiversityRepairInstruction(
            AiOutputLanguage language, AuthBypassFeasibility.AuthSurface surface, int distinct) {
        if (language == AiOutputLanguage.ZH_CN) {
            return AuthBypassFeasibility.POC_DIVERSITY_REQUIRED
                    + "：当前仅有 " + distinct + " 个结构不同 PoC，目标至少 "
                    + AuthBypassFeasibility.AUTH_POC_MECHANISM_MIN
                    + " 个（按机制/过闸路径去重），或对缺口逐条给出 infeasibleEntries（含 entryRef+reason/"
                    + "evidenceRef）。不得只提交重复 payload 变体。工具阶段已关闭。";
        }
        return AuthBypassFeasibility.POC_DIVERSITY_REQUIRED
                + ": only " + distinct + " structurally distinct PoC(s); need at least "
                + AuthBypassFeasibility.AUTH_POC_MECHANISM_MIN
                + " mechanism/path-deduped candidates, or infeasibleEntries with entryRef+reason/"
                + "evidenceRef for each gap. Duplicate payload variants are rejected. Tool phase closed.";
    }
}

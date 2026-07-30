package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;


/** 鉴权面、PoC 与确认上下文。 */
public final class AuthContextBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunContextBuilder pathRuns;

    public AuthContextBuilder(ControlPlaneStore store, PathRunSource pathRunSource) {
        this(store, new PathRunContextBuilder(store, pathRunSource));
    }

    public AuthContextBuilder(ControlPlaneStore store, PathRunContextBuilder pathRuns) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRuns = java.util.Objects.requireNonNull(pathRuns, "pathRuns");
    }

    public String authConfigHypothesisContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.AUTH_ANALYSIS || job.scanId() == null) return "";
        try {
            List<SecurityHypothesis> hyps = store.hypotheses(job.scanId());
            List<SecurityHypothesis> selected = hyps.stream()
                    .filter(h -> h != null
                            && ("HARDCODED_REMEMBER_ME_CIPHER_KEY".equals(h.securityProperty())
                            || ("UNSAFE_DESERIALIZATION_SURFACE".equals(h.securityProperty())
                            && h.detectorVersion() != null
                            && h.detectorVersion().startsWith("remember-me-cipher/"))))
                    .limit(8)
                    .toList();
            if (selected.isEmpty()) return "";
            StringBuilder block = new StringBuilder();
            if (language == AiOutputLanguage.ZH_CN) {
                block.append("AUTH_CONFIG_HYPOTHESES（服务端 CONFIG/TYPESTATE FACT 候选；STATIC_INFERRED；"
                        + "优先引用，勿猜 kPH+；SLICE_EMPTY≠未发现）：\n");
            } else {
                block.append("AUTH_CONFIG_HYPOTHESES (server CONFIG/TYPESTATE FACT candidates; "
                        + "STATIC_INFERRED; cite these over kPH+ guesses; SLICE_EMPTY≠miss):\n");
            }
            for (SecurityHypothesis hyp : selected) {
                block.append("- hypothesisId=").append(hyp.hypothesisId())
                        .append(" property=").append(hyp.securityProperty())
                        .append(" family=").append(hyp.family().name());
                if (hyp.source() != null && !hyp.source().isBlank()) {
                    block.append(" source=").append(hyp.source());
                }
                if (hyp.effect() != null && !hyp.effect().isBlank()) {
                    block.append(" effect=").append(hyp.effect());
                }
                block.append('\n');
            }
            return block.toString();
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    public String authSurfacePromptContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.AUTH_ANALYSIS || job.scanId() == null) return "";
        AuthBypassFeasibility.AuthSurface surface = loadAuthSurface(job);
        if (!surface.present()) {
            return language == AiOutputLanguage.ZH_CN
                    ? "AUTH_SURFACE：当前扫描未检出 JWT/AUTH_GAP/鉴权标注入口；bypassPoCs 可为空但须写 emptyReason。\n"
                    : "AUTH_SURFACE: no JWT/AUTH_GAP/auth-annotated entries; empty bypassPoCs allowed with emptyReason.\n";
        }
        StringBuilder block = new StringBuilder();
        if (language == AiOutputLanguage.ZH_CN) {
            block.append("AUTH_SURFACE（服务端静态信号；存在鉴权面时 bypassPoCs 不得为空）：\n")
                    .append("- jwtSinkCount=").append(surface.jwtSinkCount())
                    .append(" authGapSinkCount=").append(surface.authGapSinkCount())
                    .append(" jwtOrAuthGapFindingCount=").append(surface.jwtOrAuthGapFindingCount())
                    .append(" authAnnotatedEntryCount=").append(surface.authAnnotatedEntryCount())
                    .append('\n');
            if (!surface.sampleEntryRefs().isEmpty()) {
                block.append("- sampleEntryRefs=").append(surface.sampleEntryRefs()).append('\n');
            }
            block.append("- 必须输出非空 bypassPoCs（含 authorizationHeader/JWT 假设或逐条 infeasible）。")
                    .append("空数组将触发 AUTH_BYPASS_POC_REQUIRED。\n");
        } else {
            block.append("AUTH_SURFACE (server static signals; non-empty bypassPoCs required):\n")
                    .append("- jwtSinkCount=").append(surface.jwtSinkCount())
                    .append(" authGapSinkCount=").append(surface.authGapSinkCount())
                    .append(" jwtOrAuthGapFindingCount=").append(surface.jwtOrAuthGapFindingCount())
                    .append(" authAnnotatedEntryCount=").append(surface.authAnnotatedEntryCount())
                    .append('\n');
            if (!surface.sampleEntryRefs().isEmpty()) {
                block.append("- sampleEntryRefs=").append(surface.sampleEntryRefs()).append('\n');
            }
            block.append("- Emit non-empty bypassPoCs (authorizationHeader/JWT hypotheses or per-entry infeasible). ")
                    .append("Empty array triggers AUTH_BYPASS_POC_REQUIRED.\n");
        }
        return block.toString();
    }

    public AuthBypassFeasibility.AuthSurface loadAuthSurface(
            SQLiteControlPlanePersistence.AiJobData job) {
        if (job == null || job.scanId() == null) {
            return new AuthBypassFeasibility.AuthSurface(false, 0, 0, 0, 0, List.of());
        }
        try {
            return AuthBypassFeasibility.detectAuthSurface(store.requireScan(job.scanId()).dto());
        } catch (RuntimeException ignored) {
            return new AuthBypassFeasibility.AuthSurface(false, 0, 0, 0, 0, List.of());
        }
    }
    public String authBypassConfirmPromptContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.AUTH_ANALYSIS) return "";
        List<ApiDtos.PathRunDto> runs = pathRuns.loadPathRuns(job);
        boolean confirmPass = isAuthBypassConfirmPass(job, runs);
        StringBuilder block = new StringBuilder();
        if (language == AiOutputLanguage.ZH_CN) {
            block.append("AUTH_BYPASS_CONFIRMATION（服务端证据门禁；结论须带 bypassConfirmation）：\n");
            if (confirmPass) {
                block.append("- 本轮为动态后的绕过确认（AUTH_BYPASS_CONFIRM）。必须对照 PATH_RUN_FACTS。\n")
                        .append("- bypassConfirmation.status 只能是 HYPOTHESIS 或 DYNAMIC_CONTRAST；")
                        .append("无 AUTH_CHALLENGE / BYPASS_CANDIDATE|ADMIN 过闸（2xx/3xx）PathRun 时")
                        .append("不得写 DYNAMIC_CONTRAST，也不得宣称已绕过。\n")
                        .append("- pathRunRefs 仅引用真实 pathRunId。零动态证据时服务端会改写为 ")
                        .append("INSUFFICIENT_EVIDENCE。\n");
            } else {
                block.append("- 本轮为静态可行性假设；bypassConfirmation.status=HYPOTHESIS。\n")
                        .append("- 零 PathRun 证据时禁止宣称已绕过或 DYNAMIC_CONTRAST。\n");
            }
        } else {
            block.append("AUTH_BYPASS_CONFIRMATION (server evidence gate; emit bypassConfirmation):\n");
            if (confirmPass) {
                block.append("- This is the post-dynamic bypass confirm pass (AUTH_BYPASS_CONFIRM). ")
                        .append("Cross-check PATH_RUN_FACTS.\n")
                        .append("- bypassConfirmation.status is HYPOTHESIS or DYNAMIC_CONTRAST only when ")
                        .append("PathRuns show AUTH_CHALLENGE or BYPASS_CANDIDATE/ADMIN pass-gate (2xx/3xx). ")
                        .append("Without that evidence do not claim bypass confirmed.\n")
                        .append("- pathRunRefs must cite real pathRunId values. Server rewrites to ")
                        .append("INSUFFICIENT_EVIDENCE when claims lack evidence.\n");
            } else {
                block.append("- This pass is static feasibility; use bypassConfirmation.status=HYPOTHESIS.\n")
                        .append("- With zero PathRun evidence never claim bypass confirmed or DYNAMIC_CONTRAST.\n");
            }
        }
        return block.toString();
    }

    public boolean isAuthBypassConfirmPass(
            SQLiteControlPlanePersistence.AiJobData job, List<ApiDtos.PathRunDto> pathRuns) {
        if (job == null || job.role() != AgentRole.AUTH_ANALYSIS) return false;
        if (pathRuns != null && !pathRuns.isEmpty()) return true;
        return countPriorAuthJobs(job) >= 1;
    }

    public int countPriorAuthJobs(SQLiteControlPlanePersistence.AiJobData job) {
        if (job == null || job.scanId() == null) return 0;
        try {
            return (int) store.aiJobs(job.projectId()).stream()
                    .filter(item -> job.scanId().equals(item.scanId()))
                    .filter(item -> item.role() == AgentRole.AUTH_ANALYSIS)
                    .filter(item -> !Objects.equals(item.aiJobId(), job.aiJobId()))
                    .filter(item -> "COMPLETED".equals(item.status())
                            || "QUEUED".equals(item.status())
                            || "RUNNING".equals(item.status()))
                    .count();
        } catch (RuntimeException ignored) {
            return 0;
        }
    }
    public List<AuthBypassCandidate> loadFeasibilityPoCs(SQLiteControlPlanePersistence.AiJobData job) {
        if (job == null || job.scanId() == null) return List.of();
        List<AuthBypassCandidate> candidates = new ArrayList<>();
        for (SQLiteControlPlanePersistence.AiJobData prior : store.aiJobs(job.projectId())) {
            if (!job.scanId().equals(prior.scanId())
                    || prior.role() != AgentRole.AUTH_ANALYSIS
                    || !"COMPLETED".equals(prior.status())
                    || prior.conclusionJson() == null) {
                continue;
            }
            candidates.addAll(AuthBypassFeasibility.fromConclusionJson(prior.conclusionJson()));
        }
        Map<String, AuthBypassCandidate> deduped = new LinkedHashMap<>();
        for (AuthBypassCandidate candidate : candidates) {
            deduped.putIfAbsent(
                    candidate.entryRef() + "|" + candidate.techniqueId() + "|" + candidate.track().name(),
                    candidate);
        }
        return List.copyOf(deduped.values());
    }
    public String authBypassFeasibilityContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null) return "";
        if (job.role() != AgentRole.DYNAMIC_VERIFICATION
                && job.role() != AgentRole.AUTH_ANALYSIS
                && job.role() != AgentRole.VULNERABILITY_TRIAGE
                && job.role() != AgentRole.PATH_EXPLORATION) {
            return "";
        }
        List<AuthBypassCandidate> unique = loadFeasibilityPoCs(job);
        String emptyReason = "";
        for (SQLiteControlPlanePersistence.AiJobData prior : store.aiJobs(job.projectId())) {
            if (!job.scanId().equals(prior.scanId())
                    || prior.role() != AgentRole.AUTH_ANALYSIS
                    || !"COMPLETED".equals(prior.status())
                    || prior.conclusionJson() == null) {
                continue;
            }
            emptyReason = AuthBypassFeasibility.emptyReasonFromConclusion(prior.conclusionJson());
            if (!emptyReason.isBlank()) break;
        }
        if (unique.isEmpty() && job.role() == AgentRole.AUTH_ANALYSIS) {
            return "";
        }
        StringBuilder block = new StringBuilder();
        if (language == AiOutputLanguage.ZH_CN) {
            block.append("AUTH_BYPASS_FEASIBILITY（AUTH 研判的绕过 PoC；服务端已 schema 校验；")
                    .append("属 INFERENCE 假设。DYNAMIC 应优先 sandbox_probe 尝试；不得单独升验证状态）：\n");
        } else {
            block.append("AUTH_BYPASS_FEASIBILITY (AUTH-authored bypass PoCs; server schema-validated; ")
                    .append("INFERENCE only. DYNAMIC should attempt via sandbox_probe; never alone upgrade status):\n");
        }
        if (unique.isEmpty()) {
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- 无已校验 PoC"
                    + (emptyReason.isBlank() ? "。\n" : "： " + emptyReason + "\n")
                    : "- No validated PoCs"
                    + (emptyReason.isBlank() ? ".\n" : ": " + emptyReason + "\n"));
            return block.toString();
        }
        int emitted = 0;
        for (AuthBypassCandidate candidate : unique) {
            if (emitted >= AiPromptLimits.MAX_BYPASS_POC_PROMPT_ROWS) break;
            try {
                ObjectNode row = AuthBypassFeasibility.toJson(candidate);
                // 保持 prompt 有界：包含 auth material 存在性与截断后的 header。
                if (candidate.hasAuthMaterial()) {
                    String token = candidate.authorizationHeader();
                    row.put("authorizationHeader", token.length() <= 240
                            ? token : token.substring(0, 240));
                }
                block.append("- ").append(JSON.writeValueAsString(row)).append('\n');
            } catch (Exception ignored) {
                block.append("- entryRef=").append(candidate.entryRef())
                        .append(" techniqueId=").append(candidate.techniqueId())
                        .append(" track=").append(candidate.track().name()).append('\n');
            }
            emitted++;
        }
        if (unique.size() > AiPromptLimits.MAX_BYPASS_POC_PROMPT_ROWS) {
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- …另有 " + (unique.size() - AiPromptLimits.MAX_BYPASS_POC_PROMPT_ROWS) + " 条未内联。\n"
                    : "- …" + (unique.size() - AiPromptLimits.MAX_BYPASS_POC_PROMPT_ROWS) + " more omitted.\n");
        }
        if (job.role() == AgentRole.DYNAMIC_VERIFICATION) {
            int target = Math.min(AuthBypassFeasibility.DYNAMIC_POC_PROBE_MAX,
                    Math.max(AuthBypassFeasibility.DYNAMIC_POC_PROBE_MIN, Math.min(unique.size(),
                            AuthBypassFeasibility.DYNAMIC_POC_PROBE_MAX)));
            if (unique.size() < AuthBypassFeasibility.DYNAMIC_POC_PROBE_MIN) {
                target = unique.size();
            }
            if (language == AiOutputLanguage.ZH_CN) {
                block.append("强制：在结论前必须对至少 ").append(target)
                        .append(" 条（至多 ")
                        .append(Math.min(AuthBypassFeasibility.DYNAMIC_POC_PROBE_MAX, unique.size()))
                        .append(" 条）PoC 调用 sandbox_probe(entrypointRef, techniqueId, authorizationHeader, candidateInputs)；")
                        .append("不得仅用 PATH_RUN_FACTS / facts_search 叙事结案。零探针将触发 ")
                        .append(AuthBypassFeasibility.DYNAMIC_ATTEMPT_REQUIRED).append("。\n");
            } else {
                block.append("REQUIRED: before concluding, call sandbox_probe(entrypointRef, techniqueId, ")
                        .append("authorizationHeader, candidateInputs) for at least ").append(target)
                        .append(" and at most ")
                        .append(Math.min(AuthBypassFeasibility.DYNAMIC_POC_PROBE_MAX, unique.size()))
                        .append(" PoCs. Narrative-only / facts_search-only is rejected; zero probes trigger ")
                        .append(AuthBypassFeasibility.DYNAMIC_ATTEMPT_REQUIRED).append(".\n");
            }
        }
        return block.toString();
    }
}

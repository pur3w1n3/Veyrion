package com.aq.jvmsentinel.ai.prompt;

import com.aq.jvmsentinel.ai.FindingBindings;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** 各 AgentRole 的固定/可定制角色指令与 REPORT 专章合同。 */
public final class AiRolePrompts {
    private static final ObjectMapper JSON = new ObjectMapper();

    private AiRolePrompts() {
    }

    public static String roleInstruction(
            com.aq.jvmsentinel.provider.AgentRole role, AiOutputLanguage language) {
        if (language == AiOutputLanguage.ZH_CN) {
            return switch (role) {
                case PRE_ANALYSIS -> """
                        优先消费已注入的 SCAN_MEMORY_INDEX、SCAN_SUMMARY、ENTRY_SUMMARY、RANKED_SINK_CATALOG；
                        INDEX 已在上下文时勿再 scan_memory_get section=INDEX；深挖用 section=FACTS|WORK
                        （ROLE_SLICE 时才可选 role=，默认当前任务角色）。
                        需要更多条目时 facts_search：query 用 entryId/route/class（勿用 * 或单空格；空 query=列表）。
                        建立入口、业务模块、参数/权限前置条件、依赖和敏感触发点模型，并补充静态索引可能遗漏的入口候选。
                        需要子图细节时用 code_query kind=TAINT_GRAPH（可带 sinkId/entryId）。
                        补充项必须标记为 MODEL_SUPPLEMENT、给出理由和证据引用；不得改写或伪造静态事实，
                        不得把补充入口直接标成运行时可达。
                        """;
                case AUTH_ANALYSIS -> """
                        基于静态事实与 PRE_ANALYSIS 假设，建立鉴权模型并输出结构化绕过可行性 PoC（假设，非已验证）。
                        消费 FRAMEWORK_ADAPTER_CONTEXT 与 PARAMETER_CONSTRAINT_HINTS：适配器信号仅为 HINT，
                        不得当作已提取密钥的 FACT；用参数约束精化 authorizationHeader / claims / query / bodyHint。
                        必须先调用 code_query 从授权制品中收获 JWT sign-key、skip-url、@PreAuth、TokenFilter、
                        Secure/Jwt 类、RememberMe/COOKIE_MATERIAL 等材料，再写 bypassPoCs，并用 code_query 证据 ID 填 evidenceRefs。
                        不得假设全局硬编码商业密钥为 FACT；仅当 code_query 回报 jwtSecretMaterialFound/
                        secretCandidates.mintable=true 时才可提出 DEFAULT_SECRET_HS256 并引用证据。
                        若存在 HARDCODED_REMEMBER_ME_CIPHER_KEY / COOKIE_MATERIAL / rememberMeCipherMaterialFound，
                        优先引用这些 FACT 与 hyp-rmc 假设，禁止凭空猜测 kPH+ 字典密钥；METHOD_VIEW SLICE_EMPTY
                        不能当作「未发现 cipherKey」。Cookie 通道可用 REMEMBER_ME_COOKIE / CUSTOM_POC（非 JWT）。
                        无密钥材料时优先 MISSING_AUTH / EMPTY_BEARER / ALG_NONE 等不依赖密钥的技术。
                        必须通过 plan_propose 或最终回答中的 bypassPoCs/bypassCandidates JSON 给出条目：
                        entryRef、techniqueId、track、rationale、evidenceRefs、confidence，以及你研判需要的
                        authorizationHeader / secondaryAuthorizationHeader（兼容别名 bladeAuthHeader）/
                        query / bodyHint（可含 JWT、alg-none、自定义 claims）。
                        服务端只做 schema/边界校验后交给动态验证执行；不得改网络/挂载/命令。
                        只能用 facts_search/evidence_get/plan_propose/code_query。
                        有 PathRun 时用 kind=PATH_RUN 核对。
                        结论须含 bypassConfirmation：{status:HYPOTHESIS|DYNAMIC_CONTRAST, pathRunRefs:[...]}；
                        零动态 PathRun 证据不得宣称已绕过，也不得写 DYNAMIC_CONTRAST。
                        AUTH_GAP 仅为次级静态信号。
                        若扫描存在 JWT / AUTH_GAP / 鉴权标注入口，bypassPoCs 不得为空：须给出可探针假设，
                        或对入口给出明确 infeasible 条目（仍含 techniqueId/rationale/evidenceRefs）；
                        仅当鉴权面为零时才允许空列表并写 emptyReason。服务端对有鉴权面却空列表会强制补写一次或填充 RULE_GENERATED 草案。
                        """;
                case PATH_EXPLORATION -> """
                        只能消费前置建模、鉴权分析、动态验证、沙箱 PathRun（HTTP/Agent/SQL）、
                        PathTrace（facts_search kind=PATH_TRACE）与
                        CONTRAST_LEDGER / STATIC_CONTRAST 结果，重新建立多条互相区分的路径模型。
                        优先消费 PathTrace.effectRefs（EFFECT:FILE_WRITE|FILE_READ|FILE_DELETE|SSRF|EXPRESSION|…
                        及 sink 符号；旧 EFFECT:FILE 仍表示写）与 EFFECT 事件 attributes 的
                        targetClass/targetMethod，将运行时效果绑回静态 sink/finding。
                        优先消费 COVERAGE_GAP_FACTS：对每条 gap 生成可探针 nextExperiment；
                        需要污点子图时用 code_query kind=TAINT_GRAPH。
                        每条链路必须写明入口、身份轨、实际请求与响应、数据/状态转换、可能触发点、证据引用、
                        反证、置信度和停止条件；不得把未执行的候选写成事实。
                        可对 MATCHED/PARTIAL 建可探针 nextExperiments；STATIC_ONLY 只标「静态候选/未动态触及」，
                        不得升为已绕过/已确认。FORCED_REACHABILITY 且 HTTP 2xx + ENTRY_HIT 表示
                        有运行时路径材料（INSTRUMENTATION_REACHABILITY / 测试工具绕行），禁止写「无运行时确认」
                        或「无一动态证据」；仍禁止写成匿名可利用或已确认利用，不得升 VERIFIED；
                        FORCED 单独不得升 DYNAMIC_CONFIRMED / VERIFIED（ADR-0004）。
                        若 PathRun 存在 FORCED 轨 HTTP 2xx，禁止把 UNAUTH/ADMIN 的 302 写成「全局无绕过/
                        no bypass found」——必须区分鉴权墙（UNAUTH）与强达门禁通过（FORCED）。
                        结论必须包含 nextExperiments[]：每项含 entryRef、objective、track、
                        可选 techniqueId/candidateInputs/pathRunRefs；禁止只综述 AUTH_GAP。
                        结论还必须包含 findingBindings[]（供 REPORT_GENERATION 写入 Markdown「关键发现」）：
                        对每个 finding/hypothesis（含 STATIC_INFERRED）给出
                        findingId|hypothesisId、title、severity、status、
                        api:{method,route,entryRef}、poc:{kind,steps[],provenance}；
                        poc.kind 取 STATIC_HINT|AUTH_POC|EXPERIMENT_HINT|RUNTIME_OBSERVED；
                        STATIC_INFERRED 可给静态/鉴权 PoC 或实验提示，必须诚实标注 provenance；
                        材料缺失时写「本轮未形成可复现 PoC」，禁止编造 VERIFIED 利用或从 FORCED-only 宣称已确认。
                        工具白名单含 sandbox_probe：仅可对明确 coverage gap 调用；必填 track、objective，
                        gaps 非空时必填 coverageGapRef；expectedSignal/stopCondition 仅为标签；
                        优先消费 TRACE_PLAN_VS_ACTUAL：对 missingEffects 入口优先 sandbox_probe。
                        禁止指定命令、镜像、挂载、网络、UID 或预算。只能消费服务端返回并成功投影的动态事实。
                        """;
                case DYNAMIC_VERIFICATION -> """
                        消费 AUTH_BYPASS_FEASIBILITY / bypassPoCs：当该列表非空时，在给出叙事结论之前必须先对
                        top-N（至少 min(N,3)、至多 min(N,8)）条已校验 PoC 调用 sandbox_probe
                        （entrypointRef + techniqueId，有 authorizationHeader 时必须带上）；禁止只做 facts_search
                        或纯叙事跳过探针。对照 PathRun/HTTP/SQL/Agent 观测做支持/反证。
                        消费 FUZZ_STRATEGY_CONTEXT 与 BRANCH_CONSTRAINT_FACTS；对 SQL/COMMAND/JNDI 等 sink
                        调用 fuzz_strategy_get，将 probeTemplates.inputHint 与约束字面量写入 candidateInputs。
                        结论 JSON 须含 selectedProbes:[{name,input,expectedSignal}]（对应 ProbeTemplate）。
                        只能引用已存在的 entry:*；不得改命令、网络、挂载、UID 或预算。
                        sandbox_probe 回传含 pathRuns；并用 facts_search kind=PATH_RUN 核对。
                        零 sandbox_probe 时服务端会触发 DYNAMIC_POC_ATTEMPT_REQUIRED 补写或自动入队焦点探针。
                        不得单独把结论升为 DYNAMIC_CONFIRMED 或 VERIFIED；状态只由证据门禁决定。
                        """;
                case VULNERABILITY_TRIAGE -> """
                        基于 PRE_ANALYSIS、AUTH_ANALYSIS、DYNAMIC_VERIFICATION、PATH_EXPLORATION、PathRun
                        与 CONTRAST_LEDGER / STATIC_CONTRAST / TRACE_PLAN_VS_ACTUAL，再查询 SCAN 与 DYNAMIC_EVIDENCE。
                        漏洞候选必须经过本地授权沙箱的动态调试闭环：若没有入口命中、参数绑定、触发点执行和可重放结果，
                        只能标记为推测/证据不足，不能标记为存在或 VERIFIED。STATIC_ONLY 对照行不得升为已绕过/已确认。
                        对 TRACE_PLAN_VS_ACTUAL 的 missingEffects 优先 sandbox_probe 补齐观测。
                        FORCED_REACHABILITY 且 HTTP 2xx + ENTRY_HIT 是有运行时路径材料（须引用
                        INSTRUMENTATION_REACHABILITY / 测试工具绕行），禁止写「无运行时确认」或「无一动态证据」；
                        仍禁止把「仅 FORCED/仅 2xx/仅入口」写成匿名可利用或 VERIFIED；FORCED 单独不得升 DYNAMIC_CONFIRMED（ADR-0004）。
                        当服务端已对危险 sink 效果（H3 SQL / H4 EFFECT_TRIGGERED）给出 DYNAMIC_CONFIRMED 时，
                        必须引用该状态与 requiredPrivilege/authContext（未认证/cookie/低权/管理员等），不得降级为「仅达达性」。
                        禁止用 UNAUTH/COVERAGE 的 302 否定已存在的 FORCED 2xx（不得写「Shiro 全局无绕过」）。
                        DYNAMIC_CONFIRMED 仅服务端门禁可写。列出前置条件、证据、反证/缺口、影响和下一步验证。
                        结论必须包含 nextExperiments[]（可被 sandbox_probe 消费的入口×轨步骤）；组合链仅在共享
                        资源/身份/文件 PathRun 证据上候选；禁止 AUTH_GAP 综述替代下一步实验。
                        结论 JSON 必须含 rootCause：{attackPath:[{layer,label,evidenceRefs[]}],rootCauseStatement,
                        affectedComponent,cweId,fixSuggestion}；按 ROOT_CAUSE_TEMPLATE 填形；每个 attackPath step
                        的 evidenceRefs 不可空；cweId 优先采用 CWE_MAPPING_HINTS。
                        """;
                case REPORT_GENERATION -> reportRoleInstruction(AiOutputLanguage.ZH_CN);
            };
        }
        return switch (role) {
            case PRE_ANALYSIS -> """
                    Prefer already-injected SCAN_MEMORY_INDEX, SCAN_SUMMARY, ENTRY_SUMMARY, RANKED_SINK_CATALOG;
                    do not call scan_memory_get section=INDEX when INDEX is present — deepen with FACTS|WORK
                    (optional role= only for ROLE_SLICE; defaults to current job role). For facts_search use
                    entryId/route/class queries (never "*" or a lone space; omit query to list). Build the
                    entrypoint/business/permission/dependency/trigger model and add MODEL_SUPPLEMENT candidates
                    with reasons and evidence. Deepen with code_query kind=TAINT_GRAPH (optional sinkId/entryId).
                    Never rewrite static facts or claim runtime reachability.
                    """;
            case AUTH_ANALYSIS -> """
                    From static facts and PRE_ANALYSIS hypotheses, build the auth model and emit structured
                    bypass-feasibility PoCs (hypotheses, not verified). FRAMEWORK_ADAPTER_CONTEXT signals are
                    HINTS only — never treat them as harvested FACT keys. Call code_query first to harvest JWT
                    sign-key material, skip-url patterns, @PreAuth, TokenFilter, Secure/Jwt classes, and
                    RememberMe/COOKIE_MATERIAL from the authorized artifact; cite code_query evidence IDs in
                    evidenceRefs. Do not assume a global hardcoded commercial key is FACT; propose
                    DEFAULT_SECRET_HS256 only when code_query reports jwtSecretMaterialFound /
                    secretCandidates.mintable=true. When HARDCODED_REMEMBER_ME_CIPHER_KEY / COOKIE_MATERIAL /
                    rememberMeCipherMaterialFound exists, cite those FACT/hyp-rmc hypotheses — do not guess
                    kPH+ dictionary keys; METHOD_VIEW SLICE_EMPTY does not mean cipherKey was missed. Cookie
                    channel may use REMEMBER_ME_COOKIE / CUSTOM_POC (not JWT). Without harvested secrets prefer
                    MISSING_AUTH / EMPTY_BEARER / ALG_NONE. Use PARAMETER_CONSTRAINT_HINTS to refine
                    authorizationHeader/claims/query/bodyHint. Use plan_propose and/or a final
                    bypassPoCs/bypassCandidates JSON with entryRef, techniqueId, track, rationale, evidenceRefs,
                    confidence, and AI-authored authorizationHeader/secondaryAuthorizationHeader
                    (deprecated wire alias: bladeAuthHeader)/query/bodyHint (JWT, alg-none,
                    custom claims allowed). The server schema-gates then DYNAMIC executes. Use only
                    facts_search/evidence_get/plan_propose/code_query. Never change network/mounts/commands. Emit
                    bypassConfirmation:{status:HYPOTHESIS|DYNAMIC_CONTRAST,pathRunRefs:[...]}. Never claim bypass
                    or DYNAMIC_CONTRAST without PathRun evidence. AUTH_GAP is secondary. When the scan has JWT /
                    AUTH_GAP / auth-annotated entries, bypassPoCs MUST be non-empty (probe hypotheses or explicit
                    per-entry infeasible rows with techniqueId/rationale). Empty list is allowed only with zero auth
                    surface plus emptyReason. Server will re-ask once or seed RULE_GENERATED drafts if still empty.
                    """;
            case PATH_EXPLORATION -> """
                    Consume PRE_ANALYSIS, AUTH_ANALYSIS, DYNAMIC_VERIFICATION, PathRun (HTTP/Agent/SQL),
                    PathTrace (facts_search kind=PATH_TRACE), CONTRAST_LEDGER / STATIC_CONTRAST, and
                    COVERAGE_GAP_FACTS. Prefer PathTrace lastBusinessHop, parameterFlow, effectRefs
                    (EFFECT:FILE_WRITE|FILE_READ|FILE_DELETE|SSRF|EXPRESSION|… plus sink symbol; legacy EFFECT:FILE
                    still means write), and EFFECT event attributes targetClass/targetMethod when binding effects
                    back to static sinks/findings. Use exitReason when proposing nextExperiments (World Pack refine,
                    parameter expand, posture replay). Emit a
                    nextExperiment per gap when possible. Deepen taint structure with code_query kind=TAINT_GRAPH.
                    Model multiple distinct paths with track/posture, actual requests, responses, data/state
                    transitions, triggers, evidence, counterevidence, confidence, and stop conditions. Prefer
                    MATCHED/PARTIAL for probeable nextExperiments; STATIC_ONLY is static-candidate / not
                    dynamically touched — never elevate to bypassed/confirmed. FORCED_REACHABILITY with HTTP 2xx
                    + ENTRY_HIT is runtime path material (cite INSTRUMENTATION_REACHABILITY / test-tool bypass);
                    never write "no runtime confirmation" or "zero dynamic evidence"; still never claim anonymous
                    exploitability or confirmed exploit / VERIFIED; FORCED alone must not become DYNAMIC_CONFIRMED
                    or VERIFIED (ADR-0004). Never turn an unexecuted candidate into fact.
                    Emit nextExperiments[] with entryRef, objective, track, optional
                    techniqueId/candidateInputs/pathRunRefs — steps must be sandbox_probe-consumable, not AUTH_GAP
                    essays. Also emit findingBindings[] for REPORT_GENERATION Markdown "Key Findings" section:
                    for each finding/hypothesis (including STATIC_INFERRED) provide
                    findingId|hypothesisId, title, severity, status, api:{method,route,entryRef},
                    poc:{kind,steps[],provenance}; poc.kind is STATIC_HINT|AUTH_POC|EXPERIMENT_HINT|RUNTIME_OBSERVED;
                    STATIC_INFERRED may use static/auth PoC or experiment hints with honest provenance;
                    write "No reproducible PoC in this round" when absent — never invent VERIFIED exploits or elevate from FORCED-only.
                    Allowlist includes sandbox_probe: probe only an explicit coverage gap; required track,
                    objective, and coverageGapRef when gaps exist; expectedSignal/stopCondition are labels only;
                    prefer TRACE_PLAN_VS_ACTUAL missingEffects entries for sandbox_probe priority;
                    never choose command, image, mount, network, UID, budget, or forcedReachability. Consume only
                    server-returned, successfully projected dynamic facts. FORCED_REACHABILITY /
                    INSTRUMENTATION_REACHABILITY effects are path materials, not anonymous exploit proof.
                    """;
            case DYNAMIC_VERIFICATION -> """
                    Consume AUTH_BYPASS_FEASIBILITY / bypassPoCs. When that list is non-empty you MUST call
                    sandbox_probe for top-N PoCs (at least min(N,3), at most min(N,8)) with entry:* + techniqueId
                    and authorizationHeader when present BEFORE any narrative conclusion. Consume
                    FUZZ_STRATEGY_CONTEXT and BRANCH_CONSTRAINT_FACTS. Call fuzz_strategy_get for
                    SQL/COMMAND/JNDI sinks and use probeTemplates.inputHint plus constraint literals as
                    candidateInputs. Conclusion JSON must include selectedProbes:[{name,input,expectedSignal}]
                    matching ProbeTemplate names. Do not skip to facts_search-only or narrative-only. Compare
                    PathRun/HTTP/SQL/Agent observations. Zero sandbox_probe triggers DYNAMIC_POC_ATTEMPT_REQUIRED
                    re-ask or server auto-enqueue. Never change commands, network, mounts, UID, or budget. Never
                    alone upgrade to DYNAMIC_CONFIRMED or VERIFIED.
                    """;
            case VULNERABILITY_TRIAGE -> """
                    Base the analysis on PRE_ANALYSIS, AUTH_ANALYSIS, DYNAMIC_VERIFICATION, PATH_EXPLORATION,
                    PathRuns, CONTRAST_LEDGER / STATIC_CONTRAST, and TRACE_PLAN_VS_ACTUAL, then query SCAN and
                    DYNAMIC_EVIDENCE. Prefer sandbox_probe on TRACE_PLAN_VS_ACTUAL missingEffects entries.
                    A vulnerability may be marked present only after local authorized sandbox debugging closes
                    entry hit, parameter binding, trigger execution, and replay evidence. Otherwise keep it as
                    hypothesis or insufficient evidence; never claim VERIFIED without replay evidence.
                    STATIC_ONLY contrast rows must not be elevated to bypassed/confirmed.
                    FORCED_REACHABILITY with HTTP 2xx + ENTRY_HIT is runtime path material — cite
                    INSTRUMENTATION_REACHABILITY / test-tool bypass; never write "no runtime confirmation" or
                    "zero dynamic evidence"; still never claim FORCED-only / 2xx-only / entry-only as anonymous
                    exploitability or VERIFIED; FORCED alone must not become DYNAMIC_CONFIRMED (ADR-0004).
                    When the server already set DYNAMIC_CONFIRMED for a dangerous sink effect (H3 SQL / H4
                    EFFECT_TRIGGERED), cite that status and requiredPrivilege/authContext; do not demote to
                    reachability-only. DYNAMIC_CONFIRMED is server-gated only. Emit nextExperiments[] consumable by sandbox_probe;
                    combination chains only when PathRuns share identity/resource/file evidence — not AUTH_GAP essays.
                    Conclusion JSON must include rootCause shaped like ROOT_CAUSE_TEMPLATE, with attackPath steps
                    that each carry non-empty evidenceRefs; prefer CWE_MAPPING_HINTS for cweId.
                    """;
            case REPORT_GENERATION -> reportRoleInstruction(AiOutputLanguage.EN);
        };
    }

    /**
     * REPORT_GENERATION 角色合同：locale-pure 可交付 Markdown 大纲 + 填空骨架。
     * 服务端仍通过 {@link FindingBindings#enforceReportSection} 强制封面/摘要/关键发现/附录。
     */
    public static String reportRoleInstruction(AiOutputLanguage language) {
        if (language == AiOutputLanguage.ZH_CN) {
            return """
                    先查询 SCAN、ENTRY、SINK、EVIDENCE、PathRun、PathTrace（facts_search kind=PATH_TRACE）、
                    STATIC_CONTRAST 与 DYNAMIC_EVIDENCE。优先消费 FINDING_BINDINGS_FACTS 与 PRIOR_ROLE_INFERENCE
                    中 PATH_EXPLORATION 的 findingBindings（接口+PoC+reportRole），不得由前端或本角色凭空编造接口/PoC。
                    输出必须是面向客户的可交付安全审计报告，不是内部控制面/调试清单。
                    主文用人话写风险、影响面与复现；内部枚举、pathRunRefs、poc.kind、三轨术语放入附录。
                    不要单独展开「证据图」或「覆盖矩阵」专章。

                    【硬性规则】
                    - locale-pure 简体中文：禁止英文专章标题（## Key Findings / ## Vulnerabilities / ## Executive Summary 等）。
                    - 禁止旧模板标题「## 漏洞相关」；主发现章使用「## 关键发现」。
                    - 不得编造 VERIFIED；不得把「仅 FORCED_REACHABILITY / 仅 2xx / 仅入口」写成 DYNAMIC_CONFIRMED / 匿名可利用（ADR-0004）。
                    - FORCED 2xx+ENTRY_HIT 无危险 sink 效果时是 INSTRUMENTATION_REACHABILITY 路径材料；有 H3/H4 确认时须写 DYNAMIC_CONFIRMED + 所需权限。
                    - 复现步骤只能来自 FINDING_BINDINGS_FACTS / findingBindings / 已投影 PathRun·PathTrace；
                      无材料写「本轮未形成可复现 PoC」+ 简短下一步，禁止在主文堆砌 UNAUTH/COVERAGE/FORCED 术语。
                    - 入口未知时写「入口未绑定」，禁止主文写 UNKNOWN UNBOUND 原文堆砌。
                    - 验证状态用人话（已动态确认 / 仅静态信号 / 待验证），并在括号保留枚举原文：
                      STATIC_INFERRED、DYNAMIC_SUSPECTED、DYNAMIC_CONFIRMED、VERIFIED、UNREACHED。
                    - 不得把 DYNAMIC_CONFIRMED 宣传为生产实库已证实；MOCK / SCAN_AUTH_POSTURE 不得写成匿名利用。
                    - 排序门禁：「## 关键发现」只放高置信、有攻击配合链或可达 RCE/等价影响证据的项（reportRole=PRIMARY）。
                    - 默认未授权/鉴权缺口、无后续配合链、且无可达 RCE 证据的入口放入「## 其他风险点」
                      （reportRole=RISK_POINT），标注为风险提示而非主发现，禁止夸大成已确认 RCE。

                    【必填章节】（顺序固定）
                    1. # 安全审计报告
                    2. ## 报告元信息 — 项目/扫描 ID（若可知）、范围摘要、总体结论（一句话风险等级）
                    3. ## 执行摘要 — 按严重度计数；已动态确认 vs 仅静态信号；是否有可复现 PoC
                    4. ## 关键发现 — 仅 PRIMARY；按「高危/中危/低危/信息」分组（勿扁平编号混排）；组内可按验证状态优先；
                       每条含业务可读标题、风险等级、验证状态、简述、三层技术路径、复现步骤、证据摘要（次级）
                    5. ## 其他风险点 — 仅 RISK_POINT（无材料可写「无」一行；同样按严重度分组）
                    6. ## 利用链 — 仅当 findings/rootCause/AttackStep/已有链证据可推断时给出；
                       标注「推断/候选」vs「已验证」；禁止编造；无材料写「本轮未识别可组合利用链」
                    7. ## 附录：技术细节 — sink、entryId、provenance、poc.kind、pathRunRefs、内部状态
                    8. ## 限制与下一步验证 — coverage gap / 身份不可用 / 预算耗尽与可引用 nextExperiments

                    【三层技术路径】（每条发现必填，用人话、简洁）
                    - **入口**: METHOD route / 接口绑定；未知写「入口未绑定」，禁止 UNKNOWN UNBOUND 堆砌
                    - **中途代码逻辑**: 入口到危险点之间的关键业务/代码逻辑（来自 path hop / rootCause.attackPath /
                      描述）；无材料写「本轮证据不足以描述中间逻辑」
                    - **底层触发位置**: 真正触发危险操作的 sink/底层调用（如 Class#method）

                    【选填章节】（有材料时按序插入附录之后；无材料可省略，禁止空话填充）
                    - ## 修复建议（消费 FIX_SUGGESTION_CONTEXT / rootCause.fixSuggestion 与 CWE）
                    - ## 攻击路径（Mermaid flowchart，至少 3 步；单 finding 路径，不同于「利用链」组合）
                    - ## 静态·动态对照账本摘要

                    【Markdown 骨架 — 按事实填空；占位符勿原样保留】
                    # 安全审计报告

                    ## 报告元信息
                    - **扫描 ID**: {scanId}
                    - **范围摘要**: 共 {n} 条发现（关键发现 {p} / 其他风险点 {r}）
                    - **总体结论**: {一句话风险等级，勿升 VERIFIED}

                    ## 执行摘要
                    ### 发现数量（按严重度）
                    - 高危（high）: {n}
                    ### 验证与复现概况
                    - **已动态确认/已验证**: {n}
                    - **仅静态信号**: {n}
                    - **具备可复现 PoC 材料**: {n}

                    ## 关键发现

                    ### 高危
                    #### 1. {PRIMARY title}
                    - **风险等级**: 高危（high）
                    - **验证状态**: {人话}（{STATIC_INFERRED|...}）
                    - **简述**: {2–4 句，先风险后技术点}
                    - **技术路径**:
                      - **入口**: {METHOD route 或 入口未绑定}
                      - **中途代码逻辑**: {业务 hop / 本轮证据不足以描述中间逻辑}
                      - **底层触发位置**: `{Class#method}`
                    - **复现步骤**:
                      1. {findingBindings.poc.steps 或 本轮未形成可复现 PoC}
                    ##### 证据摘要
                    - sink: `{sink}`
                    - entryId: `{entryRef}`
                    - provenance: `{...}`

                    ## 其他风险点

                    > 默认未授权可达但无后续配合链、且无可达高影响证据的入口，仅作风险提示。

                    ### 中危
                    #### 1. {RISK_POINT title}
                    - **标注**: 风险提示（非主发现）
                    - **风险等级**: 中危（medium）
                    - **验证状态**: 仅静态信号（STATIC_INFERRED）
                    - **简述**: {description}
                    - **技术路径**:
                      - **入口**: {METHOD route 或 入口未绑定}
                      - **中途代码逻辑**: 本轮证据不足以描述中间逻辑
                      - **底层触发位置**: `{sink}`
                    - **复现步骤**:
                      1. 本轮未形成可复现 PoC。

                    ## 利用链
                    1. 【推断/候选】{注册/鉴权绕过类} + {需认证危险 sink} = {影响面简述}
                    （无材料时仅写：本轮未识别可组合利用链）

                    ## 附录：技术细节
                    ### A.1 {title}
                    - findingId / status / poc.kind / pathRunRefs / 原始 sink

                    ## 限制与下一步验证
                    - {coverage gap / IDENTITY_UNAVAILABLE / 预算耗尽}
                    - 下一步: {可引用 nextExperiments，非空话}
                    """;
        }
        return """
                Query SCAN, ENTRY, SINK, EVIDENCE, PathRun, PathTrace (facts_search kind=PATH_TRACE),
                STATIC_CONTRAST, and DYNAMIC_EVIDENCE first. Prefer FINDING_BINDINGS_FACTS and
                PATH_EXPLORATION findingBindings (API + PoC + reportRole) from PRIOR_ROLE_INFERENCE —
                do not invent interface/PoC in this role. Output a customer-deliverable security audit
                report, not an internal control-plane / debug checklist. Put risk, impact surface, and
                reproduction in the main body; keep enums, pathRunRefs, poc.kind, and tri-track jargon
                in the appendix. Do not add dedicated Evidence Graph or Coverage Matrix chapters.

                [Hard rules]
                - locale-pure English: do not mix Chinese section headers
                  (## 关键发现 / ## 漏洞相关 / ## 执行摘要 / ## 其他风险点).
                - Do not use legacy "## Vulnerabilities"; use "## Key Findings" for primary items.
                - Never invent VERIFIED; FORCED-only / 2xx-only / entry-only must not be written as
                  DYNAMIC_CONFIRMED / anonymous exploitability (ADR-0004).
                - FORCED 2xx+ENTRY_HIT without dangerous sink effect is INSTRUMENTATION_REACHABILITY path material;
                  with H3/H4 confirmation write DYNAMIC_CONFIRMED + required privilege.
                - Reproduction steps only from FINDING_BINDINGS_FACTS / findingBindings / projected
                  PathRun·PathTrace; write "No reproducible PoC in this round" plus a short next step when
                  absent — do not dump UNAUTH/COVERAGE/FORCED jargon into the main body.
                - When entry is unknown write "entrypoint unbound"; do not dump UNKNOWN UNBOUND in the main body.
                - Use human-readable verification status (dynamically confirmed / static signal only / pending)
                  and keep enums in parentheses: STATIC_INFERRED, DYNAMIC_SUSPECTED, DYNAMIC_CONFIRMED,
                  VERIFIED, UNREACHED.
                - Do not market DYNAMIC_CONFIRMED as production-database proof; MOCK / SCAN_AUTH_POSTURE
                  must not be written as anonymous exploit.
                - Ordering gate: "## Key Findings" holds only high-confidence items with attack
                  cooperation chains or reachable RCE/equivalent impact evidence (reportRole=PRIMARY).
                - Default unauthenticated / auth-gap endpoints without follow-on cooperation and without
                  reachable RCE evidence MUST go in "## Additional Risk Notes" (reportRole=RISK_POINT);
                  label as risk notes only — do not oversell as confirmed RCE.

                [Required sections] (fixed order)
                1. # Security Audit Report
                2. ## Report Metadata — project/scan ID when known, scope summary, one-line overall risk
                3. ## Executive Summary — counts by severity; confirmed vs static-only; reproducible PoC presence
                4. ## Key Findings — PRIMARY only; group by High / Medium / Low / Informational (no flat mixed list);
                   within a group prefer verification status; each item: business title, risk level,
                   verification status, summary, three-layer technical path, reproduction, evidence digest
                5. ## Additional Risk Notes — RISK_POINT only (one-line "none" when empty; also severity-grouped)
                6. ## Exploit Chains — only when findings/rootCause/AttackStep/existing chain evidence support it;
                   label inferred/candidate vs verified; never invent; otherwise write
                   "No combinable exploit chain identified this round"
                7. ## Appendix: Technical Details — sink, entryId, provenance, poc.kind, pathRunRefs, raw status
                8. ## Limitations and Next Validation Steps — coverage gaps / identity unavailable / budget + nextExperiments

                [Three-layer technical path] (required per finding; human-readable, concise)
                - **Entry**: METHOD route / API binding; write "entrypoint unbound" when unknown —
                  do not dump UNKNOWN UNBOUND
                - **Intermediate logic**: key business/code logic between entry and dangerous sink
                  (from path hops / rootCause.attackPath / description); write
                  "Insufficient evidence this round to describe intermediate logic" when absent
                - **Trigger location**: real sink / low-level call site (e.g. Class#method)

                [Optional sections] (insert after appendix when materials exist; omit rather than pad)
                - ## Remediation / Fix Suggestions (FIX_SUGGESTION_CONTEXT / rootCause.fixSuggestion + CWE)
                - ## Attack Path (Mermaid flowchart, >=3 steps; single-finding path, distinct from Exploit Chains)
                - ## Static-Dynamic Contrast Ledger Summary

                [Markdown skeleton — fill from facts; do not leave placeholders]
                # Security Audit Report

                ## Report Metadata
                - **Scan ID**: {scanId}
                - **Scope summary**: {n} findings (key findings {p} / additional risk notes {r})
                - **Overall conclusion**: {one-line risk rating; never elevate to VERIFIED}

                ## Executive Summary
                ### Finding counts by severity
                - high: {n}
                ### Verification and reproduction overview
                - **Dynamically confirmed / verified**: {n}
                - **Static signal only**: {n}
                - **With reproducible PoC material**: {n}

                ## Key Findings

                ### High
                #### 1. {PRIMARY title}
                - **Risk level**: high
                - **Verification status**: {human label} ({STATIC_INFERRED|...})
                - **Summary**: {2–4 sentences, risk first}
                - **Technical path**:
                  - **Entry**: {METHOD route or entrypoint unbound}
                  - **Intermediate logic**: {business hops OR insufficient-evidence phrase}
                  - **Trigger location**: `{Class#method}`
                - **Reproduction steps**:
                  1. {findingBindings.poc.steps OR No reproducible PoC in this round}
                ##### Evidence digest
                - sink: `{sink}`
                - entryId: `{entryRef}`
                - provenance: `{...}`

                ## Additional Risk Notes

                > Default unauthenticated endpoints without follow-on cooperation and without reachable
                > high-impact evidence are risk notes only.

                ### Medium
                #### 1. {RISK_POINT title}
                - **Label**: risk note (not a primary finding)
                - **Risk level**: medium
                - **Verification status**: Static signal only (STATIC_INFERRED)
                - **Summary**: {description}
                - **Technical path**:
                  - **Entry**: {METHOD route or entrypoint unbound}
                  - **Intermediate logic**: Insufficient evidence this round to describe intermediate logic
                  - **Trigger location**: `{sink}`
                - **Reproduction steps**:
                  1. No reproducible PoC in this round.

                ## Exploit Chains
                1. [inferred/candidate] {register/auth-gap} + {authenticated dangerous sink} = {impact hint}
                (when no materials: only write "No combinable exploit chain identified this round")

                ## Appendix: Technical Details
                ### A.1 {title}
                - findingId / status / poc.kind / pathRunRefs / raw sink

                ## Limitations and Next Validation Steps
                - {coverage gap / IDENTITY_UNAVAILABLE / budget exhausted}
                - Next: {cite nextExperiments; no filler}
                """;
    }

    public static String rolePrompt(SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        try {
            JsonNode policy = JSON.readTree(job.policySnapshotJson());
            String field = language == AiOutputLanguage.ZH_CN ? "promptZh" : "promptEn";
            String customized = policy.path(field).asText("");
            if (!customized.isBlank()) {
                // 自定义 role_bindings 文本仅替换默认 roleInstruction；
                // buildUserPrompt 中的服务端注入块仍然始终生效。
                return "\nCUSTOM_ROLE_PROMPT (operator editable; obey immutable server safety rules;"
                        + " server inject sections such as RANKED_SINK_CATALOG / COVERAGE_GAP_FACTS still apply):\n"
                        + customized.trim() + "\n";
            }
        } catch (Exception ignored) {
            // policy 无效时由快照校验拒绝；此处保留固定角色 prompt 作为防御性回退。
        }
        return roleInstruction(job.role(), language);
    }
}

package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.aq.jvmsentinel.analysis.BranchConstraintHarvester;
import com.aq.jvmsentinel.analysis.CandidateRanker;
import com.aq.jvmsentinel.analysis.CweMapper;
import com.aq.jvmsentinel.analysis.TaintGraph;
import com.aq.jvmsentinel.analysis.TaintGraphProjector;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapter;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.analysis.fuzz.FuzzStrategyRegistry;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.ParameterSpec;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;


/** PRE_ANALYSIS 静态事实与辅助上下文。 */
public final class PreAnalysisContextBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunSource pathRunSource;

    private final PathRunContextBuilder pathRunLoader;
    private final AiJobHistoryQueries history;

    public PreAnalysisContextBuilder(ControlPlaneStore store, PathRunSource pathRunSource,
                                     PathRunContextBuilder pathRunLoader, AiJobHistoryQueries history) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.pathRunLoader = java.util.Objects.requireNonNull(pathRunLoader, "pathRunLoader");
        this.history = java.util.Objects.requireNonNull(history, "history");
    }

    public String cweMappingHintsContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null || job.role() != AgentRole.VULNERABILITY_TRIAGE) return "";
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            StringBuilder block = new StringBuilder();
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "CWE_MAPPING_HINTS（服务端静态映射；非 VERIFIED）：\n"
                    : "CWE_MAPPING_HINTS (server static mapping; not VERIFIED):\n");
            int emitted = 0;
            for (ApiDtos.SinkDto sink : scan.dto().sinks()) {
                String cwe = com.aq.jvmsentinel.analysis.CweMapper.cweMappingFor(sink.category());
                if (cwe == null) continue;
                block.append("- sinkId=").append(sink.id())
                        .append(" category=").append(sink.category())
                        .append(" cweId=").append(cwe).append('\n');
                if (++emitted >= 16) break;
            }
            if (emitted == 0) {
                block.append(language == AiOutputLanguage.ZH_CN ? "- （空）\n" : "- (empty)\n");
            }
            return block.toString();
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    public String rootCauseTemplateContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.VULNERABILITY_TRIAGE) return "";
        if (language == AiOutputLanguage.ZH_CN) {
            return """
                    ROOT_CAUSE_TEMPLATE（示例形状；须填真实 evidenceRefs；非 VERIFIED）：
                    {"rootCause":{"attackPath":[{"layer":"HTTP","label":"POST /api/user/query","evidenceRefs":["entry:xxx"]},{"layer":"param","label":"username 无过滤","evidenceRefs":["tp-001"]},{"layer":"sink","label":"SQL 拼接","evidenceRefs":["pathrun:yyy"]}],"rootCauseStatement":"缺少参数化查询","affectedComponent":"UserRepository#findByUsername","cweId":"CWE-89","fixSuggestion":"改用 PreparedStatement 占位符"}}
                    """;
        }
        return """
                ROOT_CAUSE_TEMPLATE (example shape; fill real evidenceRefs; not VERIFIED):
                {"rootCause":{"attackPath":[{"layer":"HTTP","label":"POST /api/user/query","evidenceRefs":["entry:xxx"]},{"layer":"param","label":"username unsanitized","evidenceRefs":["tp-001"]},{"layer":"sink","label":"SQL concat","evidenceRefs":["pathrun:yyy"]}],"rootCauseStatement":"missing parameterized query","affectedComponent":"UserRepository#findByUsername","cweId":"CWE-89","fixSuggestion":"use PreparedStatement placeholders"}}
                """;
    }
    public String taintGraphSummaryContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.PRE_ANALYSIS || job.scanId() == null) return "";
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            TaintGraph graph = TaintGraphProjector.project(
                    StaticFactSnapshot.resolveTaintPaths(
                            store.staticFacts(job.scanId()), scan.dto().sinks()));
            StringBuilder block = new StringBuilder();
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "TAINT_GRAPH_SUMMARY（服务端投影；细节用 code_query kind=TAINT_GRAPH；非 VERIFIED）：\n"
                    : "TAINT_GRAPH_SUMMARY (server projection; deepen via code_query kind=TAINT_GRAPH; not VERIFIED):\n");
            block.append("- nodeCount=").append(graph.nodes().size())
                    .append(" edgeCount=").append(graph.edges().size())
                    .append(" truncated=").append(graph.truncated()).append('\n');
            int emitted = 0;
            for (TaintGraph.TaintNode node : graph.nodes()) {
                if (node.kind() != TaintGraph.NodeKind.SINK) continue;
                if (emitted >= AiPromptLimits.MAX_TAINT_PATH_SUMMARY_ROWS) break;
                block.append("- highRiskSink nodeId=").append(node.id())
                        .append(" class=").append(AiPromptText.truncatePromptValue(node.classname(), 120))
                        .append(" method=").append(AiPromptText.truncatePromptValue(node.methodDesc(), 80))
                        .append('\n');
                emitted++;
            }
            if (emitted == 0) {
                block.append(language == AiOutputLanguage.ZH_CN
                        ? "- 无 SINK 节点；可用 code_query kind=TAINT_GRAPH 再查。\n"
                        : "- No SINK nodes; retry with code_query kind=TAINT_GRAPH.\n");
            }
            return block.toString();
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    public String branchConstraintFactsContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null) return "";
        if (job.role() != AgentRole.PRE_ANALYSIS && job.role() != AgentRole.DYNAMIC_VERIFICATION) {
            return "";
        }
        return formatParameterConstraintBlock(job, language,
                language == AiOutputLanguage.ZH_CN
                        ? "BRANCH_CONSTRAINT_FACTS（服务端启发式约束；非 VERIFIED）：\n"
                        : "BRANCH_CONSTRAINT_FACTS (server heuristic constraints; not VERIFIED):\n");
    }

    public String parameterConstraintHintsContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.AUTH_ANALYSIS || job.scanId() == null) return "";
        return formatParameterConstraintBlock(job, language,
                language == AiOutputLanguage.ZH_CN
                        ? "PARAMETER_CONSTRAINT_HINTS（辅助精化 auth header/claims；非 VERIFIED）：\n"
                        : "PARAMETER_CONSTRAINT_HINTS (refine auth header/claims; not VERIFIED):\n");
    }

    public String formatParameterConstraintBlock(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language, String header) {
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            StringBuilder block = new StringBuilder(header);
            int emitted = 0;
            for (ApiDtos.EntryDto entry : scan.dto().entries()) {
                List<ParameterSpec> specs = BranchConstraintHarvester.harvest(
                        entry.parameters(), entry.preconditions());
                for (ParameterSpec spec : specs) {
                    if (spec.constraints().isEmpty() && "string".equals(spec.type())) continue;
                    if (emitted >= AiPromptLimits.MAX_CONSTRAINT_PROMPT_ROWS) break;
                    block.append("- entryRef=entry:").append(entry.id())
                            .append(" param=").append(spec.name())
                            .append(" type=").append(spec.type())
                            .append(" origin=").append(spec.origin())
                            .append(" constraints=");
                    try {
                        block.append(JSON.writeValueAsString(spec.constraints()));
                    } catch (Exception ignored) {
                        block.append(spec.toLegacyEncoding());
                    }
                    block.append('\n');
                    emitted++;
                }
                if (emitted >= AiPromptLimits.MAX_CONSTRAINT_PROMPT_ROWS) break;
            }
            if (emitted == 0) {
                block.append(language == AiOutputLanguage.ZH_CN ? "- （空）\n" : "- (empty)\n");
            }
            return block.toString();
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    public String frameworkAdapterContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.AUTH_ANALYSIS || job.scanId() == null) return "";
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            java.nio.file.Path artifactPath = null;
            try {
                ControlPlaneStore.ProjectRecord project = store.requireProject(job.projectId());
                var artifact = store.artifact(project, job.artifactDigest());
                if (artifact != null) artifactPath = artifact.normalizedPath();
            } catch (RuntimeException ignored) {
                artifactPath = null;
            }
            List<String> routes = scan.dto().entries().stream()
                    .map(ApiDtos.EntryDto::route)
                    .filter(route -> route != null && !route.isBlank())
                    .limit(64)
                    .toList();
            List<FrameworkAdapter> matched = FrameworkAdapterRegistry.matching(artifactPath, routes);
            StringBuilder block = new StringBuilder();
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "FRAMEWORK_ADAPTER_CONTEXT（服务端匹配 HINT；非 FACT；非 VERIFIED）：\n"
                    : "FRAMEWORK_ADAPTER_CONTEXT (server match HINT; not FACT; not VERIFIED):\n");
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- 适配器信号仅为线索；必须用 code_query 从制品提取密钥/鉴权逻辑并引用证据，"
                            + "不得把全局硬编码商业密钥当作 FACT。\n"
                    : "- Adapter signals are hints only; call code_query to extract keys/auth logic from "
                            + "the artifact and cite evidence; never treat a global hardcoded commercial "
                            + "key as FACT.\n");
            if (matched.isEmpty()) {
                block.append(language == AiOutputLanguage.ZH_CN
                        ? "- 未匹配专用 FrameworkAdapter；按通用 Spring/JWT 假设编写 bypassPoCs。\n"
                        : "- No FrameworkAdapter matched; author bypassPoCs with generic Spring/JWT hypotheses.\n");
                return block.toString();
            }
            for (FrameworkAdapter adapter : matched) {
                block.append("- adapterId=").append(adapter.id());
                adapter.suggestJwtSecret(artifactPath).ifPresent(hint ->
                        block.append(" harvestedSecretSignal=").append(hint));
                if (adapter.preferSecondaryAuthHeader(null)) {
                    block.append(" preferSecondaryAuthHeaderHint=true");
                    if (adapter.secondaryAuthHeaderName() != null
                            && !adapter.secondaryAuthHeaderName().isBlank()) {
                        block.append(" secondaryAuthHeaderName=")
                                .append(adapter.secondaryAuthHeaderName());
                    }
                }
                if (!adapter.defaultBypassTechniques().isEmpty()) {
                    block.append(" techniqueLibrary=").append(adapter.defaultBypassTechniques());
                }
                block.append('\n');
                for (String note : adapter.jwtSecretHintNotes()) {
                    block.append("  - wellKnownKeyHint: ").append(note).append('\n');
                }
            }
            return block.toString();
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    public String fuzzStrategyContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.DYNAMIC_VERIFICATION || job.scanId() == null) return "";
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            StringBuilder block = new StringBuilder();
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "FUZZ_STRATEGY_CONTEXT（按 sink 类别的探针模板；调用 fuzz_strategy_get 取明细；非 VERIFIED）：\n"
                    : "FUZZ_STRATEGY_CONTEXT (sink-category probe templates; call fuzz_strategy_get for detail; not VERIFIED):\n");
            LinkedHashSet<String> categories = new LinkedHashSet<>();
            for (ApiDtos.SinkDto sink : scan.dto().sinks()) {
                if (sink.category() == null || sink.category().isBlank()) continue;
                String cat = sink.category().trim().toUpperCase(java.util.Locale.ROOT);
                if ("JWT".equals(cat) || "AUTH_GAP".equals(cat)) continue;
                categories.add(cat);
                if (categories.size() >= AiPromptLimits.MAX_FUZZ_CATEGORY_PROMPT_ROWS) break;
            }
            if (categories.isEmpty()) {
                block.append(language == AiOutputLanguage.ZH_CN ? "- （空）\n" : "- (empty)\n");
                return block.toString();
            }
            for (String category : categories) {
                FuzzStrategyRegistry.FuzzStrategy strategy = FuzzStrategyRegistry.forSink(category);
                block.append("- category=").append(strategy.sinkCategory()).append(" templates=");
                List<String> templates = new ArrayList<>();
                for (FuzzStrategyRegistry.ProbeTemplate template : strategy.probeTemplates()) {
                    templates.add(template.name() + ":" + AiPromptText.truncatePromptValue(template.inputHint(), 48)
                            + "->" + template.expectedSignal());
                }
                block.append(templates).append('\n');
            }
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- 结论须输出 selectedProbes[{name,input,expectedSignal}]。\n"
                    : "- Emit selectedProbes[{name,input,expectedSignal}] in the conclusion.\n");
            return block.toString();
        } catch (RuntimeException ignored) {
            return "";
        }
    }
    public String preAnalysisStaticFactsContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.PRE_ANALYSIS || job.scanId() == null) return "";
        ControlPlaneStore.ScanRecord scan;
        try {
            scan = store.requireScan(job.scanId());
        } catch (RuntimeException ignored) {
            return "";
        }
        ApiDtos.ScanDto dto = scan.dto();
        StringBuilder block = new StringBuilder();
        if (language == AiOutputLanguage.ZH_CN) {
            block.append("SCAN_SUMMARY（服务端可信静态事实导航；深层结论仍需用工具引用 evidence refs）：\n");
        } else {
            block.append("SCAN_SUMMARY (trusted server static-fact navigation; cite evidence refs via tools for deep claims):\n");
        }
        try {
            block.append("- ").append(JSON.writeValueAsString(AiPromptText.scanPromptSummary(dto))).append('\n');
        } catch (Exception ignored) {
            block.append("- scanId=").append(dto.scanId())
                    .append(" entries=").append(dto.entries().size())
                    .append(" evidenceRefs=").append(dto.evidenceRefs().size()).append('\n');
        }
        block.append(rankedSinkCatalogBlock(scan, language));
        block.append(language == AiOutputLanguage.ZH_CN
                ? "这些是服务端已持久化事实的有界摘要，只用于导航；不得据此提升验证状态。"
                + " 使用 entry ids、route、controller/class、HTTP method 与英文枚举关键词查询 facts_search，"
                + "不要只用中文自由文本。\n"
                : "These bounded server-persisted facts are for navigation only and must not upgrade verification status. "
                + "Use entry ids, routes, controller/class names, HTTP methods, and English enum keywords with facts_search; "
                + "do not rely only on translated prose queries.\n");
        block.append(language == AiOutputLanguage.ZH_CN
                ? "ENTRY_SUMMARY（最多 40 个静态入口；需要细节时用 facts_search kind=ENTRY query=<entryId|route|class> 或 evidence_get）：\n"
                : "ENTRY_SUMMARY (up to 40 static entries; deepen with facts_search kind=ENTRY query=<entryId|route|class> or evidence_get):\n");
        if (dto.entries().isEmpty()) {
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- 无静态入口；不得声称已发现入口事实，只能说明静态索引未返回入口。\n"
                    : "- No static entries; do not claim entry facts, only that the static index returned none.\n");
            return block.toString();
        }
        int emitted = 0;
        for (ApiDtos.EntryDto entry : dto.entries()) {
            if (emitted >= AiPromptLimits.MAX_PRE_ENTRY_PROMPT_ROWS) break;
            try {
                block.append("- ").append(JSON.writeValueAsString(AiPromptText.entryPromptSummary(entry))).append('\n');
            } catch (Exception ignored) {
                block.append("- entryRef=entry:").append(entry.id())
                        .append(" method=").append(entry.method())
                        .append(" route=").append(entry.route())
                        .append(" controller=").append(entry.declaringClass()).append('\n');
            }
            emitted++;
        }
        if (dto.entries().size() > AiPromptLimits.MAX_PRE_ENTRY_PROMPT_ROWS) {
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- …另有 " + (dto.entries().size() - AiPromptLimits.MAX_PRE_ENTRY_PROMPT_ROWS)
                    + " 个入口未内联，请用 facts_search kind=ENTRY 按 entry id、route 或 class 拉取。\n"
                    : "- …" + (dto.entries().size() - AiPromptLimits.MAX_PRE_ENTRY_PROMPT_ROWS)
                    + " more entries omitted; fetch with facts_search kind=ENTRY by entry id, route, or class.\n");
        }
        return block.toString();
    }

    public String fixSuggestionContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() != AgentRole.REPORT_GENERATION || job.scanId() == null) return "";
        StringBuilder block = new StringBuilder();
        block.append(language == AiOutputLanguage.ZH_CN
                ? "FIX_SUGGESTION_CONTEXT（来自 TRIAGE rootCause / findings；须写入 ## 修复建议；非 VERIFIED）：\n"
                : "FIX_SUGGESTION_CONTEXT (from TRIAGE rootCause / findings; require Remediation section; not VERIFIED):\n");
        int emitted = 0;
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            // 优先 TRIAGE 已挂载 finding（与 dashboard 同源），再回退 job JSON。
            List<ApiDtos.FindingDto> ordered = new ArrayList<>();
            for (ApiDtos.FindingDto finding : scan.dto().findings()) {
                if (finding.findingId() != null && finding.findingId().startsWith("finding-triage-")) {
                    ordered.add(finding);
                }
            }
            for (ApiDtos.FindingDto finding : scan.dto().findings()) {
                if (finding.findingId() != null && finding.findingId().startsWith("finding-triage-")) {
                    continue;
                }
                ordered.add(finding);
            }
            for (ApiDtos.FindingDto finding : ordered) {
                if (finding.rootCause() == null || finding.rootCause().isEmpty()) continue;
                if (emitted >= 8) break;
                Object fix = finding.rootCause().get("fixSuggestion");
                Object cwe = finding.rootCause().get("cweId");
                String source = finding.findingId() != null && finding.findingId().startsWith("finding-triage-")
                        ? "TRIAGE_ATTACHED" : "FINDING";
                block.append("- source=").append(source)
                        .append(" findingId=").append(finding.findingId())
                        .append(" cweId=").append(cwe == null ? "" : cwe)
                        .append(" fixSuggestion=").append(fix == null ? "" : AiPromptText.truncatePromptValue(String.valueOf(fix), 240))
                        .append('\n');
                emitted++;
            }
        } catch (RuntimeException ignored) {
            // 回退到先前 TRIAGE job 结论。
        }
        if (emitted == 0) {
            String triageRootCause = history.latestRootCauseJson(
                    job.projectId(), job.scanId(), AgentRole.VULNERABILITY_TRIAGE);
            if (triageRootCause != null && !triageRootCause.isBlank()) {
                block.append("- source=PRIOR_TRIAGE rootCause=").append(triageRootCause).append('\n');
                emitted++;
            }
        }
        if (emitted == 0) {
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- （空）证据不足时在 ## 修复建议 写明证据不足，勿编造补丁。\n"
                    : "- (empty) If evidence is insufficient, say so under Remediation; do not invent patches.\n");
        }
        return block.toString();
    }

    public String rankedSinkCatalogBlock(
            ControlPlaneStore.ScanRecord scan, AiOutputLanguage language) {
        List<ApiDtos.PathRunDto> runs = pathRunLoader.loadPathRunsForScanSafe(scan);
        ContrastLedger.Ledger ledger = ContrastLedger.build(
                scan.dto().entries(), scan.dto().sinks(), scan.evidence(), runs,
                StaticFactSnapshot.resolveTaintPaths(
                        store.staticFacts(scan.dto().scanId()), scan.dto().sinks()));
        List<CandidateRanker.RankedSinkView> ranked = CandidateRanker.rank(
                scan.dto().sinks(),
                StaticFactSnapshot.resolveTaintPaths(
                        store.staticFacts(scan.dto().scanId()), scan.dto().sinks()),
                scan.dto().entries(), ledger.rows());
        StringBuilder block = new StringBuilder();
        block.append(language == AiOutputLanguage.ZH_CN
                ? "RANKED_SINK_CATALOG（服务端确定性排序，最多 20 条；非 VERIFIED）：\n"
                : "RANKED_SINK_CATALOG (deterministic server ranking, top 20; not VERIFIED):\n");
        if (ranked.isEmpty()) {
            block.append(language == AiOutputLanguage.ZH_CN ? "- （空）\n" : "- (empty)\n");
            return block.toString();
        }
        int emitted = 0;
        for (CandidateRanker.RankedSinkView view : ranked) {
            if (emitted >= 20) break;
            block.append("- rank=").append(view.rank())
                    .append(" sinkId=").append(view.sinkId())
                    .append(" category=").append(view.category())
                    .append(" score=").append(String.format(java.util.Locale.ROOT, "%.2f", view.score()))
                    .append(" reasons=").append(view.rankReasons())
                    .append('\n');
            emitted++;
        }
        return block.toString();
    }
}

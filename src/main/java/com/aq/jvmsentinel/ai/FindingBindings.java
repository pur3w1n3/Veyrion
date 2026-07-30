package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.analysis.hypothesis.FindingRuntimeEnricher;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.worker.DynamicConfirmedGate;
import com.aq.jvmsentinel.worker.TraceProjectionService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 服务端闸门的 PATH → REPORT 合同：逐 finding API + 诚实 PoC 绑定。
 *
 * <p>渲染为可交付审计报告结构（封面/执行摘要/按严重度分组的关键发现/利用链/附录），
 * 而非内部控制面调试视角。关键发现含入口→中途逻辑→底层触发三层技术路径。
 * 绝不捏造 VERIFIED 利用。仅 FORCED/2xx/入口到达 →
 * {@code INSTRUMENTATION_REACHABILITY} 实验提示；危险 sink 效果经
 * {@link FindingRuntimeEnricher} / H4 门禁确认时透传 {@code DYNAMIC_CONFIRMED}
 * 并标注权限需求（requiredPrivilege）。binding 本身不发明状态，但必须消费
 * 服务端 enricher 投影（findings 表可能仍为 STATIC_INFERRED）。</p>
 */
public final class FindingBindings {
    public static final int MAX_BINDINGS = 48;
    /** 孤儿 EFFECT 占位上限，避免全站 SpEL/RememberMe 噪声挤掉 BPMN/JWT/强达 finding。 */
    public static final int MAX_ORPHAN_BINDINGS = 12;
    public static final int MAX_POC_STEPS = 8;
    public static final int MAX_HOPS_IN_POC = 6;
    /** 交付主章：关键发现（原「漏洞相关」调试列表已废弃）。 */
    public static final String SECTION_ZH = "## 关键发现";
    public static final String SECTION_EN = "## Key Findings";
    public static final String RISK_SECTION_ZH = "## 其他风险点";
    public static final String RISK_SECTION_EN = "## Additional Risk Notes";
    public static final String EXEC_SECTION_ZH = "## 执行摘要";
    public static final String EXEC_SECTION_EN = "## Executive Summary";
    public static final String APPENDIX_SECTION_ZH = "## 附录：技术细节";
    public static final String APPENDIX_SECTION_EN = "## Appendix: Technical Details";
    /** 关键发现之后、附录之前：可组合利用链（无材料时写诚实空态）。 */
    public static final String CHAIN_SECTION_ZH = "## 利用链";
    public static final String CHAIN_SECTION_EN = "## Exploit Chains";
    public static final String TITLE_ZH = "# 安全审计报告";
    public static final String TITLE_EN = "# Security Audit Report";
    /** 旧版专章标题（触发服务端重写）。 */
    public static final String LEGACY_SECTION_ZH = "## 漏洞相关";
    public static final String LEGACY_SECTION_EN = "## Vulnerabilities";
    public static final String REPORT_ROLE_PRIMARY = "PRIMARY";
    public static final String REPORT_ROLE_RISK_POINT = "RISK_POINT";
    public static final String NO_POC_ZH = "本轮未形成可复现 PoC";
    public static final String NO_POC_EN = "No reproducible PoC in this round";
    public static final String NO_MID_LOGIC_ZH = "本轮证据不足以描述中间逻辑";
    public static final String NO_MID_LOGIC_EN = "Insufficient evidence this round to describe intermediate logic";
    public static final String NO_CHAIN_ZH = "本轮未识别可组合利用链";
    public static final String NO_CHAIN_EN = "No combinable exploit chain identified this round";
    /** 兼容旧断言/文案探测。 */
    public static final String NO_POC_ZH_LEGACY = "暂无 PoC";
    public static final String NO_POC_EN_LEGACY = "No PoC yet";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> HIGH_IMPACT_PROPERTIES = Set.of(
            "JWT", "BPMN_DEPLOY", "BPMN_EXEC", "COMMAND", "DESERIALIZATION",
            "FILE", "FILE_WRITE", "FILE_READ", "FILE_DELETE", "SQL", "SSRF", "EXPRESSION",
            "TEMPLATE", "JNDI", "HARDCODED_JWT_SIGN_KEY", "HARDCODED_REMEMBER_ME_CIPHER_KEY",
            "UNSAFE_DESERIALIZATION_SURFACE", "JWT_SECRET_CONFIG", "JWT_ALG_NONE");

    private FindingBindings() {
    }

    public record ApiBinding(String method, String route, String entryRef) {
        public ApiBinding {
            method = method == null || method.isBlank() ? "UNKNOWN" : method.trim().toUpperCase(Locale.ROOT);
            route = route == null || route.isBlank() ? "/" : route.trim();
            entryRef = entryRef == null ? "" : entryRef.trim();
        }
    }

    public record PocBinding(String kind, List<String> steps, String provenance) {
        public PocBinding {
            kind = kind == null || kind.isBlank() ? "STATIC_HINT" : kind.trim();
            steps = List.copyOf(steps == null ? List.of() : steps);
            provenance = provenance == null ? "" : provenance.trim();
        }
    }

    public record Binding(
            String findingId,
            String hypothesisId,
            String title,
            String severity,
            String status,
            ApiBinding api,
            PocBinding poc,
            String description,
            List<String> pathRunRefs,
            String reportRole,
            String sink,
            String midLogic,
            String securityProperty
    ) {
        public Binding {
            findingId = findingId == null ? "" : findingId.trim();
            hypothesisId = hypothesisId == null ? "" : hypothesisId.trim();
            title = title == null ? "" : title.trim();
            severity = severity == null ? "" : severity.trim();
            status = status == null || status.isBlank() ? ApiDtos.STATIC_INFERRED : status.trim();
            api = api == null ? new ApiBinding("UNKNOWN", "/", "") : api;
            poc = poc == null ? new PocBinding("STATIC_HINT", List.of(), "") : poc;
            description = description == null ? "" : description.trim();
            pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
            reportRole = normalizeReportRole(reportRole);
            sink = sink == null ? "" : sink.trim();
            midLogic = midLogic == null ? "" : midLogic.trim();
            securityProperty = securityProperty == null ? "" : securityProperty.trim();
            if ("VERIFIED".equals(status) || ApiDtos.DYNAMIC_CONFIRMED.equals(status)) {
                // binding 不得铸造提升；调用方仅透传服务端 status。
            }
        }

        /** 向后兼容重载（默认 PRIMARY，无 sink / midLogic / securityProperty）。 */
        public Binding(
                String findingId,
                String hypothesisId,
                String title,
                String severity,
                String status,
                ApiBinding api,
                PocBinding poc,
                String description,
                List<String> pathRunRefs) {
            this(findingId, hypothesisId, title, severity, status, api, poc, description,
                    pathRunRefs, REPORT_ROLE_PRIMARY, "", "", "");
        }

        /** 向后兼容重载（无 sink / midLogic / securityProperty）。 */
        public Binding(
                String findingId,
                String hypothesisId,
                String title,
                String severity,
                String status,
                ApiBinding api,
                PocBinding poc,
                String description,
                List<String> pathRunRefs,
                String reportRole) {
            this(findingId, hypothesisId, title, severity, status, api, poc, description,
                    pathRunRefs, reportRole, "", "", "");
        }

        /** 向后兼容重载（无 midLogic / securityProperty）。 */
        public Binding(
                String findingId,
                String hypothesisId,
                String title,
                String severity,
                String status,
                ApiBinding api,
                PocBinding poc,
                String description,
                List<String> pathRunRefs,
                String reportRole,
                String sink) {
            this(findingId, hypothesisId, title, severity, status, api, poc, description,
                    pathRunRefs, reportRole, sink, "", "");
        }
    }

    /** assemble 结果：含 totalCandidates，供 prompt 标记 truncated 而非静默当全集。 */
    public record AssembleResult(List<Binding> bindings, int totalCandidates) {
        public AssembleResult {
            bindings = List.copyOf(bindings == null ? List.of() : bindings);
            if (totalCandidates < 0) {
                throw new IllegalArgumentException("totalCandidates must be >= 0");
            }
        }

        public boolean truncated() {
            return totalCandidates > bindings.size();
        }
    }

    public static List<Binding> assemble(
            List<ApiDtos.FindingDto> findings,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.PathRunDto> pathRuns,
            Map<String, PathTrace> tracesByPathRunId,
            AiOutputLanguage language) {
        return assembleDetailed(findings, entries, pathRuns, tracesByPathRunId, language).bindings();
    }

    public static AssembleResult assembleDetailed(
            List<ApiDtos.FindingDto> findings,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.PathRunDto> pathRuns,
            Map<String, PathTrace> tracesByPathRunId,
            AiOutputLanguage language) {
        boolean zh = language != AiOutputLanguage.EN;
        List<ApiDtos.FindingDto> source = findings == null ? List.of() : findings;
        List<ApiDtos.EntryDto> catalog = entries == null ? List.of() : entries;
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;
        Map<String, PathTrace> traces = tracesByPathRunId == null ? Map.of() : tracesByPathRunId;
        // 先按 enricher 投影后的验证态/严重度排序再截断（DB 可能仍为 STATIC_INFERRED）。
        List<EnrichedFinding> ranked = new ArrayList<>();
        for (ApiDtos.FindingDto finding : source) {
            if (finding == null) continue;
            FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                    finding, catalog, runs, traces, property -> property);
            ranked.add(new EnrichedFinding(finding, enrichment));
        }
        ranked.sort(enrichedSelectionOrder());
        // 孤儿强危险 EFFECT（无静态 finding）优先占位，但有上限，避免挤掉高价值 finding。
        List<Binding> orphans = orphanEffectBindings(source, catalog, runs, traces, zh);
        List<Binding> out = new ArrayList<>();
        LinkedHashSet<String> orphanKeys = new LinkedHashSet<>();
        int orphanSlots = Math.min(MAX_ORPHAN_BINDINGS, MAX_BINDINGS);
        for (Binding orphan : orphans) {
            if (out.size() >= orphanSlots) break;
            out.add(orphan);
            if (orphan.api() != null) {
                orphanKeys.add(orphan.securityProperty() + "|" + orphan.api().method()
                        + "|" + orphan.api().route());
            }
        }
        for (EnrichedFinding item : ranked) {
            if (out.size() >= MAX_BINDINGS) break;
            Binding binding = bindOne(item.finding(), item.enrichment(), catalog, runs, traces, zh);
            String key = binding.securityProperty() + "|" + binding.api().method()
                    + "|" + binding.api().route();
            if (orphanKeys.contains(key)) continue;
            out.add(binding);
        }
        out.sort(bindingDeliverableOrder());
        return new AssembleResult(out, ranked.size() + orphans.size());
    }

    private record EnrichedFinding(
            ApiDtos.FindingDto finding, FindingRuntimeEnricher.Enrichment enrichment) {
    }

    private static Comparator<EnrichedFinding> enrichedSelectionOrder() {
        return Comparator
                .comparingInt((EnrichedFinding e) -> statusRank(e.enrichment().verificationStatus()))
                // 有 PathRun/强达材料的 finding 优先于纯静态高影响噪声，避免 MAX_BINDINGS 截掉强达。
                .thenComparingInt(e -> e.enrichment().pathRunRefs().isEmpty() ? 1 : 0)
                .thenComparingInt(e -> selectionImpactRank(e.finding()))
                .thenComparingInt(e -> severityRank(e.finding().severity()))
                .thenComparing(e -> e.finding().findingId(), Comparator.nullsLast(String::compareTo));
    }

    private static Binding bindOne(
            ApiDtos.FindingDto finding,
            FindingRuntimeEnricher.Enrichment enrichment,
            List<ApiDtos.EntryDto> catalog,
            List<ApiDtos.PathRunDto> runs,
            Map<String, PathTrace> traces,
            boolean zh) {
        ApiDtos.EntryDto entry = resolveEntry(finding, catalog);
        ApiBinding api = apiOf(finding, entry);
        LinkedHashSet<String> forcedRefs = new LinkedHashSet<>();
        LinkedHashSet<String> coverageRefs = new LinkedHashSet<>();
        PathRunPick bestForced = null;
        PathRunPick bestCoverage = null;
        PathRunPick bestConfirmed = null;
        for (ApiDtos.PathRunDto run : runs) {
            if (run == null) continue;
            PathTrace trace = traces.get(run.pathRunId());
            if (!FindingRuntimeEnricher.matchesFindingEntry(finding, catalog, run, trace)
                    && !matchesEntry(finding, entry, catalog, run)) {
                continue;
            }
            if (!FindingRuntimeEnricher.entryReached(run, trace)) continue;
            RuntimePostureKind kind = postureKind(run, trace);
            PathRunPick pick = new PathRunPick(run, trace, kind);
            if (enrichment.pathRunRefs().contains(run.pathRunId())
                    && ApiDtos.DYNAMIC_CONFIRMED.equals(enrichment.verificationStatus())) {
                if (bestConfirmed == null || prefer(pick, bestConfirmed)) bestConfirmed = pick;
            }
            if (kind == RuntimePostureKind.FORCED_REACHABILITY) {
                forcedRefs.add(run.pathRunId());
                if (bestForced == null || prefer(pick, bestForced)) bestForced = pick;
            } else if (kind == RuntimePostureKind.COVERAGE_POSTURE) {
                coverageRefs.add(run.pathRunId());
                if (bestCoverage == null || prefer(pick, bestCoverage)) bestCoverage = pick;
            }
        }
        // 服务端 enricher 投影优先；不得降级已落库的 CONFIRMED/VERIFIED。
        String prior = finding.verificationStatus() == null || finding.verificationStatus().isBlank()
                ? ApiDtos.STATIC_INFERRED : finding.verificationStatus().trim();
        String status = enrichment.verificationStatus();
        if (ApiDtos.DYNAMIC_CONFIRMED.equals(prior) || "VERIFIED".equals(prior)) {
            status = ApiDtos.DYNAMIC_CONFIRMED.equals(prior) ? prior : ApiDtos.DYNAMIC_CONFIRMED;
        }
        PathRunPick bestEffect = bestConfirmed != null ? bestConfirmed
                : (bestForced != null ? bestForced
                : (bestCoverage != null ? bestCoverage : null));
        boolean confirmed = ApiDtos.DYNAMIC_CONFIRMED.equals(status) || "VERIFIED".equals(status);
        PocBinding poc;
        List<String> pathRunRefs;
        if (confirmed && bestEffect != null) {
            poc = confirmedPoc(bestEffect, api, finding, zh);
            pathRunRefs = !enrichment.pathRunRefs().isEmpty()
                    ? enrichment.pathRunRefs()
                    : (bestForced != null ? List.copyOf(forcedRefs) : List.copyOf(coverageRefs));
        } else if (bestForced != null) {
            poc = forcedPoc(bestForced, api, zh);
            pathRunRefs = !enrichment.pathRunRefs().isEmpty()
                    ? enrichment.pathRunRefs() : List.copyOf(forcedRefs);
        } else if (bestCoverage != null) {
            poc = coveragePoc(bestCoverage, api, zh);
            pathRunRefs = !enrichment.pathRunRefs().isEmpty()
                    ? enrichment.pathRunRefs() : List.copyOf(coverageRefs);
        } else {
            poc = staticPoc(api, entry, zh);
            pathRunRefs = List.of();
        }
        String title = enrichment.title() == null || enrichment.title().isBlank()
                ? finding.title() : enrichment.title();
        String reportRole = classifyReportRole(finding, poc, pathRunRefs);
        String sink = finding.sink() == null ? "" : finding.sink().trim();
        String securityProperty = finding.securityProperty() == null
                ? "" : finding.securityProperty().trim();
        PathTrace midTrace = bestEffect == null ? null : bestEffect.trace();
        return new Binding(
                finding.findingId(),
                finding.hypothesisId() == null ? "" : finding.hypothesisId(),
                title,
                finding.severity(),
                status,
                api,
                poc,
                descriptionOf(title, status, api, poc, zh),
                pathRunRefs,
                reportRole,
                sink,
                midLogicOf(finding, poc, midTrace, zh),
                securityProperty);
    }

    /**
     * 从 PathTrace 业务 hop / rootCause.attackPath 中层抽取「入口→危险点」中间逻辑；
     * 无材料时返回诚实空态文案（不编造）。
     */
    static String midLogicOf(ApiDtos.FindingDto finding, PocBinding poc, boolean zh) {
        return midLogicOf(finding, poc, null, zh);
    }

    static String midLogicOf(ApiDtos.FindingDto finding, PocBinding poc, PathTrace trace, boolean zh) {
        List<String> hopChain = extractHopChainFromPoc(poc, zh);
        if (!hopChain.isEmpty()) {
            return String.join(" → ", hopChain);
        }
        List<String> fromTrace = businessHops(trace);
        if (!fromTrace.isEmpty()) {
            return String.join(" → ", fromTrace.stream().map(FindingBindings::shortenTypeRef).toList());
        }
        if (trace != null && trace.lastBusinessHop() != null && !trace.lastBusinessHop().isBlank()) {
            return shortenTypeRef(trace.lastBusinessHop());
        }
        List<String> rootMid = extractMidFromRootCause(finding == null ? null : finding.rootCause());
        if (!rootMid.isEmpty()) {
            return String.join(" → ", rootMid);
        }
        return zh ? NO_MID_LOGIC_ZH : NO_MID_LOGIC_EN;
    }

    private static List<String> extractHopChainFromPoc(PocBinding poc, boolean zh) {
        if (poc == null || poc.steps() == null) return List.of();
        String marker = zh ? "观测到的业务调用链：" : "Observed business call chain:";
        for (String step : poc.steps()) {
            if (step == null) continue;
            int idx = step.indexOf(marker);
            if (idx < 0) continue;
            String rest = step.substring(idx + marker.length()).trim();
            if (rest.isBlank()) continue;
            List<String> hops = new ArrayList<>();
            for (String part : rest.split("\\s*→\\s*|\\s*->\\s*")) {
                String shortHop = shortenTypeRef(part.trim());
                if (!shortHop.isBlank()) hops.add(shortHop);
            }
            if (!hops.isEmpty()) return hops;
        }
        return List.of();
    }

    private static List<String> extractMidFromRootCause(Map<String, Object> rootCause) {
        if (rootCause == null || rootCause.isEmpty()) return List.of();
        Object raw = rootCause.get("attackPath");
        if (!(raw instanceof List<?> steps) || steps.isEmpty()) return List.of();
        List<String> mid = new ArrayList<>();
        for (Object stepObj : steps) {
            if (!(stepObj instanceof Map<?, ?> step)) continue;
            Object layerObj = step.get("layer");
            Object labelObj = step.get("label");
            String layer = layerObj == null ? "" : String.valueOf(layerObj).trim().toLowerCase(Locale.ROOT);
            String label = labelObj == null ? "" : String.valueOf(labelObj).trim();
            if (label.isBlank()) continue;
            // 跳过入口/最终 sink 层，只保留中间业务/参数逻辑
            if (layer.equals("http") || layer.equals("entry") || layer.equals("entrypoint")
                    || layer.equals("sink") || layer.equals("effect")) {
                continue;
            }
            mid.add(label);
            if (mid.size() >= MAX_HOPS_IN_POC) break;
        }
        return mid;
    }

    static String shortenTypeRef(String ref) {
        if (ref == null || ref.isBlank()) return "";
        String trimmed = ref.trim();
        int hash = trimmed.lastIndexOf('#');
        if (hash > 0) {
            String type = trimmed.substring(0, hash);
            String method = trimmed.substring(hash);
            int dot = type.lastIndexOf('.');
            String simple = dot >= 0 ? type.substring(dot + 1) : type;
            return simple + method;
        }
        int dot = trimmed.lastIndexOf('.');
        return dot >= 0 ? trimmed.substring(dot + 1) : trimmed;
    }

    static String triggerLocation(Binding binding, boolean zh) {
        if (binding != null && binding.sink() != null && !binding.sink().isBlank()) {
            return shortenTypeRef(binding.sink());
        }
        return zh ? "触发位置未绑定" : "trigger unbound";
    }

    /**
 * 默认未鉴权 / AUTH_GAP 端点，无后续配合链且无可达 RCE 类影响时，
 * 为 {@link #REPORT_ROLE_RISK_POINT}（报告底部）。
 * 高影响属性与有证据配合链保留 {@link #REPORT_ROLE_PRIMARY}。
 */
    static String classifyReportRole(
            ApiDtos.FindingDto finding, PocBinding poc, List<String> pathRunRefs) {
        if (finding == null) return REPORT_ROLE_PRIMARY;
        String prop = finding.securityProperty() == null ? "" : finding.securityProperty().trim();
        String propUpper = prop.toUpperCase(Locale.ROOT);
        String title = finding.title() == null ? "" : finding.title();
        String sink = finding.sink() == null ? "" : finding.sink().toUpperCase(Locale.ROOT);
        if (HIGH_IMPACT_PROPERTIES.contains(propUpper)
                || sinkContainsHighImpact(sink)
                || titleSuggestsHighImpact(title)) {
            return REPORT_ROLE_PRIMARY;
        }
        boolean authGapish = "AUTH_GAP".equals(propUpper)
                || "GUARD_INCONSISTENCY".equals(propUpper)
                || title.contains("鉴权缺口")
                || title.contains("鉴权门控")
                || title.toLowerCase(Locale.ROOT).contains("auth gap")
                || title.toLowerCase(Locale.ROOT).contains("auth gate");
        if (!authGapish) {
            return REPORT_ROLE_PRIMARY;
        }
        if (hasCooperationEvidence(poc, pathRunRefs)) {
            return REPORT_ROLE_PRIMARY;
        }
        return REPORT_ROLE_RISK_POINT;
    }

    private static boolean sinkContainsHighImpact(String sinkUpper) {
        if (sinkUpper == null || sinkUpper.isBlank()) return false;
        return sinkUpper.contains("BPMN")
                || sinkUpper.contains("FLOWABLE")
                || sinkUpper.contains("ACTIVITI")
                || sinkUpper.contains("CAMUNDA")
                || sinkUpper.contains("RUNTIME.EXEC")
                || sinkUpper.contains("PROCESSBUILDER")
                || sinkUpper.contains("OBJECTINPUTSTREAM")
                || sinkUpper.contains("CREATEDEPLOYMENT")
                || sinkUpper.contains("DEPLOYMENTBUILDER");
    }

    private static boolean titleSuggestsHighImpact(String title) {
        if (title == null || title.isBlank()) return false;
        String lower = title.toLowerCase(Locale.ROOT);
        return title.contains("JWT") || lower.contains("jwt")
                || title.contains("RCE") || lower.contains("rce")
                || title.contains("反序列化") || lower.contains("deserial")
                || title.contains("命令执行") || title.contains("BPMN")
                || lower.contains("bpmn") || lower.contains("flowable")
                || title.contains("硬编码") || title.contains("RememberMe");
    }

    private static boolean hasCooperationEvidence(PocBinding poc, List<String> pathRunRefs) {
        if (poc == null) return false;
        boolean runtimeish = "EXPERIMENT_HINT".equals(poc.kind())
                || "RUNTIME_OBSERVED".equals(poc.kind())
                || "AUTH_POC".equals(poc.kind());
        if (!runtimeish || pathRunRefs == null || pathRunRefs.isEmpty()) {
            return false;
        }
        for (String step : poc.steps()) {
            if (step == null) continue;
            String s = step.toLowerCase(Locale.ROOT);
            if (s.contains("effectrefs=")
                    && !s.contains("未观测")
                    && !s.contains("no sink")
                    && !s.contains("no effect")) {
                return true;
            }
            if ((s.contains("→") || s.contains("->"))
                    && (s.contains("service") || s.contains("repository")
                    || s.contains("util") || s.contains("deploy")
                    || s.contains("exec") || s.contains("mapper"))) {
                return true;
            }
        }
        return false;
    }

    private static String normalizeReportRole(String reportRole) {
        if (reportRole == null || reportRole.isBlank()) {
            return REPORT_ROLE_PRIMARY;
        }
        String upper = reportRole.trim().toUpperCase(Locale.ROOT);
        return REPORT_ROLE_RISK_POINT.equals(upper) ? REPORT_ROLE_RISK_POINT : REPORT_ROLE_PRIMARY;
    }

    private static PocBinding confirmedPoc(
            PathRunPick pick, ApiBinding api, ApiDtos.FindingDto finding, boolean zh) {
        List<String> steps = new ArrayList<>();
        ApiDtos.PathRunDto run = pick.run();
        String impact = formatImpactSurface(api, zh);
        steps.add(zh
                ? "在授权沙箱对「" + impact + "」复现请求，观测 HTTP "
                + run.httpStatus() + "，入口命中=" + run.entryHit() + "。"
                : "Replay request to \"" + impact + "\" in the authorized sandbox; observed HTTP "
                + run.httpStatus() + ", entryHit=" + run.entryHit() + ".");
        List<String> hops = businessHops(pick.trace());
        if (!hops.isEmpty()) {
            steps.add(zh
                    ? "观测到的业务调用链：" + String.join(" → ", hops)
                    : "Observed business call chain: " + String.join(" → ", hops));
        }
        if (pick.trace() != null && pick.trace().effectRefs() != null
                && !pick.trace().effectRefs().isEmpty()) {
            steps.add(zh
                    ? "已观测危险 sink 效果：" + pick.trace().effectRefs()
                    : "Observed dangerous sink effects: " + pick.trace().effectRefs());
        }
        String privilege = privilegeLabelFor(pick, finding, zh);
        if (!privilege.isBlank()) {
            steps.add(zh
                    ? "利用所需权限/身份：" + privilege
                    : "Required privilege / identity: " + privilege);
        }
        steps.add(zh
                ? "说明：已由服务端 H3/H4 门禁动态确认；不等于生产实库 VERIFIED。"
                : "Note: dynamically confirmed by server H3/H4 gate; not production VERIFIED.");
        return new PocBinding("DYNAMIC_CONFIRMED_POC", trimSteps(steps),
                "RUNTIME_OBSERVED");
    }

    private static String privilegeLabelFor(PathRunPick pick, ApiDtos.FindingDto finding, boolean zh) {
        if (pick == null || pick.run() == null) return "";
        boolean cookie = finding != null && finding.securityProperty() != null
                && (finding.securityProperty().contains("REMEMBER_ME")
                || finding.securityProperty().contains("DESERIAL"));
        String code = com.aq.jvmsentinel.worker.RequiredPrivilege.codeFor(
                com.aq.jvmsentinel.worker.TraceProjectionService.toPathRunModel(pick.run()),
                pick.trace(), cookie);
        return com.aq.jvmsentinel.worker.RequiredPrivilege.humanLabel(code, zh);
    }

    private static String extractPrivilegeFromPoc(PocBinding poc, boolean zh) {
        if (poc == null || poc.steps() == null) return "";
        String marker = zh ? "利用所需权限/身份：" : "Required privilege / identity: ";
        for (String step : poc.steps()) {
            if (step != null && step.startsWith(marker)) {
                return step.substring(marker.length()).trim();
            }
        }
        return "";
    }

    private static PocBinding forcedPoc(PathRunPick pick, ApiBinding api, boolean zh) {
        List<String> steps = new ArrayList<>();
        ApiDtos.PathRunDto run = pick.run();
        String impact = formatImpactSurface(api, zh);
        steps.add(zh
                ? "在授权沙箱对「" + impact + "」发起请求，观测 HTTP "
                + run.httpStatus() + "，入口命中=" + run.entryHit() + "。"
                : "In the authorized sandbox, request \"" + impact + "\"; observed HTTP "
                + run.httpStatus() + ", entryHit=" + run.entryHit() + ".");
        List<String> hops = businessHops(pick.trace());
        if (!hops.isEmpty()) {
            steps.add(zh
                    ? "观测到的业务调用链：" + String.join(" → ", hops)
                    : "Observed business call chain: " + String.join(" → ", hops));
        }
        if (pick.trace() != null && pick.trace().effectRefs() != null
                && !pick.trace().effectRefs().isEmpty()) {
            steps.add(zh
                    ? "观测到副作用引用：" + pick.trace().effectRefs()
                    + "（若已满足利用条件应由服务端升为动态确认）。"
                    : "Observed effect refs: " + pick.trace().effectRefs()
                    + " (server should confirm when exploit conditions are met).");
        } else {
            steps.add(zh
                    ? "尚未观测到敏感副作用触发；本材料仅证明受控环境下路径可达，不得当作利用证明。"
                    : "No sensitive side effect observed; reachability only — not exploit proof.");
        }
        steps.add(zh
                ? "说明：仅强达/入口到达不能单独确认为漏洞；需危险 sink 效果闭环。"
                : "Note: forced reachability alone cannot confirm a vulnerability; dangerous sink effect required.");
        return new PocBinding("EXPERIMENT_HINT", trimSteps(steps),
                RuntimePosture.PROVENANCE_INSTRUMENTATION);
    }

    private static PocBinding coveragePoc(PathRunPick pick, ApiBinding api, boolean zh) {
        List<String> steps = new ArrayList<>();
        String impact = formatImpactSurface(api, zh);
        steps.add(zh
                ? "使用扫描配置的身份会话访问「" + impact + "」，观测 HTTP "
                + pick.run().httpStatus() + "，入口命中=" + pick.run().entryHit() + "。"
                : "Using the scan-configured identity session, access \"" + impact
                + "\"; observed HTTP " + pick.run().httpStatus()
                + ", entryHit=" + pick.run().entryHit() + ".");
        List<String> hops = businessHops(pick.trace());
        if (!hops.isEmpty()) {
            steps.add(zh
                    ? "观测到的业务调用链：" + String.join(" → ", hops)
                    : "Observed business call chain: " + String.join(" → ", hops));
        } else {
            steps.add(zh
                    ? NO_POC_ZH + "（未观测到更深业务路径）。"
                    : NO_POC_EN + " (no deeper business path observed).");
        }
        steps.add(zh
                ? "说明：扫描身份可达不等于鉴权绕过已确认。"
                : "Note: scan-identity reachability is not confirmed auth bypass.");
        return new PocBinding("EXPERIMENT_HINT", trimSteps(steps),
                RuntimePosture.PROVENANCE_SCAN_AUTH);
    }

    private static PocBinding staticPoc(ApiBinding api, ApiDtos.EntryDto entry, boolean zh) {
        List<String> steps = new ArrayList<>();
        steps.add(zh ? NO_POC_ZH + "。" : NO_POC_EN + ".");
        String impact = formatImpactSurface(api, zh);
        if (!isUnboundApi(api) || entry != null) {
            steps.add(zh
                    ? "下一步：在授权环境对「" + impact + "」补充动态验证并核对请求/响应与副作用。"
                    : "Next: dynamically validate \"" + impact
                    + "\" in an authorized environment and inspect request/response plus side effects.");
        } else {
            steps.add(zh
                    ? "下一步：先绑定入口后再做动态验证。"
                    : "Next: bind an entrypoint, then perform dynamic validation.");
        }
        return new PocBinding("STATIC_HINT", trimSteps(steps), "STATIC_INFERRED");
    }

    private static List<String> businessHops(PathTrace trace) {
        if (trace == null) return List.of();
        List<String> hops = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        if (trace.events() != null) {
            for (TraceEvent event : trace.events()) {
                if (event == null || event.kind() != TraceEventKind.METHOD_HOP) continue;
                String subject = event.subjectRef() == null ? "" : event.subjectRef().trim();
                if (subject.isBlank()) continue;
                String lower = subject.toLowerCase(Locale.ROOT);
                if (lower.contains("javax.servlet") || lower.contains("jakarta.servlet")
                        || lower.contains("springframework.web.servlet.frameworkservlet")
                        || lower.contains("springframework.web.servlet.dispatcherservlet")
                        || lower.contains("faststringwriter")
                        || lower.contains("org.springblade.core.tool.api.r#")) {
                    continue;
                }
                if (seen.add(subject)) {
                    hops.add(subject);
                }
                if (hops.size() >= MAX_HOPS_IN_POC) break;
            }
        }
        if (hops.isEmpty() && trace.lastBusinessHop() != null && !trace.lastBusinessHop().isBlank()) {
            String last = trace.lastBusinessHop().trim();
            String lower = last.toLowerCase(Locale.ROOT);
            if (!(lower.contains("faststringwriter")
                    || lower.contains("javax.servlet")
                    || lower.contains("jakarta.servlet"))) {
                hops.add(last);
            }
        }
        return hops;
    }

    /**
     * 运行时观测到强危险 EFFECT，但静态阶段未生成<strong>可吸收该效果</strong>的 finding 时，
     * 合成 REPORT 绑定，避免 SpEL/命令等效果只出现在 AI 散文里、findingBindings 全静态。
     *
     * <p>「覆盖」必须以 H4 property 匹配为准：同入口的 AUTH_GAP 不得吞掉 EXPRESSION/DESERIAL 孤儿。
     * RememberMe 全站 DESERIAL 噪声折叠为单键，避免占满 {@link #MAX_ORPHAN_BINDINGS}。
     */
    static List<Binding> orphanEffectBindings(
            List<ApiDtos.FindingDto> findings,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.PathRunDto> pathRuns,
            Map<String, PathTrace> tracesByPathRunId,
            boolean zh) {
        List<ApiDtos.FindingDto> source = findings == null ? List.of() : findings;
        List<ApiDtos.EntryDto> catalog = entries == null ? List.of() : entries;
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;
        Map<String, PathTrace> traces = tracesByPathRunId == null ? Map.of() : tracesByPathRunId;
        LinkedHashMap<String, Binding> byKey = new LinkedHashMap<>();
        for (ApiDtos.PathRunDto run : runs) {
            if (run == null) continue;
            PathTrace trace = traces.get(run.pathRunId());
            if (trace == null || trace.effectRefs() == null || trace.effectRefs().isEmpty()) continue;
            PathRun model = TraceProjectionService.toPathRunModel(run);
            if (DynamicConfirmedGate.evaluateEffect(model, trace, "")
                    != VerificationStatus.DYNAMIC_CONFIRMED) {
                continue;
            }
            Set<String> kinds = DynamicConfirmedGate.effectKindsOf(trace);
            String property = primaryOrphanProperty(kinds);
            if (property.isBlank()) continue;
            // 仅当同入口 finding 的 securityProperty 能经 H4 吸收该 EFFECT 时才算已覆盖。
            if (effectAbsorbedByFinding(source, catalog, run, trace, model)) {
                continue;
            }
            String route = routeOf(run);
            boolean rememberMeChannel = looksLikeRememberMeChannel(run, trace);
            String key = rememberMeChannel && "DESERIALIZATION".equals(property)
                    ? "DESERIALIZATION|*|REMEMBER_ME_CHANNEL"
                    : property + "|" + run.method() + "|" + route;
            PathRunPick pick = new PathRunPick(run, trace, postureKind(run, trace));
            ApiBinding api = new ApiBinding(
                    run.method(),
                    rememberMeChannel && "DESERIALIZATION".equals(property)
                            ? "/* (RememberMe/cookie channel)"
                            : (route.isBlank() ? "/" : route),
                    run.entrypointRef() == null ? "" : run.entrypointRef());
            PocBinding poc = confirmedPoc(pick, api, null, zh);
            String sink = firstEffectSink(trace);
            String title = zh
                    ? "已动态确认的" + orphanPropertyLabel(property, true)
                    : "Dynamically confirmed " + orphanPropertyLabel(property, false);
            if (rememberMeChannel && "DESERIALIZATION".equals(property)) {
                title = zh
                        ? "已动态确认的 RememberMe/反序列化信道信号"
                        : "Dynamically confirmed RememberMe/deserialization channel signal";
            }
            String findingId = "runtime-effect-" + run.pathRunId();
            Binding binding = new Binding(
                    findingId,
                    "",
                    title,
                    "high",
                    ApiDtos.DYNAMIC_CONFIRMED,
                    api,
                    poc,
                    descriptionOf(title, ApiDtos.DYNAMIC_CONFIRMED, api, poc, zh),
                    List.of(run.pathRunId()),
                    REPORT_ROLE_PRIMARY,
                    sink,
                    midLogicOf(null, poc, trace, zh),
                    property);
            Binding prior = byKey.get(key);
            if (prior == null || preferOrphan(binding, prior)) {
                byKey.put(key, binding);
            }
        }
        List<Binding> orphans = new ArrayList<>(byKey.values());
        orphans.sort(Comparator
                .comparingInt((Binding b) -> statusRank(b.status()))
                .thenComparing(Binding::findingId));
        return orphans;
    }

    /** 同入口 finding 的 property 经 H4 可确认该 EFFECT → 由 enricher 负责，不算孤儿。 */
    private static boolean effectAbsorbedByFinding(
            List<ApiDtos.FindingDto> findings,
            List<ApiDtos.EntryDto> catalog,
            ApiDtos.PathRunDto run,
            PathTrace trace,
            PathRun model) {
        for (ApiDtos.FindingDto finding : findings) {
            if (finding == null) continue;
            if (!FindingRuntimeEnricher.matchesFindingEntry(finding, catalog, run, trace)) {
                continue;
            }
            String property = finding.securityProperty() == null ? "" : finding.securityProperty();
            if (DynamicConfirmedGate.evaluateEffect(model, trace, property)
                    == VerificationStatus.DYNAMIC_CONFIRMED) {
                return true;
            }
        }
        return false;
    }

    private static boolean looksLikeRememberMeChannel(ApiDtos.PathRunDto run, PathTrace trace) {
        String summary = run == null || run.requestSummary() == null
                ? "" : run.requestSummary().toLowerCase(Locale.ROOT);
        if (summary.contains("rememberme") || summary.contains("remember-me")
                || summary.contains("cookie")) {
            return true;
        }
        if (trace == null || trace.effectRefs() == null) return false;
        for (String ref : trace.effectRefs()) {
            if (ref == null) continue;
            String lower = ref.toLowerCase(Locale.ROOT);
            if (lower.contains("rememberme") || lower.contains("remember-me")
                    || lower.contains("shiro")) {
                return true;
            }
        }
        return false;
    }

    private static boolean preferOrphan(Binding candidate, Binding incumbent) {
        if (candidate.pathRunRefs().size() != incumbent.pathRunRefs().size()) {
            return candidate.pathRunRefs().size() > incumbent.pathRunRefs().size();
        }
        return candidate.findingId().compareTo(incumbent.findingId()) < 0;
    }

    private static String primaryOrphanProperty(Set<String> kinds) {
        if (kinds == null || kinds.isEmpty()) return "";
        for (String preferred : List.of(
                "EXPRESSION", "COMMAND", "DESERIALIZATION", "JNDI", "SQL", "JDBC",
                "SSRF", "FILE_WRITE", "FILE", "PROCESS")) {
            if (kinds.contains(preferred)) return preferred;
        }
        return "";
    }

    private static String orphanPropertyLabel(String property, boolean zh) {
        String p = property == null ? "" : property.trim().toUpperCase(Locale.ROOT);
        if (zh) {
            return switch (p) {
                case "EXPRESSION" -> "表达式/SpEL 注入信号";
                case "COMMAND" -> "命令执行信号";
                case "DESERIALIZATION" -> "反序列化信号";
                case "JNDI" -> "JNDI 注入信号";
                case "SQL", "JDBC" -> "SQL 注入信号";
                case "SSRF" -> "SSRF 信号";
                case "FILE_WRITE", "FILE" -> "文件写入信号";
                case "PROCESS" -> "进程执行信号";
                default -> "危险 sink 效果信号";
            };
        }
        return p.isBlank() ? "dangerous sink effect" : p.toLowerCase(Locale.ROOT) + " signal";
    }

    private static String routeOf(ApiDtos.PathRunDto run) {
        if (run == null) return "";
        String ref = run.entrypointRef() == null ? "" : run.entrypointRef().trim();
        if (ref.startsWith("entry:") && ref.chars().filter(ch -> ch == ':').count() >= 2) {
            int second = ref.indexOf(':', "entry:".length());
            if (second > 0 && second + 1 < ref.length()) {
                return ref.substring(second + 1);
            }
        }
        String summary = run.requestSummary() == null ? "" : run.requestSummary();
        for (String part : summary.split("\\s+")) {
            if (part.startsWith("/")) return part;
        }
        return ref;
    }

    private static String firstEffectSink(PathTrace trace) {
        if (trace == null || trace.effectRefs() == null) return "";
        for (String ref : trace.effectRefs()) {
            if (ref == null || ref.isBlank()) continue;
            if (ref.toUpperCase(Locale.ROOT).startsWith("EFFECT:")) continue;
            if (ref.contains("#") || ref.contains(".")) return ref.trim();
        }
        return trace.effectRefs().isEmpty() ? "" : trace.effectRefs().get(0);
    }

    private static String descriptionOf(
            ApiDtos.FindingDto finding, ApiBinding api, PocBinding poc, boolean zh) {
        String title = finding.title() == null ? "" : finding.title().trim();
        String status = finding.verificationStatus() == null ? ApiDtos.STATIC_INFERRED
                : finding.verificationStatus();
        return descriptionOf(title, status, api, poc, zh);
    }

    private static String descriptionOf(
            String titleRaw, String statusRaw, ApiBinding api, PocBinding poc, boolean zh) {
        String title = titleRaw == null ? "" : titleRaw.trim();
        String impact = formatImpactSurface(api, zh);
        String statusLabel = humanStatus(statusRaw, zh);
        boolean hasRuntimePoc = poc != null && ("EXPERIMENT_HINT".equals(poc.kind())
                || "RUNTIME_OBSERVED".equals(poc.kind())
                || "AUTH_POC".equals(poc.kind())
                || "DYNAMIC_CONFIRMED_POC".equals(poc.kind()))
                && poc.steps() != null && !poc.steps().isEmpty()
                && poc.steps().stream().noneMatch(s -> s != null
                && (s.contains(NO_POC_ZH) || s.contains(NO_POC_EN)
                || s.contains(NO_POC_ZH_LEGACY) || s.contains(NO_POC_EN_LEGACY)));
        if (zh) {
            StringBuilder sb = new StringBuilder();
            sb.append("存在「").append(title).append("」风险信号，影响面为「")
                    .append(impact).append("」，当前验证状态为").append(statusLabel).append("。");
            if (hasRuntimePoc) {
                sb.append("已有受控环境下的路径观测材料，可作进一步验证参考，但不得单独视为生产已证实利用。");
            } else {
                sb.append("本轮主要依据静态分析/推断信号，尚未形成可独立复现的攻击证明。");
            }
            return sb.toString();
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Risk signal \"").append(title).append("\" affects \"")
                .append(impact).append("\"; verification status is ").append(statusLabel).append(".");
        if (hasRuntimePoc) {
            sb.append(" Controlled-environment path observations exist for follow-up,")
                    .append(" but must not alone be treated as production-confirmed exploit.");
        } else {
            sb.append(" This round is based mainly on static/inferred signals;")
                    .append(" no independently reproducible exploit proof yet.");
        }
        return sb.toString();
    }

    private static ApiDtos.EntryDto resolveEntry(
            ApiDtos.FindingDto finding, List<ApiDtos.EntryDto> catalog) {
        if (finding == null || catalog.isEmpty()) return null;
        String raw = finding.entrypointId();
        if (raw == null || raw.isBlank()) raw = finding.entry();
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(catalog, raw);
        if (resolution.resolved()) return resolution.entry();
        // 尝试 finding.entry 的 METHOD:route 形式
        if (finding.entry() != null && !finding.entry().isBlank()) {
            resolution = EntryRefResolver.resolve(catalog, finding.entry());
            if (resolution.resolved()) return resolution.entry();
        }
        return null;
    }

    private static ApiBinding apiOf(ApiDtos.FindingDto finding, ApiDtos.EntryDto entry) {
        if (entry != null) {
            return new ApiBinding(
                    entry.method(),
                    entry.route(),
                    EntryRefResolver.canonicalRef(entry));
        }
        String entryText = finding.entry() == null ? "" : finding.entry().trim();
        String method = "UNKNOWN";
        String route = entryText.isBlank() ? "/" : entryText;
        if (entryText.startsWith("entry:")) {
            String rest = entryText.substring("entry:".length());
            int colon = rest.indexOf(':');
            if (colon > 0) {
                String maybeMethod = rest.substring(0, colon).toUpperCase(Locale.ROOT);
                if (maybeMethod.matches("[A-Z]+")) {
                    method = maybeMethod;
                    route = rest.substring(colon + 1);
                }
            }
        }
        String entryRef = finding.entrypointId() == null || finding.entrypointId().isBlank()
                ? ""
                : (finding.entrypointId().startsWith("entry:")
                ? finding.entrypointId()
                : "entry:" + finding.entrypointId());
        return new ApiBinding(method, route, entryRef);
    }

    private static boolean matchesEntry(
            ApiDtos.FindingDto finding,
            ApiDtos.EntryDto entry,
            List<ApiDtos.EntryDto> catalog,
            ApiDtos.PathRunDto run) {
        if (run == null || run.entrypointRef() == null) return false;
        List<String> keys = new ArrayList<>();
        if (entry != null) {
            keys.addAll(EntryRefResolver.joinKeys(catalog, EntryRefResolver.canonicalRef(entry)));
            keys.add(EntryRefResolver.methodRouteRef(entry));
        }
        if (finding.entrypointId() != null && !finding.entrypointId().isBlank()) {
            keys.addAll(EntryRefResolver.joinKeys(catalog, finding.entrypointId()));
        }
        if (finding.entry() != null && !finding.entry().isBlank()) {
            keys.addAll(EntryRefResolver.joinKeys(catalog, finding.entry()));
        }
        LinkedHashSet<String> runKeys = new LinkedHashSet<>(
                EntryRefResolver.joinKeys(catalog, run.entrypointRef()));
        for (String key : keys) {
            if (runKeys.contains(key)) return true;
        }
        return false;
    }

    private static RuntimePostureKind postureKind(ApiDtos.PathRunDto run, PathTrace trace) {
        if (trace != null && trace.posture() != null && trace.posture().postureKind() != null) {
            return trace.posture().postureKind();
        }
        String plan = run.experimentPlanId() == null ? "" : run.experimentPlanId().toLowerCase(Locale.ROOT);
        if (plan.contains("forced")) return RuntimePostureKind.FORCED_REACHABILITY;
        if (plan.contains("coverage")) return RuntimePostureKind.COVERAGE_POSTURE;
        if (plan.contains("unauth")) return RuntimePostureKind.UNAUTH;
        return RuntimePostureKind.UNAUTH;
    }

    private static boolean prefer(PathRunPick candidate, PathRunPick current) {
        int cHttp = candidate.run().httpStatus();
        int curHttp = current.run().httpStatus();
        boolean cOk = cHttp >= 200 && cHttp < 400;
        boolean curOk = curHttp >= 200 && curHttp < 400;
        if (cOk != curOk) return cOk;
        int cHops = businessHops(candidate.trace()).size();
        int curHops = businessHops(current.trace()).size();
        return cHops > curHops;
    }

    public static ArrayNode toJsonArray(List<Binding> bindings) {
        ArrayNode array = JSON.createArrayNode();
        for (Binding binding : bindings == null ? List.<Binding>of() : bindings) {
            array.add(toJson(binding));
        }
        return array;
    }

    public static ObjectNode toJson(Binding binding) {
        ObjectNode node = JSON.createObjectNode();
        if (!binding.findingId().isBlank()) node.put("findingId", binding.findingId());
        if (!binding.hypothesisId().isBlank()) node.put("hypothesisId", binding.hypothesisId());
        node.put("title", binding.title());
        node.put("severity", binding.severity());
        node.put("status", binding.status());
        node.put("reportRole", binding.reportRole());
        node.put("description", binding.description());
        if (!binding.sink().isBlank()) node.put("sink", binding.sink());
        if (!binding.midLogic().isBlank()) node.put("midLogic", binding.midLogic());
        if (!binding.securityProperty().isBlank()) {
            node.put("securityProperty", binding.securityProperty());
        }
        ObjectNode api = node.putObject("api");
        api.put("method", binding.api().method());
        api.put("route", binding.api().route());
        api.put("entryRef", binding.api().entryRef());
        ObjectNode poc = node.putObject("poc");
        poc.put("kind", binding.poc().kind());
        poc.put("provenance", binding.poc().provenance());
        ArrayNode steps = poc.putArray("steps");
        binding.poc().steps().forEach(steps::add);
        ArrayNode refs = node.putArray("pathRunRefs");
        binding.pathRunRefs().forEach(refs::add);
        return node;
    }

    public static String formatFactsBlock(List<Binding> bindings, AiOutputLanguage language) {
        int total = bindings == null ? 0 : bindings.size();
        return formatFactsBlock(bindings, total, language);
    }

    public static String formatFactsBlock(AssembleResult assembled, AiOutputLanguage language) {
        if (assembled == null) {
            return formatFactsBlock(List.of(), 0, language);
        }
        return formatFactsBlock(assembled.bindings(), assembled.totalCandidates(), language);
    }

    public static String formatFactsBlock(List<Binding> bindings, int totalCandidates,
                                          AiOutputLanguage language) {
        boolean zh = language != AiOutputLanguage.EN;
        StringBuilder block = new StringBuilder();
        if (zh) {
            block.append("FINDING_BINDINGS_FACTS（服务端从 findings×PathRun/PathTrace 装配；")
                    .append("供 PATH/REPORT 写入「关键发现」交付章节；不得编造 VERIFIED；")
                    .append("FORCED=INSTRUMENTATION_REACHABILITY）：\n");
        } else {
            block.append("FINDING_BINDINGS_FACTS (server-assembled from findings×PathRun/PathTrace; ")
                    .append("for PATH/REPORT Key Findings deliverable section; never invent VERIFIED; ")
                    .append("FORCED=INSTRUMENTATION_REACHABILITY):\n");
        }
        if (bindings == null || bindings.isEmpty()) {
            block.append(zh ? "- （空）\n" : "- (empty)\n");
            return block.toString();
        }
        int i = 0;
        for (Binding binding : bindings) {
            if (i++ >= MAX_BINDINGS) break;
            block.append("- findingId=").append(binding.findingId())
                    .append(" reportRole=").append(binding.reportRole())
                    .append(" status=").append(binding.status())
                    .append(" severity=").append(binding.severity())
                    .append(" api=").append(binding.api().method()).append(' ')
                    .append(binding.api().route())
                    .append(" entryRef=").append(binding.api().entryRef())
                    .append(" poc.kind=").append(binding.poc().kind())
                    .append(" provenance=").append(binding.poc().provenance())
                    .append('\n');
            for (String step : binding.poc().steps()) {
                block.append("  · ").append(step).append('\n');
            }
        }
        int shown = Math.min(bindings.size(), MAX_BINDINGS);
        int total = Math.max(totalCandidates, shown);
        if (total > shown) {
            block.append(zh
                    ? "- truncated=true shown=" + shown + " totalCandidates=" + total
                    + " maxBindings=" + MAX_BINDINGS
                    + "；其余请用 facts_search kind=FINDING（offset 续页）或 evidence_get finding:<id>。\n"
                    : "- truncated=true shown=" + shown + " totalCandidates=" + total
                    + " maxBindings=" + MAX_BINDINGS
                    + "; fetch remainder with facts_search kind=FINDING (offset) or evidence_get finding:<id>.\n");
        }
        return block.toString();
    }

    public static String renderMarkdownSection(List<Binding> bindings, AiOutputLanguage language) {
        boolean zh = language != AiOutputLanguage.EN;
        StringBuilder md = new StringBuilder();
        md.append(zh ? TITLE_ZH : TITLE_EN).append("\n\n");
        if (bindings == null || bindings.isEmpty()) {
            appendCoverMeta(md, List.of(), List.of(), zh);
            md.append(zh ? EXEC_SECTION_ZH : EXEC_SECTION_EN).append("\n\n");
            md.append(zh
                    ? "本轮未装配到可交付发现条目。请结合静态 findings 与动态 PathRun 复核后再生成报告。\n\n"
                    : "No deliverable findings were assembled in this round. "
                    + "Review static findings and dynamic PathRuns before publishing.\n\n");
            md.append(zh ? SECTION_ZH : SECTION_EN).append("\n\n");
            md.append(zh ? "无。\n\n" : "None.\n\n");
            return md.toString();
        }
        List<Binding> primary = new ArrayList<>();
        List<Binding> risks = new ArrayList<>();
        for (Binding binding : bindings) {
            if (REPORT_ROLE_RISK_POINT.equals(binding.reportRole())) {
                risks.add(binding);
            } else {
                primary.add(binding);
            }
        }
        appendCoverMeta(md, primary, risks, zh);
        appendExecutiveSummary(md, primary, risks, zh);

        md.append(zh ? SECTION_ZH : SECTION_EN).append("\n\n");
        if (primary.isEmpty()) {
            md.append(zh
                    ? "本期无高置信主发现；详见下方「其他风险点」。\n\n"
                    : "No high-confidence primary findings; see Additional Risk Notes below.\n\n");
        } else {
            appendFindingsBySeverity(md, primary, zh, true);
        }
        if (!risks.isEmpty()) {
            md.append(zh ? RISK_SECTION_ZH : RISK_SECTION_EN).append("\n\n");
            md.append(zh
                    ? "> 以下条目多为默认未授权/鉴权缺口入口：在缺少后续配合链或可达高影响证据时，"
                    + "仅作风险提示，不作主漏洞夸大。\n\n"
                    : "> The items below are mostly default unauthenticated / auth-gap endpoints. "
                    + "Without follow-on cooperation or reachable high-impact evidence they are risk "
                    + "notes only — not primary confirmed vulnerabilities.\n\n");
            appendFindingsBySeverity(md, risks, zh, false);
        }
        appendExploitChains(md, bindings, zh);
        appendAppendix(md, bindings, zh);
        return md.toString();
    }

    /** 按高危/中危/低危/信息/未知分组；组内验证状态优先。 */
    private static void appendFindingsBySeverity(
            StringBuilder md, List<Binding> items, boolean zh, boolean primary) {
        Map<String, List<Binding>> groups = new LinkedHashMap<>();
        for (String bucket : List.of("high", "medium", "low", "info", "unknown")) {
            groups.put(bucket, new ArrayList<>());
        }
        for (Binding binding : items) {
            groups.get(severityBucket(binding.severity())).add(binding);
        }
        for (Map.Entry<String, List<Binding>> entry : groups.entrySet()) {
            List<Binding> group = entry.getValue();
            if (group.isEmpty()) continue;
            group.sort(Comparator
                    .comparingInt((Binding b) -> statusRank(b.status()))
                    .thenComparingInt(b -> severityRank(b.severity()))
                    .thenComparing(Binding::findingId));
            md.append(severityGroupHeading(entry.getKey(), zh)).append("\n\n");
            int index = 1;
            for (Binding binding : group) {
                appendFindingCard(md, binding, zh, primary, index++);
            }
        }
    }

    private static String severityBucket(String severity) {
        return switch (normalizeSeverityKey(severity)) {
            case "critical", "high" -> "high";
            case "medium" -> "medium";
            case "low" -> "low";
            case "info" -> "info";
            default -> "unknown";
        };
    }

    private static String severityGroupHeading(String bucket, boolean zh) {
        if (!zh) {
            return switch (bucket) {
                case "high" -> "### High";
                case "medium" -> "### Medium";
                case "low" -> "### Low";
                case "info" -> "### Informational";
                default -> "### Unknown";
            };
        }
        return switch (bucket) {
            case "high" -> "### 高危";
            case "medium" -> "### 中危";
            case "low" -> "### 低危";
            case "info" -> "### 信息";
            default -> "### 未知";
        };
    }

    private static int statusRank(String status) {
        String raw = status == null || status.isBlank() ? ApiDtos.STATIC_INFERRED : status.trim();
        if (ApiDtos.DYNAMIC_CONFIRMED.equals(raw) || "VERIFIED".equals(raw)) return 0;
        if (ApiDtos.DYNAMIC_SUSPECTED.equals(raw)) return 1;
        if ("UNREACHED".equals(raw)) return 3;
        return 2;
    }

    /**
     * 保守推断可组合利用链：优先 rootCause 跨 finding 暗示，其次「鉴权/注册类」+「需认证危险 sink」。
     * 标注为推断/候选，绝不升 VERIFIED。
     */
    private static void appendExploitChains(StringBuilder md, List<Binding> bindings, boolean zh) {
        md.append(zh ? CHAIN_SECTION_ZH : CHAIN_SECTION_EN).append("\n\n");
        List<String> chains = inferExploitChains(bindings, zh);
        if (chains.isEmpty()) {
            md.append(zh ? NO_CHAIN_ZH : NO_CHAIN_EN).append("\n\n");
            return;
        }
        md.append(zh
                ? "> 以下为基于本轮发现的**候选/推断**组合利用提示，不等于已验证攻击链；"
                + "不得单独宣传为 VERIFIED。\n\n"
                : "> The following are **candidate / inferred** combination hints from this round's "
                + "findings — not verified attack chains; do not market as VERIFIED.\n\n");
        int index = 1;
        for (String chain : chains) {
            md.append(index++).append(". ").append(chain).append("\n");
        }
        md.append('\n');
    }

    static List<String> inferExploitChains(List<Binding> bindings, boolean zh) {
        if (bindings == null || bindings.isEmpty()) return List.of();
        List<Binding> enablers = new ArrayList<>();
        List<Binding> payloads = new ArrayList<>();
        for (Binding binding : bindings) {
            if (binding == null) continue;
            if (isChainEnabler(binding)) enablers.add(binding);
            if (isChainPayload(binding)) payloads.add(binding);
        }
        if (enablers.isEmpty() || payloads.isEmpty()) return List.of();
        List<String> out = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (Binding enabler : enablers) {
            for (Binding payload : payloads) {
                if (enabler.findingId().equals(payload.findingId())) continue;
                // 避免 AUTH_GAP 与自身同类重复组链
                if (isChainEnabler(payload) && !isChainPayloadExclusive(payload)) continue;
                String key = enabler.findingId() + "|" + payload.findingId();
                if (!seen.add(key)) continue;
                String left = shortFindingLabel(enabler);
                String right = shortFindingLabel(payload);
                String effect = chainEffectHint(payload, zh);
                String line = zh
                        ? "【推断/候选】" + left + " + " + right + " = " + effect
                        + "（证据强度：静态/推断组合，待动态复核）"
                        : "[inferred/candidate] " + left + " + " + right + " = " + effect
                        + " (evidence: static/inferred combination; needs dynamic review)";
                out.add(line);
                if (out.size() >= 6) return List.copyOf(out);
            }
        }
        return List.copyOf(out);
    }

    private static boolean isChainEnabler(Binding binding) {
        String prop = binding.securityProperty() == null
                ? "" : binding.securityProperty().toUpperCase(Locale.ROOT);
        String title = binding.title() == null ? "" : binding.title();
        String lower = title.toLowerCase(Locale.ROOT);
        if (REPORT_ROLE_RISK_POINT.equals(binding.reportRole())) return true;
        if ("AUTH_GAP".equals(prop) || "GUARD_INCONSISTENCY".equals(prop)
                || "AUTH_BYPASS".equals(prop)) {
            return true;
        }
        return title.contains("鉴权缺口") || title.contains("鉴权绕过") || title.contains("未授权")
                || title.contains("任意用户注册") || title.contains("注册")
                || lower.contains("auth gap") || lower.contains("auth bypass")
                || lower.contains("register") || lower.contains("signup")
                || lower.contains("unauthenticated");
    }

    private static boolean isChainPayload(Binding binding) {
        if (binding == null) return false;
        String prop = binding.securityProperty() == null
                ? "" : binding.securityProperty().toUpperCase(Locale.ROOT);
        if (HIGH_IMPACT_PROPERTIES.contains(prop)) return true;
        String sink = binding.sink() == null ? "" : binding.sink().toUpperCase(Locale.ROOT);
        if (sinkContainsHighImpact(sink)) return true;
        return titleSuggestsHighImpact(binding.title())
                || titleSuggestsUploadOrExec(binding.title());
    }

    /** 危险 payload（上传/反序列化/命令等），不含纯鉴权缺口。 */
    private static boolean isChainPayloadExclusive(Binding binding) {
        if (!isChainPayload(binding)) return false;
        String prop = binding.securityProperty() == null
                ? "" : binding.securityProperty().toUpperCase(Locale.ROOT);
        return HIGH_IMPACT_PROPERTIES.contains(prop)
                || sinkContainsHighImpact(binding.sink() == null ? "" : binding.sink().toUpperCase(Locale.ROOT))
                || titleSuggestsUploadOrExec(binding.title());
    }

    private static boolean titleSuggestsUploadOrExec(String title) {
        if (title == null || title.isBlank()) return false;
        String lower = title.toLowerCase(Locale.ROOT);
        return title.contains("上传") || title.contains("文件写") || title.contains("命令")
                || title.contains("反序列化") || title.contains("表达式")
                || lower.contains("upload") || lower.contains("file write")
                || lower.contains("command") || lower.contains("deserial")
                || lower.contains("rce") || lower.contains("expression");
    }

    private static String shortFindingLabel(Binding binding) {
        String title = binding.title() == null || binding.title().isBlank()
                ? binding.findingId() : binding.title();
        if (title.length() > 40) title = title.substring(0, 37) + "...";
        return title;
    }

    private static String chainEffectHint(Binding payload, boolean zh) {
        String prop = payload.securityProperty() == null
                ? "" : payload.securityProperty().toUpperCase(Locale.ROOT);
        String title = payload.title() == null ? "" : payload.title().toLowerCase(Locale.ROOT);
        String sink = payload.sink() == null ? "" : payload.sink().toUpperCase(Locale.ROOT);
        if (prop.contains("FILE") || title.contains("上传") || title.contains("upload")
                || sink.contains("FILE") || sink.contains("UPLOAD")) {
            return zh ? "可能进一步达成任意文件写入 / 代码执行面" : "may further enable arbitrary file write / code execution surface";
        }
        if (prop.contains("COMMAND") || prop.contains("DESERIAL") || prop.contains("EXPRESSION")
                || prop.contains("JNDI") || prop.contains("BPMN")
                || title.contains("rce") || title.contains("命令") || title.contains("反序列化")
                || sinkContainsHighImpact(sink)) {
            return zh ? "可能进一步达成远程代码执行或等价影响" : "may further enable RCE or equivalent impact";
        }
        if (prop.contains("SQL")) {
            return zh ? "可能进一步扩大数据面影响" : "may further expand data-plane impact";
        }
        return zh ? "可能扩大高影响利用面" : "may expand high-impact exploit surface";
    }

    private static void appendCoverMeta(
            StringBuilder md, List<Binding> primary, List<Binding> risks, boolean zh) {
        int total = primary.size() + risks.size();
        String overall = overallConclusion(primary, risks, zh);
        md.append(zh ? "## 报告元信息\n\n" : "## Report Metadata\n\n");
        md.append(zh ? "- **范围摘要**: 共 " : "- **Scope summary**: ")
                .append(total)
                .append(zh ? " 条发现（关键发现 " : " findings (key findings ")
                .append(primary.size())
                .append(zh ? " / 其他风险点 " : " / additional risk notes ")
                .append(risks.size())
                .append(zh ? "）\n" : ")\n");
        md.append(zh ? "- **总体结论**: " : "- **Overall conclusion**: ")
                .append(overall).append("\n\n");
    }

    private static void appendExecutiveSummary(
            StringBuilder md, List<Binding> primary, List<Binding> risks, boolean zh) {
        List<Binding> all = new ArrayList<>(primary);
        all.addAll(risks);
        md.append(zh ? EXEC_SECTION_ZH : EXEC_SECTION_EN).append("\n\n");
        md.append(zh ? "### 发现数量（按严重度）\n\n" : "### Finding counts by severity\n\n");
        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        for (String level : List.of("critical", "high", "medium", "low", "info")) {
            bySeverity.put(level, 0);
        }
        for (Binding binding : all) {
            String key = normalizeSeverityKey(binding.severity());
            bySeverity.merge(key, 1, Integer::sum);
        }
        for (Map.Entry<String, Integer> entry : bySeverity.entrySet()) {
            if (entry.getValue() <= 0) continue;
            md.append("- ").append(severityDisplay(entry.getKey(), zh))
                    .append(": ").append(entry.getValue()).append('\n');
        }
        if (all.isEmpty()) {
            md.append(zh ? "- （无）\n" : "- (none)\n");
        }
        md.append('\n');
        int verifiedLike = 0;
        int staticOnly = 0;
        int staticWithRuntime = 0;
        int pending = 0;
        int withPoc = 0;
        for (Binding binding : all) {
            String status = binding.status();
            boolean runtimeMaterial = hasRuntimePathMaterial(binding);
            if (ApiDtos.DYNAMIC_CONFIRMED.equals(status) || "VERIFIED".equals(status)) {
                verifiedLike++;
            } else if (ApiDtos.DYNAMIC_SUSPECTED.equals(status)) {
                pending++;
            } else if (runtimeMaterial) {
                // FORCED/COVERAGE 材料按 ADR-0004 保持 STATIC_INFERRED，但不得计入「纯静态」。
                staticWithRuntime++;
            } else {
                staticOnly++;
            }
            if (hasReproduciblePoc(binding)) withPoc++;
        }
        md.append(zh ? "### 验证与复现概况\n\n" : "### Verification and reproduction overview\n\n");
        md.append(zh
                ? "- **已动态确认/已验证**: " + verifiedLike + "\n"
                + "- **动态疑似（待进一步验证）**: " + pending + "\n"
                + "- **含运行时路径材料（强达/覆盖，未确认）**: " + staticWithRuntime + "\n"
                + "- **仅静态信号**: " + staticOnly + "\n"
                + "- **具备可复现 PoC 材料**: " + withPoc + "\n\n"
                : "- **Dynamically confirmed / verified**: " + verifiedLike + "\n"
                + "- **Dynamically suspected (needs further validation)**: " + pending + "\n"
                + "- **With runtime path material (forced/coverage, unconfirmed)**: "
                + staticWithRuntime + "\n"
                + "- **Static signal only**: " + staticOnly + "\n"
                + "- **With reproducible PoC material**: " + withPoc + "\n\n");
        md.append(zh
                ? "> 说明：验证状态由服务端证据门禁决定；强达/覆盖材料≠已确认利用；"
                + "静态信号与受控实验材料不得宣传为生产环境已证实利用。\n\n"
                : "> Note: verification status is server-gated by evidence; forced/coverage material "
                + "is not confirmed exploitability; static signals and controlled experiment material "
                + "must not be marketed as production-confirmed exploits.\n\n");
    }

    static boolean hasRuntimePathMaterial(Binding binding) {
        if (binding == null) return false;
        if (binding.pathRunRefs() != null && !binding.pathRunRefs().isEmpty()) return true;
        return hasReproduciblePoc(binding);
    }

    private static void appendFindingCard(
            StringBuilder md, Binding binding, boolean zh, boolean primary, int index) {
        // 组内编号用 ####，避免与严重度 ### 高危 冲突
        md.append("#### ").append(index).append(". ").append(binding.title()).append("\n\n");
        if (!primary) {
            md.append(zh
                    ? "- **标注**: 风险提示（非主发现）\n"
                    : "- **Label**: risk note (not a primary finding)\n");
        }
        md.append(zh ? "- **风险等级**: " : "- **Risk level**: ")
                .append(severityDisplay(binding.severity(), zh)).append('\n');
        md.append(zh ? "- **验证状态**: " : "- **Verification status**: ")
                .append(humanStatus(binding.status(), zh)).append('\n');
        if (ApiDtos.DYNAMIC_CONFIRMED.equals(binding.status()) || "VERIFIED".equals(binding.status())) {
            String privilege = extractPrivilegeFromPoc(binding.poc(), zh);
            if (!privilege.isBlank()) {
                md.append(zh ? "- **所需权限**: " : "- **Required privilege**: ")
                        .append(privilege).append('\n');
            }
        }
        md.append(zh ? "- **简述**: " : "- **Summary**: ")
                .append(binding.description()).append('\n');
        appendTechPath(md, binding, zh);
        md.append(zh ? "- **复现步骤**:\n" : "- **Reproduction steps**:\n");
        if (binding.poc().steps().isEmpty()) {
            md.append("  1. ").append(zh ? NO_POC_ZH : NO_POC_EN).append('\n');
        } else {
            int stepNo = 1;
            for (String step : binding.poc().steps()) {
                md.append("  ").append(stepNo++).append(". ").append(step).append('\n');
            }
        }
        md.append(zh ? "\n##### 证据摘要\n\n" : "\n##### Evidence digest\n\n");
        if (!binding.sink().isBlank()) {
            md.append(zh ? "- sink: `" : "- sink: `")
                    .append(binding.sink()).append("`\n");
        }
        if (!binding.api().entryRef().isBlank()) {
            md.append("- entryId: `").append(binding.api().entryRef()).append("`\n");
        } else {
            md.append(zh ? "- entryId: （未绑定）\n" : "- entryId: (unbound)\n");
        }
        md.append("- provenance: `")
                .append(binding.poc().provenance().isBlank()
                        ? "STATIC_INFERRED" : binding.poc().provenance())
                .append("`\n\n");
    }

    private static void appendTechPath(StringBuilder md, Binding binding, boolean zh) {
        String entry = formatImpactSurface(binding.api(), zh);
        String mid = binding.midLogic() == null || binding.midLogic().isBlank()
                ? (zh ? NO_MID_LOGIC_ZH : NO_MID_LOGIC_EN)
                : binding.midLogic();
        String trigger = triggerLocation(binding, zh);
        if (zh) {
            md.append("- **技术路径**:\n");
            md.append("  - **入口**: ").append(entry).append('\n');
            md.append("  - **中途代码逻辑**: ").append(mid).append('\n');
            md.append("  - **底层触发位置**: `").append(trigger).append("`\n");
        } else {
            md.append("- **Technical path**:\n");
            md.append("  - **Entry**: ").append(entry).append('\n');
            md.append("  - **Intermediate logic**: ").append(mid).append('\n');
            md.append("  - **Trigger location**: `").append(trigger).append("`\n");
        }
    }

    private static void appendAppendix(StringBuilder md, List<Binding> bindings, boolean zh) {
        md.append(zh ? APPENDIX_SECTION_ZH : APPENDIX_SECTION_EN).append("\n\n");
        md.append(zh
                ? "以下内容供技术复核，不属于面向业务读者的主文结论。\n\n"
                : "The following is for technical review and is not part of the business-facing conclusion.\n\n");
        int index = 1;
        for (Binding binding : bindings) {
            md.append(zh ? "### A." : "### A.")
                    .append(index++).append(' ').append(binding.title()).append("\n\n");
            if (!binding.findingId().isBlank()) {
                md.append("- findingId: `").append(binding.findingId()).append("`\n");
            }
            md.append("- status: `").append(binding.status()).append("`\n");
            md.append("- severity: `").append(binding.severity()).append("`\n");
            md.append("- reportRole: `").append(binding.reportRole()).append("`\n");
            md.append("- api: `").append(binding.api().method()).append(' ')
                    .append(binding.api().route()).append("`\n");
            if (!binding.api().entryRef().isBlank()) {
                md.append("- entryRef: `").append(binding.api().entryRef()).append("`\n");
            }
            if (!binding.sink().isBlank()) {
                md.append("- sink: `").append(binding.sink()).append("`\n");
            }
            md.append("- poc.kind: `").append(binding.poc().kind()).append("`\n");
            md.append("- provenance: `")
                    .append(binding.poc().provenance().isBlank()
                            ? "STATIC_INFERRED" : binding.poc().provenance())
                    .append("`\n");
            if (!binding.pathRunRefs().isEmpty()) {
                md.append("- pathRunRefs: `")
                        .append(String.join("`, `", binding.pathRunRefs()))
                        .append("`\n");
            }
            md.append('\n');
        }
    }

    /**
     * 确保报告 Markdown 以 locale-pure 可交付结构开头，由 bindings 构建。
     */
    public static EnforceResult enforceReportSection(
            String summaryMarkdown, List<Binding> bindings, AiOutputLanguage language) {
        boolean zh = language != AiOutputLanguage.EN;
        String sectionHeader = zh ? SECTION_ZH : SECTION_EN;
        String wrongHeader = zh ? SECTION_EN : SECTION_ZH;
        String body = summaryMarkdown == null ? "" : summaryMarkdown;
        String rendered = renderMarkdownSection(bindings, language);
        boolean hasSection = body.contains(sectionHeader);
        boolean hasExec = body.contains(zh ? EXEC_SECTION_ZH : EXEC_SECTION_EN);
        boolean hasAppendix = body.contains(zh ? APPENDIX_SECTION_ZH : APPENDIX_SECTION_EN);
        boolean hasLegacy = body.contains(zh ? LEGACY_SECTION_ZH : LEGACY_SECTION_EN)
                || body.contains(zh ? "## 风险点\n" : "## Risk Points\n");
        boolean hasApi = bodyContainsAnyApi(body, bindings)
                || bodyContainsImpactMarker(body, zh);
        boolean hasPocMarker = zh
                ? (body.contains("PoC") || body.contains("复现")
                || body.contains(NO_POC_ZH) || body.contains(NO_POC_ZH_LEGACY))
                : (body.contains("PoC") || body.contains("Reproduction")
                || body.contains(NO_POC_EN) || body.contains(NO_POC_EN_LEGACY));
        boolean needsRisk = bindings != null && bindings.stream()
                .anyMatch(b -> REPORT_ROLE_RISK_POINT.equals(b.reportRole()));
        String riskHeader = zh ? RISK_SECTION_ZH : RISK_SECTION_EN;
        boolean hasRiskSection = !needsRisk || body.contains(riskHeader);
        boolean hasChain = body.contains(zh ? CHAIN_SECTION_ZH : CHAIN_SECTION_EN);
        boolean hasTechPath = zh
                ? (body.contains("技术路径") || body.contains("中途代码逻辑"))
                : (body.contains("Technical path") || body.contains("Intermediate logic"));
        boolean mixed = body.contains(wrongHeader)
                || hasLegacy
                || (zh && (body.contains("## Executive Summary")
                || body.contains("## Key Findings")
                || body.contains("## Vulnerabilities")))
                || (!zh && (body.contains("## 执行摘要")
                || body.contains("## 关键发现")
                || body.contains("## 漏洞相关")));
        if (hasSection && hasExec && hasAppendix && hasApi && hasPocMarker
                && hasRiskSection && hasChain && hasTechPath && !mixed) {
            return new EnforceResult(body, false, false);
        }
        String cleaned = body;
        for (String header : List.of(
                wrongHeader,
                LEGACY_SECTION_ZH,
                LEGACY_SECTION_EN,
                "## Risk Points",
                "## 风险点",
                "# Audit Report",
                "# 审计报告")) {
            cleaned = stripLeadingWrongSection(cleaned, header);
        }
        // 服务端交付骨架前置；清理后的模型叙事保留在后。
        String merged = rendered + "\n" + cleaned.trim();
        if (!merged.startsWith("#")) {
            merged = (zh ? TITLE_ZH : TITLE_EN) + "\n\n" + merged;
        }
        return new EnforceResult(merged, true, mixed || hasLegacy);
    }

    public static List<Binding> parseFromConclusion(String conclusionJson) {
        if (conclusionJson == null || conclusionJson.isBlank()) return List.of();
        try {
            JsonNode root = JSON.readTree(conclusionJson);
            JsonNode array = root.get("findingBindings");
            if (array == null || !array.isArray() || array.isEmpty()) return List.of();
            List<Binding> out = new ArrayList<>();
            for (JsonNode item : array) {
                if (item == null || !item.isObject()) continue;
                ObjectNode apiNode = item.has("api") && item.get("api").isObject()
                        ? (ObjectNode) item.get("api") : JSON.createObjectNode();
                ObjectNode pocNode = item.has("poc") && item.get("poc").isObject()
                        ? (ObjectNode) item.get("poc") : JSON.createObjectNode();
                List<String> steps = new ArrayList<>();
                if (pocNode.path("steps").isArray()) {
                    for (JsonNode step : pocNode.path("steps")) {
                        if (step != null && step.isTextual() && !step.asText().isBlank()) {
                            steps.add(step.asText());
                        }
                    }
                }
                List<String> refs = new ArrayList<>();
                if (item.path("pathRunRefs").isArray()) {
                    for (JsonNode ref : item.path("pathRunRefs")) {
                        if (ref != null && ref.isTextual()) refs.add(ref.asText());
                    }
                }
                out.add(new Binding(
                        text(item, "findingId"),
                        text(item, "hypothesisId"),
                        text(item, "title"),
                        text(item, "severity"),
                        text(item, "status"),
                        new ApiBinding(text(apiNode, "method"), text(apiNode, "route"), text(apiNode, "entryRef")),
                        new PocBinding(text(pocNode, "kind"), steps, text(pocNode, "provenance")),
                        text(item, "description"),
                        refs,
                        text(item, "reportRole"),
                        text(item, "sink"),
                        text(item, "midLogic"),
                        text(item, "securityProperty")));
            }
            out.sort(bindingDeliverableOrder());
            if (out.size() > MAX_BINDINGS) {
                return List.copyOf(out.subList(0, MAX_BINDINGS));
            }
            return List.copyOf(out);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    public record EnforceResult(String summary, boolean appendedByServer, boolean localeRepaired) {
        public EnforceResult {
            summary = summary == null ? "" : summary;
        }
    }

    private record PathRunPick(ApiDtos.PathRunDto run, PathTrace trace, RuntimePostureKind kind) {
        private PathRunPick {
            Objects.requireNonNull(run, "run");
        }
    }

    private static List<String> trimSteps(List<String> steps) {
        if (steps.size() <= MAX_POC_STEPS) return List.copyOf(steps);
        return List.copyOf(steps.subList(0, MAX_POC_STEPS));
    }

    private static boolean bodyContainsAnyApi(String body, List<Binding> bindings) {
        if (body == null || bindings == null) return false;
        for (Binding binding : bindings) {
            if (binding.api().route() != null && body.contains(binding.api().route())) {
                return true;
            }
            if (!binding.api().entryRef().isBlank() && body.contains(binding.api().entryRef())) {
                return true;
            }
        }
        return false;
    }

    private static boolean bodyContainsImpactMarker(String body, boolean zh) {
        if (body == null || body.isBlank()) return false;
        return zh
                ? (body.contains("影响面") || body.contains("入口未绑定")
                || body.contains("技术路径") || body.contains("**入口**"))
                : (body.contains("Impact surface") || body.contains("entrypoint unbound")
                || body.contains("Technical path") || body.contains("**Entry**"));
    }

    static boolean isUnboundApi(ApiBinding api) {
        if (api == null) return true;
        String method = api.method() == null ? "" : api.method().trim().toUpperCase(Locale.ROOT);
        String route = api.route() == null ? "" : api.route().trim();
        boolean unknownMethod = method.isBlank() || "UNKNOWN".equals(method);
        boolean unboundRoute = route.isBlank() || "/".equals(route)
                || "UNBOUND".equalsIgnoreCase(route)
                || "entry-unbound".equalsIgnoreCase(route);
        return (unknownMethod && unboundRoute) || "UNBOUND".equalsIgnoreCase(route);
    }

    static String formatImpactSurface(ApiBinding api, boolean zh) {
        if (isUnboundApi(api)) {
            return zh ? "入口未绑定" : "entrypoint unbound";
        }
        String method = api.method();
        String route = api.route();
        if ("UNKNOWN".equalsIgnoreCase(method)) {
            return route;
        }
        return method + " " + route;
    }

    static String humanStatus(String status, boolean zh) {
        String raw = status == null || status.isBlank() ? ApiDtos.STATIC_INFERRED : status.trim();
        if (zh) {
            return switch (raw) {
                case ApiDtos.DYNAMIC_CONFIRMED -> "已动态确认（DYNAMIC_CONFIRMED）";
                case "VERIFIED" -> "已验证（VERIFIED）";
                case ApiDtos.DYNAMIC_SUSPECTED -> "动态疑似 / 待验证（DYNAMIC_SUSPECTED）";
                case "UNREACHED" -> "尚未触及（UNREACHED）";
                default -> "仅静态信号（" + raw + "）";
            };
        }
        return switch (raw) {
            case ApiDtos.DYNAMIC_CONFIRMED -> "Dynamically confirmed (DYNAMIC_CONFIRMED)";
            case "VERIFIED" -> "Verified (VERIFIED)";
            case ApiDtos.DYNAMIC_SUSPECTED -> "Dynamically suspected / pending (DYNAMIC_SUSPECTED)";
            case "UNREACHED" -> "Unreached (UNREACHED)";
            default -> "Static signal only (" + raw + ")";
        };
    }

    private static int severityRank(String severity) {
        return switch (normalizeSeverityKey(severity)) {
            case "critical" -> 0;
            case "high" -> 1;
            case "medium" -> 2;
            case "low" -> 3;
            case "info" -> 4;
            default -> 5;
        };
    }

    private static String normalizeSeverityKey(String severity) {
        if (severity == null || severity.isBlank()) return "info";
        return severity.trim().toLowerCase(Locale.ROOT);
    }

    private static String severityDisplay(String severity, boolean zh) {
        String key = normalizeSeverityKey(severity);
        if (!zh) {
            return switch (key) {
                case "critical" -> "critical (high)";
                case "high" -> "high";
                case "medium" -> "medium";
                case "low" -> "low";
                case "info" -> "info";
                default -> severity == null || severity.isBlank() ? "unknown" : severity;
            };
        }
        return switch (key) {
            case "critical" -> "高危（critical）";
            case "high" -> "高危（high）";
            case "medium" -> "中危（medium）";
            case "low" -> "低危（low）";
            case "info" -> "信息（info）";
            default -> severity == null || severity.isBlank() ? "未知" : severity;
        };
    }

    private static String overallConclusion(
            List<Binding> primary, List<Binding> risks, boolean zh) {
        List<Binding> all = new ArrayList<>(primary == null ? List.of() : primary);
        if (risks != null) all.addAll(risks);
        if (all.isEmpty()) {
            return zh ? "本轮未形成可交付风险结论。" : "No deliverable risk conclusion in this round.";
        }
        String topSeverity = "info";
        int bestRank = Integer.MAX_VALUE;
        boolean anyConfirmed = false;
        boolean anySuspected = false;
        boolean anyRuntimeMaterial = false;
        for (Binding binding : all) {
            int rank = severityRank(binding.severity());
            if (rank < bestRank) {
                bestRank = rank;
                topSeverity = normalizeSeverityKey(binding.severity());
            }
            if (ApiDtos.DYNAMIC_CONFIRMED.equals(binding.status())
                    || "VERIFIED".equals(binding.status())) {
                anyConfirmed = true;
            } else if (ApiDtos.DYNAMIC_SUSPECTED.equals(binding.status())) {
                anySuspected = true;
            }
            if (hasRuntimePathMaterial(binding)) {
                anyRuntimeMaterial = true;
            }
        }
        String sev = severityDisplay(topSeverity, zh);
        if (zh) {
            if (anyConfirmed) {
                return "存在" + sev + "级已动态确认发现，建议优先处置并复核影响面。";
            }
            if (anySuspected) {
                return "最高风险等级为" + sev + "，存在动态疑似信号，需继续验证后定级。";
            }
            if (anyRuntimeMaterial) {
                return "最高风险等级为" + sev + "，已有受控强达/路径观测材料，"
                        + "但尚无危险 sink 效果闭环确认，不得宣传为已确认可利用。";
            }
            return "最高风险等级为" + sev + "，当前以静态推断为主，尚无已确认可利用证明。";
        }
        if (anyConfirmed) {
            return "Contains " + sev + "-severity dynamically confirmed findings; prioritize remediation.";
        }
        if (anySuspected) {
            return "Highest severity is " + sev
                    + "; dynamic suspicion exists and needs further validation before final rating.";
        }
        if (anyRuntimeMaterial) {
            return "Highest severity is " + sev
                    + "; controlled forced/path observations exist, but no dangerous sink-effect "
                    + "confirmation yet — not confirmed exploitability.";
        }
        return "Highest severity is " + sev
                + "; currently static-inferred with no confirmed exploitability proof.";
    }

    private static boolean hasReproduciblePoc(Binding binding) {
        if (binding == null || binding.poc() == null || binding.poc().steps().isEmpty()) {
            return false;
        }
        String kind = binding.poc().kind();
        if ("STATIC_HINT".equals(kind)) return false;
        for (String step : binding.poc().steps()) {
            if (step == null) continue;
            if (step.contains(NO_POC_ZH) || step.contains(NO_POC_EN)
                    || step.contains(NO_POC_ZH_LEGACY) || step.contains(NO_POC_EN_LEGACY)) {
                return false;
            }
        }
        return "EXPERIMENT_HINT".equals(kind)
                || "RUNTIME_OBSERVED".equals(kind)
                || "AUTH_POC".equals(kind);
    }

    private static String stripLeadingWrongSection(String body, String wrongHeader) {
        if (body == null || body.isBlank() || wrongHeader == null) return body == null ? "" : body;
        int idx = body.indexOf(wrongHeader);
        if (idx < 0) return body;
        // 错误标题首行块之后到下一正确语言 ## 之前的内容——简单丢弃。
        return body.substring(0, idx) + body.substring(idx + wrongHeader.length());
    }

    private static int skipBom(String text) {
        if (text != null && !text.isEmpty() && text.charAt(0) == '\uFEFF') return 1;
        return 0;
    }

    private static String text(JsonNode node, String field) {
        if (node == null || field == null) return "";
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? "" : value.asText("");
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    /** 合并 AI 提供的 binding 与服务端装配；服务端填缺口，绝不提升。 */
    public static List<Binding> mergePreferringServer(List<Binding> ai, List<Binding> server) {
        if (server == null || server.isEmpty()) {
            return ai == null ? List.of() : List.copyOf(ai);
        }
        if (ai == null || ai.isEmpty()) return List.copyOf(server);
        Map<String, Binding> byId = new LinkedHashMap<>();
        for (Binding binding : server) {
            String key = binding.findingId().isBlank() ? binding.title() : binding.findingId();
            byId.put(key, binding);
        }
        for (Binding binding : ai) {
            String key = binding.findingId().isBlank() ? binding.title() : binding.findingId();
            Binding existing = byId.get(key);
            if (existing == null) {
                byId.put(key, binding);
                continue;
            }
            // AI 缺步骤时优先服务端 PoC；AI 描述更丰富且 locale 一致则保留。
            if (existing.poc().steps().isEmpty() && !binding.poc().steps().isEmpty()) {
                byId.put(key, binding);
            }
        }
        List<Binding> merged = new ArrayList<>(byId.values());
        merged.sort(bindingDeliverableOrder());
        if (merged.size() > MAX_BINDINGS) {
            return List.copyOf(merged.subList(0, MAX_BINDINGS));
        }
        return List.copyOf(merged);
    }

    /** 截断前的选择序：已确认 > 疑似 > 高严重度/高影响 > 普通 > AUTH_GAP 噪音。 */
    private static Comparator<ApiDtos.FindingDto> findingSelectionOrder() {
        return Comparator
                .comparingInt((ApiDtos.FindingDto f) -> statusRank(f.verificationStatus()))
                .thenComparingInt(f -> severityRank(f.severity()))
                .thenComparingInt(FindingBindings::selectionImpactRank)
                .thenComparing(f -> nullToEmpty(f.findingId()));
    }

    private static Comparator<Binding> bindingDeliverableOrder() {
        return Comparator
                .comparingInt((Binding b) -> REPORT_ROLE_RISK_POINT.equals(b.reportRole()) ? 1 : 0)
                .thenComparingInt(b -> statusRank(b.status()))
                .thenComparingInt(b -> severityRank(b.severity()))
                .thenComparing(Binding::findingId);
    }

    /** 数值越小越优先保留进 MAX_BINDINGS 窗口。 */
    private static int selectionImpactRank(ApiDtos.FindingDto finding) {
        if (finding == null) return 9;
        String prop = finding.securityProperty() == null ? "" : finding.securityProperty().trim();
        String propUpper = prop.toUpperCase(Locale.ROOT);
        String title = finding.title() == null ? "" : finding.title();
        String sink = finding.sink() == null ? "" : finding.sink().toUpperCase(Locale.ROOT);
        if (HIGH_IMPACT_PROPERTIES.contains(propUpper)
                || sinkContainsHighImpact(sink)
                || titleSuggestsHighImpact(title)) {
            return 0;
        }
        boolean authGapish = "AUTH_GAP".equals(propUpper)
                || "GUARD_INCONSISTENCY".equals(propUpper)
                || title.contains("鉴权缺口")
                || title.contains("鉴权门控")
                || title.toLowerCase(Locale.ROOT).contains("auth gap")
                || title.toLowerCase(Locale.ROOT).contains("auth gate");
        return authGapish ? 2 : 1;
    }
}

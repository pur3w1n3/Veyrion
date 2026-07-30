package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
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
 * <p>绝不捏造 VERIFIED 利用。FORCED PathRun 变为
 * {@code INSTRUMENTATION_REACHABILITY} 实验提示，非匿名 exploit 证明。</p>
 */
public final class FindingBindings {
    public static final int MAX_BINDINGS = 48;
    public static final int MAX_POC_STEPS = 8;
    public static final int MAX_HOPS_IN_POC = 6;
    public static final String SECTION_ZH = "## 漏洞相关";
    public static final String SECTION_EN = "## Vulnerabilities";
    public static final String RISK_SECTION_ZH = "## 风险点";
    public static final String RISK_SECTION_EN = "## Risk Points";
    public static final String REPORT_ROLE_PRIMARY = "PRIMARY";
    public static final String REPORT_ROLE_RISK_POINT = "RISK_POINT";
    public static final String NO_POC_ZH = "暂无 PoC";
    public static final String NO_POC_EN = "No PoC yet";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> HIGH_IMPACT_PROPERTIES = Set.of(
            "JWT", "BPMN_DEPLOY", "BPMN_EXEC", "COMMAND", "DESERIALIZATION",
            "FILE", "FILE_WRITE", "FILE_READ", "SQL", "SSRF", "EXPRESSION", "TEMPLATE",
            "JNDI", "HARDCODED_JWT_SIGN_KEY", "HARDCODED_REMEMBER_ME_CIPHER_KEY",
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
            String reportRole
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
            if ("VERIFIED".equals(status) || ApiDtos.DYNAMIC_CONFIRMED.equals(status)) {
                // binding 不得铸造提升；调用方仅透传服务端 status。
            }
        }

        /** 向后兼容重载（默认 PRIMARY）。 */
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
                    pathRunRefs, REPORT_ROLE_PRIMARY);
        }
    }

    public static List<Binding> assemble(
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
        List<Binding> out = new ArrayList<>();
        for (ApiDtos.FindingDto finding : source) {
            if (finding == null || out.size() >= MAX_BINDINGS) break;
            out.add(bindOne(finding, catalog, runs, traces, zh));
        }
        out.sort(Comparator
                .comparingInt((Binding b) -> REPORT_ROLE_RISK_POINT.equals(b.reportRole()) ? 1 : 0)
                .thenComparing(Binding::findingId));
        return List.copyOf(out);
    }

    private static Binding bindOne(
            ApiDtos.FindingDto finding,
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
        for (ApiDtos.PathRunDto run : runs) {
            if (run == null || !matchesEntry(finding, entry, catalog, run)) continue;
            if (!Boolean.TRUE.equals(run.entryHit())) continue;
            PathTrace trace = traces.get(run.pathRunId());
            RuntimePostureKind kind = postureKind(run, trace);
            PathRunPick pick = new PathRunPick(run, trace, kind);
            if (kind == RuntimePostureKind.FORCED_REACHABILITY) {
                forcedRefs.add(run.pathRunId());
                if (bestForced == null || prefer(pick, bestForced)) bestForced = pick;
            } else if (kind == RuntimePostureKind.COVERAGE_POSTURE) {
                coverageRefs.add(run.pathRunId());
                if (bestCoverage == null || prefer(pick, bestCoverage)) bestCoverage = pick;
            }
        }
        String status = finding.verificationStatus() == null || finding.verificationStatus().isBlank()
                ? ApiDtos.STATIC_INFERRED : finding.verificationStatus();
        // binding 绝不提升。
        if ("VERIFIED".equals(status)) {
            status = ApiDtos.STATIC_INFERRED;
        }
        PocBinding poc;
        List<String> pathRunRefs;
        if (bestForced != null) {
            poc = forcedPoc(bestForced, api, zh);
            pathRunRefs = List.copyOf(forcedRefs);
        } else if (bestCoverage != null) {
            poc = coveragePoc(bestCoverage, api, zh);
            pathRunRefs = List.copyOf(coverageRefs);
        } else {
            poc = staticPoc(api, entry, zh);
            pathRunRefs = List.of();
        }
        String reportRole = classifyReportRole(finding, poc, pathRunRefs);
        return new Binding(
                finding.findingId(),
                finding.hypothesisId() == null ? "" : finding.hypothesisId(),
                finding.title(),
                finding.severity(),
                status,
                api,
                poc,
                descriptionOf(finding, api, poc, zh),
                pathRunRefs,
                reportRole);
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

    private static PocBinding forcedPoc(PathRunPick pick, ApiBinding api, boolean zh) {
        List<String> steps = new ArrayList<>();
        ApiDtos.PathRunDto run = pick.run();
        steps.add(zh
                ? "接口 " + api.method() + " " + api.route()
                + "；实验 plan=" + nullToEmpty(run.experimentPlanId())
                + "；姿态 FORCED_REACHABILITY（Docker 强达，非匿名利用）。"
                : "API " + api.method() + " " + api.route()
                + "; experiment plan=" + nullToEmpty(run.experimentPlanId())
                + "; posture FORCED_REACHABILITY (Docker forced reachability, not anonymous exploit).");
        steps.add(zh
                ? "观测 HTTP " + run.httpStatus() + "，entryHit=" + run.entryHit()
                + "；provenance=" + RuntimePosture.PROVENANCE_INSTRUMENTATION + "。"
                : "Observed HTTP " + run.httpStatus() + ", entryHit=" + run.entryHit()
                + "; provenance=" + RuntimePosture.PROVENANCE_INSTRUMENTATION + ".");
        List<String> hops = businessHops(pick.trace());
        if (!hops.isEmpty()) {
            steps.add(zh
                    ? "失败前/响应前业务跳点：" + String.join(" → ", hops)
                    : "Business hops before exit/response: " + String.join(" → ", hops));
        }
        if (pick.trace() != null && pick.trace().effectRefs() != null
                && !pick.trace().effectRefs().isEmpty()) {
            steps.add(zh
                    ? "effectRefs=" + pick.trace().effectRefs()
                    : "effectRefs=" + pick.trace().effectRefs());
        } else {
            steps.add(zh
                    ? "未观测到 sink/effect 触发；不得写成已确认利用。"
                    : "No sink/effect observed; must not claim confirmed exploit.");
        }
        steps.add(zh
                ? "禁止升 VERIFIED / DYNAMIC_CONFIRMED（ADR-0004）。"
                : "Must not elevate VERIFIED / DYNAMIC_CONFIRMED (ADR-0004).");
        return new PocBinding("EXPERIMENT_HINT", trimSteps(steps),
                RuntimePosture.PROVENANCE_INSTRUMENTATION);
    }

    private static PocBinding coveragePoc(PathRunPick pick, ApiBinding api, boolean zh) {
        List<String> steps = new ArrayList<>();
        steps.add(zh
                ? "接口 " + api.method() + " " + api.route()
                + "；姿态 COVERAGE_POSTURE（扫描身份/会话注入，非绕过确认）。"
                : "API " + api.method() + " " + api.route()
                + "; posture COVERAGE_POSTURE (scan identity/session seed, not bypass confirmation).");
        steps.add(zh
                ? "观测 HTTP " + pick.run().httpStatus() + "，entryHit=" + pick.run().entryHit() + "。"
                : "Observed HTTP " + pick.run().httpStatus() + ", entryHit=" + pick.run().entryHit() + ".");
        List<String> hops = businessHops(pick.trace());
        if (!hops.isEmpty()) {
            steps.add(zh
                    ? "业务跳点：" + String.join(" → ", hops)
                    : "Business hops: " + String.join(" → ", hops));
        } else {
            steps.add(zh ? NO_POC_ZH + "（无更深业务跳点）。" : NO_POC_EN + " (no deeper business hops).");
        }
        return new PocBinding("EXPERIMENT_HINT", trimSteps(steps),
                RuntimePosture.PROVENANCE_SCAN_AUTH);
    }

    private static PocBinding staticPoc(ApiBinding api, ApiDtos.EntryDto entry, boolean zh) {
        List<String> steps = new ArrayList<>();
        if (api.entryRef().isBlank() && (entry == null)) {
            steps.add(zh ? NO_POC_ZH : NO_POC_EN);
            return new PocBinding("STATIC_HINT", steps, "STATIC_INFERRED");
        }
        steps.add(zh
                ? "静态入口 " + api.method() + " " + api.route()
                + (api.entryRef().isBlank() ? "" : "（" + api.entryRef() + "）")
                + "；尚无过闸动态 PathRun，" + NO_POC_ZH + "。"
                : "Static entry " + api.method() + " " + api.route()
                + (api.entryRef().isBlank() ? "" : " (" + api.entryRef() + ")")
                + "; no pass-gate PathRun yet — " + NO_POC_EN + ".");
        if (entry != null && entry.declaringClass() != null && !entry.declaringClass().isBlank()) {
            steps.add(zh
                    ? "声明类：" + entry.declaringClass()
                    : "Declaring class: " + entry.declaringClass());
        }
        steps.add(zh
                ? "建议：在授权沙箱对同入口重放 UNAUTH / COVERAGE / FORCED 三轨并核对 PathTrace。"
                : "Next: replay UNAUTH / COVERAGE / FORCED in the authorized sandbox and inspect PathTrace.");
        return new PocBinding("STATIC_HINT", trimSteps(steps), "STATIC_INFERRED");
    }

    private static List<String> businessHops(PathTrace trace) {
        if (trace == null || trace.events() == null) return List.of();
        List<String> hops = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (TraceEvent event : trace.events()) {
            if (event == null || event.kind() != TraceEventKind.METHOD_HOP) continue;
            String subject = event.subjectRef() == null ? "" : event.subjectRef().trim();
            if (subject.isBlank()) continue;
            String lower = subject.toLowerCase(Locale.ROOT);
            if (lower.contains("javax.servlet") || lower.contains("jakarta.servlet")
                    || lower.contains("springframework.web.servlet.frameworkservlet")
                    || lower.contains("springframework.web.servlet.dispatcherservlet")) {
                continue;
            }
            if (seen.add(subject)) {
                hops.add(subject);
            }
            if (hops.size() >= MAX_HOPS_IN_POC) break;
        }
        return hops;
    }

    private static String descriptionOf(
            ApiDtos.FindingDto finding, ApiBinding api, PocBinding poc, boolean zh) {
        String title = finding.title() == null ? "" : finding.title().trim();
        String sink = finding.sink() == null ? "" : finding.sink().trim();
        String status = finding.verificationStatus() == null ? ApiDtos.STATIC_INFERRED
                : finding.verificationStatus();
        if (zh) {
            return "在接口 " + api.method() + " " + api.route()
                    + " 上发现「" + title + "」候选（状态 " + status
                    + (sink.isBlank() ? "" : "，sink=" + sink)
                    + "）。PoC 材料 provenance=" + poc.provenance()
                    + "，kind=" + poc.kind()
                    + "。FORCED/MOCK 不得写成匿名可利用或 VERIFIED。";
        }
        return "Candidate \"" + title + "\" on API " + api.method() + " " + api.route()
                + " (status " + status
                + (sink.isBlank() ? "" : ", sink=" + sink)
                + "). PoC material provenance=" + poc.provenance()
                + ", kind=" + poc.kind()
                + ". FORCED/MOCK must not be written as anonymous exploit or VERIFIED.";
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
        boolean zh = language != AiOutputLanguage.EN;
        StringBuilder block = new StringBuilder();
        if (zh) {
            block.append("FINDING_BINDINGS_FACTS（服务端从 findings×PathRun/PathTrace 装配；")
                    .append("供 PATH/REPORT 写入「漏洞相关」；不得编造 VERIFIED；")
                    .append("FORCED=INSTRUMENTATION_REACHABILITY）：\n");
        } else {
            block.append("FINDING_BINDINGS_FACTS (server-assembled from findings×PathRun/PathTrace; ")
                    .append("for PATH/REPORT Vulnerabilities section; never invent VERIFIED; ")
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
        return block.toString();
    }

    public static String renderMarkdownSection(List<Binding> bindings, AiOutputLanguage language) {
        boolean zh = language != AiOutputLanguage.EN;
        StringBuilder md = new StringBuilder();
        if (bindings == null || bindings.isEmpty()) {
            md.append(zh ? SECTION_ZH : SECTION_EN).append("\n\n");
            md.append(zh
                    ? "暂无已装配的漏洞绑定；请结合静态 findings 与 PathRun 复核。\n"
                    : "No assembled vulnerability bindings; review static findings and PathRuns.\n");
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
        md.append(zh ? SECTION_ZH : SECTION_EN).append("\n\n");
        if (primary.isEmpty()) {
            md.append(zh
                    ? "本期无高置信配合链/可达影响主漏洞；见文末「风险点」。\n\n"
                    : "No high-confidence cooperation / impact primary findings; see Risk Points below.\n\n");
        } else {
            int index = 1;
            for (Binding binding : primary) {
                appendFindingCard(md, binding, zh, true, index++);
            }
        }
        if (!risks.isEmpty()) {
            md.append(zh ? RISK_SECTION_ZH : RISK_SECTION_EN).append("\n\n");
            md.append(zh
                    ? "> 默认未授权/鉴权缺口入口，若无后续配合链且无可达 RCE 类影响证据，仅标注为风险点，不作主漏洞夸大。\n\n"
                    : "> Default unauthenticated / auth-gap endpoints without follow-on cooperation "
                    + "and without reachable RCE-class impact evidence are risk annotations only — "
                    + "not primary confirmed vulnerabilities.\n\n");
            int index = 1;
            for (Binding binding : risks) {
                appendFindingCard(md, binding, zh, false, index++);
            }
        }
        return md.toString();
    }

    private static void appendFindingCard(
            StringBuilder md, Binding binding, boolean zh, boolean primary, int index) {
        md.append(zh
                        ? (primary ? "### 漏洞 " : "### 风险点 ")
                        : (primary ? "### Finding " : "### Risk Point "))
                .append(index)
                .append(": ").append(binding.title()).append("\n\n");
        if (!primary) {
            md.append(zh ? "- **标注**: 风险点（非主漏洞）\n" : "- **Label**: risk point (not primary)\n");
        }
        md.append(zh ? "- **严重度/状态**: " : "- **Severity/Status**: ")
                .append(binding.severity()).append(" / ").append(binding.status()).append('\n');
        md.append(zh ? "- **接口**: " : "- **API**: ")
                .append(binding.api().method()).append(' ').append(binding.api().route());
        if (!binding.api().entryRef().isBlank()) {
            md.append(" (`").append(binding.api().entryRef()).append("`)");
        }
        md.append('\n');
        md.append(zh ? "- **描述**: " : "- **Description**: ")
                .append(binding.description()).append('\n');
        md.append(zh ? "- **PoC / 复现**:\n" : "- **PoC / Reproduction**:\n");
        if (binding.poc().steps().isEmpty()) {
            md.append("  1. ").append(zh ? NO_POC_ZH : NO_POC_EN).append('\n');
        } else {
            int stepNo = 1;
            for (String step : binding.poc().steps()) {
                md.append("  ").append(stepNo++).append(". ").append(step).append('\n');
            }
        }
        md.append(zh ? "- **provenance**: " : "- **provenance**: ")
                .append(binding.poc().provenance().isBlank() ? "STATIC_INFERRED" : binding.poc().provenance())
                .append(" (kind=").append(binding.poc().kind()).append(")\n");
        if (!binding.pathRunRefs().isEmpty()) {
            md.append("- pathRunRefs: `")
                    .append(String.join("`, `", binding.pathRunRefs()))
                    .append("`\n");
        }
        md.append('\n');
    }

    /**
 * 确保报告 Markdown 以 locale-pure 漏洞章节开头，由 bindings 构建。
 */
    public static EnforceResult enforceReportSection(
            String summaryMarkdown, List<Binding> bindings, AiOutputLanguage language) {
        boolean zh = language != AiOutputLanguage.EN;
        String sectionHeader = zh ? SECTION_ZH : SECTION_EN;
        String wrongHeader = zh ? SECTION_EN : SECTION_ZH;
        String body = summaryMarkdown == null ? "" : summaryMarkdown;
        String rendered = renderMarkdownSection(bindings, language);
        boolean hasSection = body.contains(sectionHeader);
        boolean hasApi = bodyContainsAnyApi(body, bindings);
        boolean hasPocMarker = zh
                ? (body.contains("PoC") || body.contains("复现") || body.contains(NO_POC_ZH))
                : (body.contains("PoC") || body.contains("Reproduction") || body.contains(NO_POC_EN));
        boolean needsRisk = bindings != null && bindings.stream()
                .anyMatch(b -> REPORT_ROLE_RISK_POINT.equals(b.reportRole()));
        String riskHeader = zh ? RISK_SECTION_ZH : RISK_SECTION_EN;
        boolean hasRiskSection = !needsRisk || body.contains(riskHeader);
        boolean mixed = body.contains(wrongHeader)
                || (zh && (body.contains("## Executive Summary") || body.contains("## Vulnerabilities")))
                || (!zh && (body.contains("## 执行摘要") || body.contains("## 漏洞相关")));
        if (hasSection && hasApi && hasPocMarker && hasRiskSection && !mixed) {
            return new EnforceResult(body, false, false);
        }
        String cleaned = stripLeadingWrongSection(body, wrongHeader);
        String merged;
        if (cleaned.regionMatches(true, skipBom(cleaned), sectionHeader, 0, sectionHeader.length())
                || cleaned.contains(sectionHeader)) {
            // 前置服务端章节并保留其余内容，替换薄弱章节。
            merged = rendered + "\n" + cleaned;
        } else {
            merged = rendered + "\n" + cleaned;
        }
        if (!merged.startsWith("#")) {
            merged = (zh ? "# 审计报告\n\n" : "# Audit Report\n\n") + merged;
        }
        return new EnforceResult(merged, true, mixed);
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
                        text(item, "reportRole")));
                if (out.size() >= MAX_BINDINGS) break;
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
        if (merged.size() > MAX_BINDINGS) {
            return List.copyOf(merged.subList(0, MAX_BINDINGS));
        }
        return List.copyOf(merged);
    }
}

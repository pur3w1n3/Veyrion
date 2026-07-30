package com.aq.jvmsentinel.analysis.hypothesis;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.worker.DynamicConfirmedGate;
import com.aq.jvmsentinel.worker.RequiredPrivilege;
import com.aq.jvmsentinel.worker.TraceProjectionService;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * 将 FORCED / COVERAGE PathRun 材料 attach 到 finding wire。
 *
 * <p>H4：当动态证据表明危险 sink 被实际触发且效果满足利用条件时，可升
 * {@code DYNAMIC_CONFIRMED} 并标注 {@code requiredPrivilege}。
 * 仅 HTTP 200 / 仅入口到达 / 仅 FORCED 改控制流但无危险 sink → 保持
 * {@code STATIC_INFERRED} / {@code DYNAMIC_SUSPECTED}（ADR-0004 修订）。
 */
public final class FindingRuntimeEnricher {
    public static final String TITLE_FORCED = "强达路径风险材料";
    public static final String TITLE_COVERAGE = "鉴权门控候选";
    public static final String TITLE_CONFIRMED = "已动态确认的漏洞";
    public static final String TITLE_SUFFIX_SIGNAL = "信号";

    private FindingRuntimeEnricher() {
    }

    public record Enrichment(
            String title,
            String verificationStatus,
            List<String> pathRunRefs,
            List<String> evidenceRefs,
            String postureProvenance,
            String postureKind,
            String requiredPrivilege,
            String requiredPrivilegeLabel
    ) {
        public Enrichment {
            title = title == null ? "" : title;
            verificationStatus = verificationStatus == null || verificationStatus.isBlank()
                    ? ApiDtos.STATIC_INFERRED : verificationStatus;
            pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            postureProvenance = postureProvenance == null ? "" : postureProvenance;
            postureKind = postureKind == null ? "" : postureKind;
            requiredPrivilege = requiredPrivilege == null ? "" : requiredPrivilege;
            requiredPrivilegeLabel = requiredPrivilegeLabel == null ? "" : requiredPrivilegeLabel;
            if ("VERIFIED".equals(verificationStatus)) {
                throw new IllegalArgumentException(
                        "FindingRuntimeEnricher must not elevate to VERIFIED");
            }
        }

        /** 兼容旧 6 字段构造。 */
        public Enrichment(
                String title,
                String verificationStatus,
                List<String> pathRunRefs,
                List<String> evidenceRefs,
                String postureProvenance,
                String postureKind) {
            this(title, verificationStatus, pathRunRefs, evidenceRefs,
                    postureProvenance, postureKind, "", "");
        }
    }

    public static Enrichment enrich(
            ApiDtos.FindingDto finding,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.PathRunDto> pathRuns,
            Map<String, PathTrace> tracesByPathRunId,
            Function<String, String> categoryLabel) {
        Objects.requireNonNull(finding, "finding");
        List<ApiDtos.EntryDto> catalog = entries == null ? List.of() : entries;
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;
        Map<String, PathTrace> traces = tracesByPathRunId == null ? Map.of() : tracesByPathRunId;

        LinkedHashSet<String> forcedRefs = new LinkedHashSet<>();
        LinkedHashSet<String> coverageRefs = new LinkedHashSet<>();
        LinkedHashSet<String> confirmedRefs = new LinkedHashSet<>();
        LinkedHashSet<String> evidence = new LinkedHashSet<>(finding.evidenceRefs());
        boolean anyForcedEntryHit = false;
        boolean anyCoverageEntryHit = false;
        ApiDtos.PathRunDto bestConfirmedRun = null;
        PathTrace bestConfirmedTrace = null;
        boolean cookieChannel = looksCookieChannel(finding);

        String property = finding.securityProperty() == null ? "" : finding.securityProperty();
        for (ApiDtos.PathRunDto run : runs) {
            PathTrace trace = traces.get(run.pathRunId());
            if (!matchesFindingEntry(finding, catalog, run, trace)) continue;
            PathRun model = TraceProjectionService.toPathRunModel(run);
            // H4：必须以 securityProperty 匹配的 EFFECT 为准；不得因 PathRun 已被空 property
            // 升为 DYNAMIC_CONFIRMED（例如全站 Shiro RememberMe 反序列化）而连带确认无关 finding。
            boolean effectConfirmed = DynamicConfirmedGate.evaluateEffect(model, trace, property)
                    == VerificationStatus.DYNAMIC_CONFIRMED;
            if (effectConfirmed) {
                confirmedRefs.add(run.pathRunId());
                evidence.addAll(run.evidenceRefs());
                if (bestConfirmedRun == null
                        || preferConfirmed(run, trace, bestConfirmedRun, bestConfirmedTrace)) {
                    bestConfirmedRun = run;
                    bestConfirmedTrace = trace;
                }
                continue;
            }
            // 与 H4 一致：PathRun.entryHit 在 5xx/超时常为 null，但 PathTrace 可有 ENTRY_HIT。
            if (!entryReached(run, trace)) continue;
            RuntimePostureKind kind = postureKindOf(run, trace);
            if (kind == RuntimePostureKind.FORCED_REACHABILITY) {
                anyForcedEntryHit = true;
                forcedRefs.add(run.pathRunId());
                evidence.addAll(run.evidenceRefs());
            } else if (kind == RuntimePostureKind.COVERAGE_POSTURE) {
                anyCoverageEntryHit = true;
                coverageRefs.add(run.pathRunId());
                evidence.addAll(run.evidenceRefs());
            }
        }

        String prior = finding.verificationStatus();
        if ("VERIFIED".equals(prior)) {
            // VERIFIED 全局关闭；降为已确认材料展示，不新开 VERIFIED。
            prior = ApiDtos.DYNAMIC_CONFIRMED;
        }

        if (bestConfirmedRun != null || ApiDtos.DYNAMIC_CONFIRMED.equals(prior)) {
            ApiDtos.PathRunDto privilegeRun = bestConfirmedRun;
            PathTrace privilegeTrace = bestConfirmedTrace;
            if (privilegeRun == null) {
                for (ApiDtos.PathRunDto run : runs) {
                    PathTrace trace = traces.get(run.pathRunId());
                    if (ApiDtos.DYNAMIC_CONFIRMED.equals(run.verificationStatus())
                            && matchesFindingEntry(finding, catalog, run, trace)
                            && DynamicConfirmedGate.evaluateEffect(
                            TraceProjectionService.toPathRunModel(run), trace, property)
                            == VerificationStatus.DYNAMIC_CONFIRMED) {
                        privilegeRun = run;
                        privilegeTrace = trace;
                        confirmedRefs.add(run.pathRunId());
                        break;
                    }
                }
            }
            String privilegeCode = privilegeRun == null
                    ? RequiredPrivilege.UNKNOWN
                    : RequiredPrivilege.codeFor(
                            TraceProjectionService.toPathRunModel(privilegeRun),
                            privilegeTrace, cookieChannel);
            String title = rewriteTitle(finding, TITLE_CONFIRMED, categoryLabel);
            return new Enrichment(
                    title,
                    ApiDtos.DYNAMIC_CONFIRMED,
                    List.copyOf(confirmedRefs.isEmpty() && privilegeRun != null
                            ? List.of(privilegeRun.pathRunId()) : confirmedRefs),
                    List.copyOf(evidence),
                    privilegeTrace != null && privilegeTrace.posture() != null
                            ? privilegeTrace.posture().postureProvenance() : "",
                    privilegeTrace != null && privilegeTrace.posture() != null
                            ? privilegeTrace.posture().postureKind().name() : "",
                    privilegeCode,
                    RequiredPrivilege.humanLabel(privilegeCode, true));
        }

        if (anyForcedEntryHit) {
            String title = rewriteTitle(finding, TITLE_FORCED, categoryLabel);
            return new Enrichment(
                    title,
                    ApiDtos.STATIC_INFERRED,
                    List.copyOf(forcedRefs),
                    List.copyOf(evidence),
                    RuntimePosture.PROVENANCE_INSTRUMENTATION,
                    RuntimePostureKind.FORCED_REACHABILITY.name(),
                    "",
                    "");
        }
        if (anyCoverageEntryHit) {
            String title = rewriteTitle(finding, TITLE_COVERAGE, categoryLabel);
            return new Enrichment(
                    title,
                    ApiDtos.STATIC_INFERRED,
                    List.copyOf(coverageRefs),
                    List.copyOf(evidence),
                    RuntimePosture.PROVENANCE_SCAN_AUTH,
                    RuntimePostureKind.COVERAGE_POSTURE.name(),
                    "",
                    "");
        }
        return new Enrichment(
                finding.title(),
                prior == null || prior.isBlank() ? ApiDtos.STATIC_INFERRED : prior,
                List.of(),
                finding.evidenceRefs(),
                "",
                "",
                "",
                "");
    }

    public static Map<String, Object> applyToWire(
            Map<String, Object> base, Enrichment enrichment) {
        Map<String, Object> wire = new LinkedHashMap<>(base == null ? Map.of() : base);
        if (enrichment == null) return wire;
        if (!enrichment.title().isBlank()) {
            wire.put("title", enrichment.title());
        }
        wire.put("verificationStatus", enrichment.verificationStatus());
        wire.put("status", enrichment.verificationStatus());
        if (!enrichment.pathRunRefs().isEmpty()) {
            wire.put("pathRunRefs", enrichment.pathRunRefs());
        }
        if (!enrichment.evidenceRefs().isEmpty()) {
            wire.put("evidenceRefs", enrichment.evidenceRefs());
            wire.put("evidenceCount", enrichment.evidenceRefs().size());
            wire.put("evidence", enrichment.evidenceRefs().size());
        }
        if (!enrichment.postureProvenance().isBlank()) {
            wire.put("postureProvenance", enrichment.postureProvenance());
        }
        if (!enrichment.postureKind().isBlank()) {
            wire.put("postureKind", enrichment.postureKind());
        }
        if (!enrichment.requiredPrivilege().isBlank()) {
            wire.put("requiredPrivilege", enrichment.requiredPrivilege());
            wire.put("requiredPrivilegeLabel", enrichment.requiredPrivilegeLabel());
            wire.put("authContext", enrichment.requiredPrivilegeLabel());
        }
        return wire;
    }

    /**
     * 入口是否到达：显式 {@code entryHit=true}，或 {@code entryHit} 未知但 PathTrace
     * 含 {@code ENTRY_HIT}（5xx / DEPENDENCY_MOCK_GAP 常见）。{@code entryHit=false} 仍拒绝。
     */
    public static boolean entryReached(ApiDtos.PathRunDto run, PathTrace trace) {
        if (run == null) return false;
        if (Boolean.FALSE.equals(run.entryHit())) return false;
        if (Boolean.TRUE.equals(run.entryHit())) return true;
        if (trace == null || trace.events() == null) return false;
        return trace.events().stream()
                .anyMatch(e -> e != null && e.kind() == TraceEventKind.ENTRY_HIT);
    }

    public static boolean matchesFindingEntry(
            ApiDtos.FindingDto finding,
            List<ApiDtos.EntryDto> entries,
            ApiDtos.PathRunDto run) {
        return matchesFindingEntry(finding, entries, run, null);
    }

    public static boolean matchesFindingEntry(
            ApiDtos.FindingDto finding,
            List<ApiDtos.EntryDto> entries,
            ApiDtos.PathRunDto run,
            PathTrace trace) {
        if (finding == null || run == null) return false;
        String entryId = finding.entrypointId() == null ? "" : finding.entrypointId().trim();
        String route = finding.entry() == null ? "" : finding.entry().trim();
        if (!entryId.isBlank() && !"entry-unbound".equals(entryId) && !"UNBOUND".equals(entryId)) {
            if (EntryRefResolver.refsEquivalent(entries, "entry:" + entryId, run.entrypointRef())) {
                return true;
            }
            if (EntryRefResolver.refsEquivalent(entries, entryId, run.entrypointRef())) {
                return true;
            }
        }
        if (!route.isBlank() && !"UNBOUND".equals(route)
                && !route.toLowerCase(Locale.ROOT).contains("alias=")
                && !route.contains("BOOT-INF/")) {
            String runRef = run.entrypointRef() == null ? "" : run.entrypointRef();
            if (runRef.contains(route)) return true;
            String method = run.method() == null ? "GET" : run.method();
            if (EntryRefResolver.refsEquivalent(
                    entries, "entry:" + method + ":" + route, run.entrypointRef())) {
                return true;
            }
        }
        String property = finding.securityProperty() == null ? "" : finding.securityProperty();
        if (property.contains("REMEMBER_ME") || property.contains("UNSAFE_DESER")) {
            String summary = run.requestSummary() == null ? "" : run.requestSummary().toLowerCase(Locale.ROOT);
            if (summary.contains("rememberme") || summary.contains("cookie")) {
                return true;
            }
            return traceLooksLikeRememberMe(trace);
        }
        if (property.contains("DESERIAL")) {
            // 通用反序列化 finding：要求 effect 主体与 sink 有交集，避免 Shiro 全站噪声冒充 fastjson 等。
            return deserialEffectOverlapsSink(finding, trace);
        }
        return false;
    }

    private static boolean traceLooksLikeRememberMe(PathTrace trace) {
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

    private static boolean deserialEffectOverlapsSink(ApiDtos.FindingDto finding, PathTrace trace) {
        if (trace == null) return false;
        String sink = finding.sink() == null ? "" : finding.sink().toLowerCase(Locale.ROOT);
        if (sink.isBlank()) return false;
        // effectRefs：EFFECT:DESERIALIZATION + targetClass#method（投影后）
        if (trace.effectRefs() != null) {
            for (String ref : trace.effectRefs()) {
                if (ref == null) continue;
                String lower = ref.toLowerCase(Locale.ROOT);
                if (!(lower.contains("deserial") || lower.startsWith("effect:deserial")
                        || lower.contains("parseobject") || lower.contains("readobject")
                        || lower.contains("objectinput"))) {
                    continue;
                }
                if (sinkSymbolOverlaps(sink, lower)) {
                    return true;
                }
            }
        }
        // TraceEvent.attributes.targetClass：即使 effectRefs 仅有 kind 也能反推
        if (trace.events() != null) {
            for (var event : trace.events()) {
                if (event == null || event.kind() != com.aq.jvmsentinel.domain.pathdebug.TraceEventKind.EFFECT_TRIGGERED) {
                    continue;
                }
                Map<String, Object> attrs = event.attributes();
                String target = attrs == null ? "" : String.valueOf(attrs.getOrDefault("targetClass", ""));
                String kind = attrs == null ? "" : String.valueOf(attrs.getOrDefault("effectKind", ""));
                String blob = (target + " " + event.subjectRef() + " " + kind).toLowerCase(Locale.ROOT);
                if (!(blob.contains("deserial") || blob.contains("objectinput")
                        || blob.contains("readobject") || blob.contains("parseobject"))) {
                    continue;
                }
                if (sinkSymbolOverlaps(sink, blob)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** finding.sink 与运行时 sink 符号（owner/leaf）是否有交集。 */
    public static boolean sinkSymbolOverlaps(String sinkLower, String runtimeSymbolLower) {
        if (sinkLower == null || sinkLower.isBlank()
                || runtimeSymbolLower == null || runtimeSymbolLower.isBlank()) {
            return false;
        }
        String simple = runtimeSymbolLower;
        int hash = simple.indexOf('#');
        if (hash > 0) simple = simple.substring(0, hash);
        int slash = Math.max(simple.lastIndexOf('.'), simple.lastIndexOf('/'));
        String leaf = slash >= 0 ? simple.substring(slash + 1) : simple;
        if (!leaf.isBlank() && !"effect".equals(leaf) && sinkLower.contains(leaf)) {
            return true;
        }
        if (runtimeSymbolLower.contains("fastjson") && sinkLower.contains("fastjson")) return true;
        if (runtimeSymbolLower.contains("objectinput") && sinkLower.contains("objectinput")) return true;
        if (runtimeSymbolLower.contains("multipartfile") && sinkLower.contains("multipartfile")) {
            return true;
        }
        if (runtimeSymbolLower.contains("fileoutputstream") && sinkLower.contains("fileoutputstream")) {
            return true;
        }
        return false;
    }

    private static boolean preferConfirmed(
            ApiDtos.PathRunDto candidate, PathTrace candidateTrace,
            ApiDtos.PathRunDto incumbent, PathTrace incumbentTrace) {
        if (incumbent == null) return true;
        int cEffects = candidateTrace == null ? 0 : candidateTrace.effectRefs().size();
        int iEffects = incumbentTrace == null ? 0 : incumbentTrace.effectRefs().size();
        if (cEffects != iEffects) return cEffects > iEffects;
        return candidate.httpStatus() >= incumbent.httpStatus();
    }

    private static boolean looksCookieChannel(ApiDtos.FindingDto finding) {
        if (finding == null) return false;
        String blob = (finding.securityProperty() == null ? "" : finding.securityProperty())
                + " " + (finding.title() == null ? "" : finding.title())
                + " " + (finding.sink() == null ? "" : finding.sink());
        String lower = blob.toLowerCase(Locale.ROOT);
        return lower.contains("remember") || lower.contains("cookie")
                || lower.contains("deserial") || lower.contains("shiro");
    }

    private static RuntimePostureKind postureKindOf(ApiDtos.PathRunDto run, PathTrace trace) {
        if (trace != null && trace.posture() != null) {
            return trace.posture().postureKind();
        }
        String planId = run.experimentPlanId() == null ? "" : run.experimentPlanId().toLowerCase(Locale.ROOT);
        if (planId.contains("forced_reachability") || planId.contains(":forced")) {
            return RuntimePostureKind.FORCED_REACHABILITY;
        }
        if (planId.contains("coverage_posture") || planId.contains(":coverage")) {
            return RuntimePostureKind.COVERAGE_POSTURE;
        }
        return RuntimePostureKind.UNAUTH;
    }

    private static String rewriteTitle(
            ApiDtos.FindingDto finding,
            String materialLabel,
            Function<String, String> categoryLabel) {
        String property = finding.securityProperty() == null ? "" : finding.securityProperty().trim();
        String label = "";
        if (categoryLabel != null && !property.isBlank()) {
            label = categoryLabel.apply(property);
        }
        if (label == null || label.isBlank()) {
            label = property.isBlank() ? "" : property;
        }
        if (label.isBlank()) {
            String prior = finding.title() == null ? "" : finding.title().trim();
            if (prior.startsWith("静态推断的") && prior.endsWith(TITLE_SUFFIX_SIGNAL)) {
                label = prior.substring("静态推断的".length(), prior.length() - TITLE_SUFFIX_SIGNAL.length());
            }
        }
        if (label == null || label.isBlank()) {
            return materialLabel;
        }
        return materialLabel + "·" + label;
    }

    /** Test helper: collect forced ENTRY_HIT pathRun ids for an entry/route. */
    public static List<String> forcedEntryHitRefs(
            ApiDtos.FindingDto finding,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.PathRunDto> pathRuns,
            Map<String, PathTrace> tracesByPathRunId) {
        Enrichment enrichment = enrich(finding, entries, pathRuns, tracesByPathRunId, ignored -> "");
        return new ArrayList<>(enrichment.pathRunRefs());
    }
}

package com.aq.jvmsentinel.analysis.hypothesis;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * 将 FORCED / COVERAGE PathRun 材料 attach 到 finding wire，不提升
 * {@code VERIFIED} / {@code DYNAMIC_CONFIRMED} (ADR-0004 / PROJECT_MEMORY §2.2).
 */
public final class FindingRuntimeEnricher {
    public static final String TITLE_FORCED = "强达路径风险材料";
    public static final String TITLE_COVERAGE = "鉴权门控候选";
    public static final String TITLE_SUFFIX_SIGNAL = "信号";

    private FindingRuntimeEnricher() {
    }

    public record Enrichment(
            String title,
            String verificationStatus,
            List<String> pathRunRefs,
            List<String> evidenceRefs,
            String postureProvenance,
            String postureKind
    ) {
        public Enrichment {
            title = title == null ? "" : title;
            verificationStatus = verificationStatus == null || verificationStatus.isBlank()
                    ? ApiDtos.STATIC_INFERRED : verificationStatus;
            pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            postureProvenance = postureProvenance == null ? "" : postureProvenance;
            postureKind = postureKind == null ? "" : postureKind;
            if (ApiDtos.DYNAMIC_CONFIRMED.equals(verificationStatus)
                    || "VERIFIED".equals(verificationStatus)) {
                throw new IllegalArgumentException(
                        "FindingRuntimeEnricher must not elevate to " + verificationStatus);
            }
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
        LinkedHashSet<String> evidence = new LinkedHashSet<>(finding.evidenceRefs());
        boolean anyForcedEntryHit = false;
        boolean anyCoverageEntryHit = false;

        for (ApiDtos.PathRunDto run : runs) {
            if (!matchesFindingEntry(finding, catalog, run)) continue;
            if (!Boolean.TRUE.equals(run.entryHit())) continue;
            PathTrace trace = traces.get(run.pathRunId());
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

        String status = finding.verificationStatus();
        if (ApiDtos.DYNAMIC_CONFIRMED.equals(status) || "VERIFIED".equals(status)) {
            // 保留先前服务端 gate 提升；enricher 永不升级进入。
            return new Enrichment(
                    finding.title(), status, List.of(), finding.evidenceRefs(), "", "");
        }

        if (anyForcedEntryHit) {
            String title = rewriteTitle(finding, TITLE_FORCED, categoryLabel);
            return new Enrichment(
                    title,
                    ApiDtos.STATIC_INFERRED,
                    List.copyOf(forcedRefs),
                    List.copyOf(evidence),
                    RuntimePosture.PROVENANCE_INSTRUMENTATION,
                    RuntimePostureKind.FORCED_REACHABILITY.name());
        }
        if (anyCoverageEntryHit) {
            String title = rewriteTitle(finding, TITLE_COVERAGE, categoryLabel);
            return new Enrichment(
                    title,
                    ApiDtos.STATIC_INFERRED,
                    List.copyOf(coverageRefs),
                    List.copyOf(evidence),
                    RuntimePosture.PROVENANCE_SCAN_AUTH,
                    RuntimePostureKind.COVERAGE_POSTURE.name());
        }
        return new Enrichment(
                finding.title(),
                status == null || status.isBlank() ? ApiDtos.STATIC_INFERRED : status,
                List.of(),
                finding.evidenceRefs(),
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
        return wire;
    }

    static boolean matchesFindingEntry(
            ApiDtos.FindingDto finding,
            List<ApiDtos.EntryDto> entries,
            ApiDtos.PathRunDto run) {
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
        if (!route.isBlank() && !"UNBOUND".equals(route)) {
            String runRef = run.entrypointRef() == null ? "" : run.entrypointRef();
            if (runRef.contains(route)) return true;
            String method = run.method() == null ? "GET" : run.method();
            if (EntryRefResolver.refsEquivalent(
                    entries, "entry:" + method + ":" + route, run.entrypointRef())) {
                return true;
            }
        }
        return false;
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
        // 仅 ADMIN track 歧义（COVERAGE 与 FORCED 共享）— 要求 plan/trace。
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
            // 回退：存在时剥离 legacy「静态推断的…信号」wrapper。
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

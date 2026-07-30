package com.aq.jvmsentinel.analysis.hypothesis;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;

import java.util.List;
import java.util.Map;

/**
 * 验收：FORCED ENTRY_HIT enrich finding wire title/pathRunRef，不提升 VERIFIED。
 */
public final class FindingRuntimeEnricherAcceptanceTest {
    public static void main(String[] args) {
        forcedEntryHitEnrichesWithoutVerified();
        coverageTitleWithoutForced();
        noMatchKeepsStaticTitle();
        System.out.println("FindingRuntimeEnricherAcceptanceTest: PASS");
    }

    private static void forcedEntryHitEnrichesWithoutVerified() {
        List<ApiDtos.EntryDto> entries = List.of(entry("entry-ann-42", "POST", "/ueditor/upload"));
        ApiDtos.FindingDto finding = finding(
                "finding-1", "静态推断的文件路径穿越信号", "entry-ann-42", "/ueditor/upload",
                "PATH_TRAVERSAL");
        ApiDtos.PathRunDto run = pathRun(
                "pr-forced", "entry:POST:/ueditor/upload", true,
                "plan:posture:forced_reachability:entry-ann-42");
        PathTrace trace = forcedTrace("pr-forced", "entry:entry-ann-42");
        FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                finding, entries, List.of(run), Map.of("pr-forced", trace),
                category -> "文件路径穿越");
        check(enrichment.title().contains(FindingRuntimeEnricher.TITLE_FORCED),
                "title becomes 强达路径风险材料");
        check(!enrichment.title().startsWith("静态推断的"), "legacy static title replaced");
        check(ApiDtos.STATIC_INFERRED.equals(enrichment.verificationStatus()),
                "verificationStatus remains STATIC_INFERRED");
        check(!"VERIFIED".equals(enrichment.verificationStatus())
                        && !ApiDtos.DYNAMIC_CONFIRMED.equals(enrichment.verificationStatus()),
                "FORCED must not elevate VERIFIED/DYNAMIC_CONFIRMED");
        check(enrichment.pathRunRefs().contains("pr-forced"), "pathRunRefs attached");
        check(RuntimePosture.PROVENANCE_INSTRUMENTATION.equals(enrichment.postureProvenance()),
                "postureProvenance=INSTRUMENTATION_REACHABILITY");
        Map<String, Object> wire = FindingRuntimeEnricher.applyToWire(
                Map.of("title", finding.title(), "verificationStatus", finding.verificationStatus()),
                enrichment);
        check(wire.get("title").toString().contains(FindingRuntimeEnricher.TITLE_FORCED),
                "wire title enriched");
        check(ApiDtos.STATIC_INFERRED.equals(wire.get("verificationStatus")),
                "wire status STATIC_INFERRED");
    }

    private static void coverageTitleWithoutForced() {
        List<ApiDtos.EntryDto> entries = List.of(entry("entry-ann-9", "GET", "/admin/page"));
        ApiDtos.FindingDto finding = finding(
                "finding-2", "静态推断的鉴权缺口信号", "entry-ann-9", "/admin/page", "AUTH_GAP");
        ApiDtos.PathRunDto run = pathRun(
                "pr-cov", "entry:GET:/admin/page", true,
                "plan:posture:coverage_posture:entry-ann-9");
        PathTrace trace = coverageTrace("pr-cov", "entry:entry-ann-9");
        FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                finding, entries, List.of(run), Map.of("pr-cov", trace),
                category -> "鉴权缺口");
        check(enrichment.title().contains(FindingRuntimeEnricher.TITLE_COVERAGE),
                "coverage title 鉴权门控候选");
        check(ApiDtos.STATIC_INFERRED.equals(enrichment.verificationStatus()),
                "coverage keeps STATIC_INFERRED");
        check(RuntimePosture.PROVENANCE_SCAN_AUTH.equals(enrichment.postureProvenance()),
                "SCAN_AUTH_POSTURE provenance");
    }

    private static void noMatchKeepsStaticTitle() {
        ApiDtos.FindingDto finding = finding(
                "finding-3", "静态推断的 SQL 注入信号", "entry-ann-1", "/other", "SQL");
        FindingRuntimeEnricher.Enrichment enrichment = FindingRuntimeEnricher.enrich(
                finding, List.of(), List.of(), Map.of(), category -> "SQL 注入");
        check("静态推断的 SQL 注入信号".equals(enrichment.title()), "unchanged without PathRuns");
        check(enrichment.pathRunRefs().isEmpty(), "no pathRunRefs");
    }

    private static ApiDtos.EntryDto entry(String id, String method, String route) {
        return new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, "p", "d", "scan-a",
                id, "HTTP", method, route, "demo.C", "C",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
    }

    private static ApiDtos.FindingDto finding(
            String id, String title, String entryId, String route, String property) {
        return new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "scan-a", id, title, "high",
                ApiDtos.STATIC_INFERRED, entryId, route, "sink-1", "sink", "none",
                List.of("none"), List.of("ev-1"), 1, 0.7, ApiDtos.MOCK, null,
                "hyp-1", property);
    }

    private static ApiDtos.PathRunDto pathRun(
            String id, String entryRef, boolean entryHit, String planId) {
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, id, "scan-a", entryRef, "ADMIN", "attempt-1",
                planId, "POST", "application/json", "summary", "HTTP_OBSERVED", 200,
                entryHit, true, List.of(), "STOP", ApiDtos.DYNAMIC_SUSPECTED,
                List.of("ev-" + id), "MOCK", "");
    }

    private static PathTrace forcedTrace(String pathRunId, String entryRef) {
        return new PathTrace(
                PathTrace.SCHEMA_VERSION,
                "pathtrace:" + pathRunId,
                pathRunId,
                "probe-1",
                "plan:posture:forced_reachability:entry",
                "traceplan-1",
                entryRef,
                "ADMIN",
                RuntimePosture.forced(List.of("GUARD:AUTH:LoginFilter")),
                "world-1",
                "corr-1",
                1,
                List.of(),
                List.of(),
                TraceExitReason.COMPLETED,
                "Controller#handler",
                List.of(),
                false);
    }

    private static PathTrace coverageTrace(String pathRunId, String entryRef) {
        return new PathTrace(
                PathTrace.SCHEMA_VERSION,
                "pathtrace:" + pathRunId,
                pathRunId,
                "probe-1",
                "plan:posture:coverage_posture:entry",
                "traceplan-1",
                entryRef,
                "ADMIN",
                RuntimePosture.coverage(),
                "world-1",
                "corr-1",
                1,
                List.of(),
                List.of(),
                TraceExitReason.COMPLETED,
                "Controller#handler",
                List.of(),
                false);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.List;

/**
 * 验收：static {@code entry:entry-ann-*} 行 join 键为
 * {@code entry:METHOD:/route} (scan-ee80407e1f95449d join gap).
 */
public final class EntryAnnMethodRouteJoinAcceptanceTest {
    public static void main(String[] args) {
        joinKeysAliasAnnAndMethodRoute();
        contrastJoinAnnIdToMethodRoutePathRun();
        contrastJoinStillStaticOnlyOn401();
        System.out.println("EntryAnnMethodRouteJoinAcceptanceTest: PASS");
    }

    private static void joinKeysAliasAnnAndMethodRoute() {
        List<ApiDtos.EntryDto> entries = List.of(entry("entry-ann-42", "POST", "/ueditor/upload"));
        List<String> fromAnn = EntryRefResolver.joinKeys(entries, "entry:entry-ann-42");
        List<String> fromRoute = EntryRefResolver.joinKeys(entries, "entry:POST:/ueditor/upload");
        check(fromAnn.contains("entry:entry-ann-42"), "ann key present");
        check(fromAnn.contains("entry:POST:/ueditor/upload"), "METHOD:route alias from ann");
        check(fromRoute.contains("entry:entry-ann-42"), "canonical from METHOD:route");
        check(EntryRefResolver.refsEquivalent(
                        entries, "entry:entry-ann-42", "entry:POST:/ueditor/upload"),
                "refsEquivalent ann ↔ METHOD:route");
    }

    private static void contrastJoinAnnIdToMethodRoutePathRun() {
        List<ApiDtos.EntryDto> entries = List.of(entry("entry-ann-42", "POST", "/ueditor/upload"));
        StaticContrastRow staticRow = new StaticContrastRow(
                "contrast-1", "sink-1", "FILE", "FileUpload#write",
                List.of("entry:entry-ann-42"), "taint-1", "", ContrastStatus.UNKNOWN,
                List.of(), StaticContrastProjector.STOP_TAINT_PROJECTED, false);
        ApiDtos.PathRunDto forcedOk = pathRun(
                "pr-forced-200", "entry:POST:/ueditor/upload", "ADMIN",
                "HTTP_OBSERVED", 200, true, true);
        StaticDynamicContraster.Result result = new StaticDynamicContraster()
                .join(List.of(staticRow), List.of(forcedOk), List.of(), "snap-1", 1, entries);
        check(result.rows().size() == 1, "one joined row");
        StaticContrastRow joined = result.rows().get(0);
        check(joined.contrastStatus() == ContrastStatus.MATCHED
                        || joined.contrastStatus() == ContrastStatus.PARTIAL,
                "pass-gate PathRun joins ann-id row (not STATIC_ONLY/NO_PATHRUN)");
        check(!StaticDynamicContraster.STOP_NO_PATHRUN.equals(joined.stopReason()),
                "stopReason is not NO_PATHRUN_FOR_ENTRY");
        check(joined.pathRunRefs().contains("pr-forced-200"), "pathRunRefs attached");
        check(result.staticOnlyCount() == 0, "not broadly STATIC_ONLY when METHOD:route exists");
    }

    private static void contrastJoinStillStaticOnlyOn401() {
        List<ApiDtos.EntryDto> entries = List.of(entry("entry-ann-7", "GET", "/admin"));
        StaticContrastRow staticRow = new StaticContrastRow(
                "contrast-2", "sink-2", "AUTH_GAP", "Admin#page",
                List.of("entry:entry-ann-7"), "", "", ContrastStatus.UNKNOWN,
                List.of(), "SINK_WITHOUT_TAINT_PATH", false);
        ApiDtos.PathRunDto challenge = pathRun(
                "pr-401", "entry:GET:/admin", "UNAUTH", "AUTH_CHALLENGE", 401, false, false);
        StaticDynamicContraster.Result result = new StaticDynamicContraster()
                .join(List.of(staticRow), List.of(challenge), List.of(), "snap-1", 1, entries);
        check(result.rows().get(0).contrastStatus() == ContrastStatus.STATIC_ONLY,
                "401 still STATIC_ONLY after alias join");
    }

    private static ApiDtos.EntryDto entry(String id, String method, String route) {
        return new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, "project-a", "digest-a", "scan-a",
                id, "HTTP", method, route, "demo.Controller", "Controller",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
    }

    private static ApiDtos.PathRunDto pathRun(
            String id, String entryRef, String track, String outcome, int httpStatus,
            Boolean entryHit, Boolean parameterBound) {
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, id, "scan-1", entryRef, track, "attempt-1",
                "plan:posture:forced_reachability:entry-ann-42", "POST", "application/json",
                "summary", outcome, httpStatus,
                entryHit, parameterBound, List.of(), "STOP", ApiDtos.DYNAMIC_SUSPECTED,
                List.of("ev-" + id), "MOCK", "");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.List;

/**
 * Acceptance: 401-only PathRuns keep static rows as STATIC_ONLY (never bypassed).
 */
public final class StaticDynamicContrasterAcceptanceTest {
    public static void main(String[] args) {
        staticOnlyOnAuthChallenge();
        matchedOnPassGate();
        dynamicOnlyUnmatchedPathRun();
        claimsBypassGuard();
        System.out.println("StaticDynamicContrasterAcceptanceTest: PASS");
    }

    private static void staticOnlyOnAuthChallenge() {
        StaticContrastRow staticRow = new StaticContrastRow(
                "contrast-1", "sink-1", "COMMAND", "Runtime#exec",
                List.of("entry:entry-ann-1"), "taint-1", "", ContrastStatus.UNKNOWN,
                List.of(), StaticContrastProjector.STOP_TAINT_PROJECTED, false);
        ApiDtos.PathRunDto challenge = pathRun(
                "pr-401", "entry:entry-ann-1", "UNAUTH", "AUTH_CHALLENGE", 401,
                false, false);
        StaticDynamicContraster.Result result = new StaticDynamicContraster()
                .join(List.of(staticRow), List.of(challenge));
        check(result.rows().size() == 1, "one joined row");
        StaticContrastRow joined = result.rows().get(0);
        check(joined.contrastStatus() == ContrastStatus.STATIC_ONLY,
                "401/AUTH_CHALLENGE → STATIC_ONLY");
        check(StaticDynamicContraster.STOP_AUTH_CHALLENGE_ONLY.equals(joined.stopReason()),
                "stopReason PATHRUN_AUTH_CHALLENGE_ONLY");
        check(joined.pathRunRefs().contains("pr-401"), "pathRunRefs retained");
        check(result.staticOnlyCount() == 1, "staticOnlyCount=1");
        check(result.matchedCount() == 0, "never MATCHED on 401-only");
    }

    private static void matchedOnPassGate() {
        StaticContrastRow staticRow = new StaticContrastRow(
                "contrast-2", "sink-2", "SQL", "Statement#execute",
                List.of("entry:e2"), "taint-2", "", ContrastStatus.UNKNOWN,
                List.of(), StaticContrastProjector.STOP_TAINT_PROJECTED, false);
        ApiDtos.PathRunDto ok = pathRun(
                "pr-200", "entry:e2", "ADMIN", "HTTP_OBSERVED", 200, true, true);
        StaticDynamicContraster.Result result = new StaticDynamicContraster()
                .join(List.of(staticRow), List.of(ok));
        check(result.rows().get(0).contrastStatus() == ContrastStatus.MATCHED,
                "2xx + entryHit → MATCHED");
        check(result.matchedCount() == 1, "matchedCount=1");
    }

    private static void dynamicOnlyUnmatchedPathRun() {
        ApiDtos.PathRunDto orphan = pathRun(
                "pr-orphan", "entry:other", "USER", "HTTP_OBSERVED", 200, true, true);
        StaticDynamicContraster.Result result = new StaticDynamicContraster()
                .join(List.of(), List.of(orphan));
        check(result.dynamicOnlyCount() == 1, "unmatched PathRun → DYNAMIC_ONLY");
        check(result.rows().get(0).contrastStatus() == ContrastStatus.DYNAMIC_ONLY,
                "status DYNAMIC_ONLY");
    }

    private static void claimsBypassGuard() {
        check(StaticDynamicContraster.claimsBypassConfirmed(
                        "STATIC_ONLY row already 已绕过 on 401 AUTH_CHALLENGE"),
                "detects STATIC_ONLY narrated as bypassed");
        check(!StaticDynamicContraster.claimsBypassConfirmed(
                        "MATCHED PathRun shows HTTP 200 without claiming bypass"),
                "non-bypass narrative allowed");
    }

    private static ApiDtos.PathRunDto pathRun(
            String id, String entryRef, String track, String outcome, int httpStatus,
            Boolean entryHit, Boolean parameterBound) {
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, id, "scan-1", entryRef, track, "attempt-1",
                "", "GET", "application/json", "summary", outcome, httpStatus,
                entryHit, parameterBound, List.of(), "STOP", ApiDtos.DYNAMIC_SUSPECTED,
                List.of(), "MOCK", "");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

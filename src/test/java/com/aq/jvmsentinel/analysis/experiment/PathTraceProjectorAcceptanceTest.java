package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.domain.pathdebug.PathRunPathDebugView;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 说明：P0-21：PathTraceProjector 验收。
 */
public final class PathTraceProjectorAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        effectThenDbUnavailable();
        dbMissingTableDataGap();
        traceTruncatedRecorded();
        authPostureRequirements();
        legacyPathRunIncomplete();
        System.out.println("PathTraceProjectorAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static PathTraceProjector.ProjectionInput baseInput(RuntimePosture posture) {
        return new PathTraceProjector.ProjectionInput(
                "pathtrace:fixture",
                "pathrun:fixture",
                "probe:fixture",
                "plan:fixture",
                "traceplan:fixture",
                "entry:code",
                posture.identityTrackWire(),
                posture,
                "worldpack:fixture",
                "corr:fixture",
                1,
                List.of(),
                List.of(),
                256,
                "");
    }

    private static void effectThenDbUnavailable() {
        PathTrace trace = PathTraceProjector.projectCodeQueryDbUnavailable(
                baseInput(RuntimePosture.coverage()));
        check(trace.hasEffectBeforeExit(), "GET /code?code=x keeps effect before exit");
        check(!trace.effectRefs().isEmpty(), "effectRefs preserved after DEPENDENCY_FAILURE");
        check(trace.exitReason() == TraceExitReason.DEPENDENCY_UNAVAILABLE,
                "DB unavailable → DEPENDENCY_UNAVAILABLE");
        check(trace.events().stream().anyMatch(e -> e.kind() == TraceEventKind.EFFECT_TRIGGERED),
                "EFFECT_TRIGGERED event present");
        check(trace.events().stream().anyMatch(e -> e.kind() == TraceEventKind.DEPENDENCY_FAILURE),
                "DEPENDENCY_FAILURE event present");
    }

    private static void dbMissingTableDataGap() {
        List<PathTraceProjector.EventSummary> summaries = List.of(
                new PathTraceProjector.EventSummary(
                        TraceEventKind.ENTRY_HIT, "GET /users", "entry:users", "", false, List.of()),
                new PathTraceProjector.EventSummary(
                        TraceEventKind.EFFECT_TRIGGERED, "SQL query", "UserRepository#find",
                        "EFFECT:SQL", false, List.of("EFFECT:SQL")),
                new PathTraceProjector.EventSummary(
                        TraceEventKind.DEPENDENCY_FAILURE, "Table 'users' doesn't exist",
                        "JdbcTemplate#query", "", false, List.of()));
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:data-gap",
                "pathrun:data-gap",
                "probe:data-gap",
                "plan:data-gap",
                "traceplan:data-gap",
                "entry:users",
                "ADMIN",
                RuntimePosture.coverage(),
                "worldpack:observe",
                "corr:data-gap",
                1,
                summaries,
                List.of(),
                256,
                ""));
        check(!trace.effectRefs().isEmpty(), "effect kept on data gap");
        check(trace.exitReason() == TraceExitReason.DEPENDENCY_DATA_GAP,
                "missing table → DEPENDENCY_DATA_GAP");
    }

    private static void traceTruncatedRecorded() {
        List<PathTraceProjector.EventSummary> many = new java.util.ArrayList<>();
        for (int i = 0; i < 10; i++) {
            many.add(new PathTraceProjector.EventSummary(
                    TraceEventKind.METHOD_HOP, "hop-" + i, "Service#m" + i, "", false, List.of()));
        }
        PathTrace trace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:trunc",
                "pathrun:trunc",
                "probe:trunc",
                "plan:trunc",
                "traceplan:trunc",
                "entry:trunc",
                "UNAUTH",
                RuntimePosture.unauth(),
                "worldpack:trunc",
                "corr:trunc",
                1,
                many,
                List.of(),
                3,
                ""));
        check(trace.exitReason() == TraceExitReason.TRACE_TRUNCATED, "TRACE_TRUNCATED recorded");
        check(trace.events().stream().anyMatch(e -> e.kind() == TraceEventKind.TRACE_TRUNCATED),
                "TRACE_TRUNCATED event emitted");
    }

    private static void authPostureRequirements() {
        PathTrace unauthTrace = PathTraceProjector.project(new PathTraceProjector.ProjectionInput(
                "pathtrace:unauth",
                "pathrun:unauth",
                "probe:unauth",
                "plan:unauth",
                "traceplan:unauth",
                "entry:secure",
                "UNAUTH",
                RuntimePosture.unauth(),
                "worldpack:unauth",
                "corr:unauth",
                1,
                List.of(new PathTraceProjector.EventSummary(
                        TraceEventKind.GUARD_DECISION, "401", "AuthFilter",
                        "AUTH_CHALLENGE", false, List.of())),
                List.of(),
                256,
                ""));
        check(unauthTrace.exitReason() == TraceExitReason.AUTH_CHALLENGE, "UNAUTH 401 auth challenge");
        check("AUTH_REQUIRED".equals(PathTraceProjector.authRequirementFor(unauthTrace, 401)),
                "UNAUTH authRequirement");

        PathTrace coverageTrace = PathTraceProjector.projectCodeQueryDbUnavailable(
                baseInput(RuntimePosture.coverage()));
        check("SCAN_AUTH_POSTURE".equals(PathTraceProjector.authRequirementFor(coverageTrace, 200)),
                "COVERAGE authRequirement");

        PathTrace forcedTrace = PathTraceProjector.projectCodeQueryDbUnavailable(
                baseInput(RuntimePosture.forced(List.of("GUARD:AUTH"))));
        check("INSTRUMENTATION_REACHABILITY".equals(PathTraceProjector.authRequirementFor(forcedTrace, 200)),
                "FORCED authRequirement");
    }

    private static void legacyPathRunIncomplete() {
        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("pathRunId", "pathrun:old");
        legacy.put("entryRef", "entry:old");
        legacy.put("track", "UNAUTH");
        PathTrace trace = PathTraceProjector.fromLegacyPathRun(legacy);
        check(trace.legacyIncomplete(), "legacy PathRun → LEGACY_DYNAMIC_INCOMPLETE");
        check(trace.exitReason() == TraceExitReason.LEGACY_DYNAMIC_INCOMPLETE,
                "legacy exit reason");
        PathRunPathDebugView view = PathRunPathDebugView.fromPathRunWire(legacy);
        check(view.legacyIncomplete(), "PathRunPathDebugView legacy");
        check(trace.posture().postureKind() != com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind.FORCED_REACHABILITY
                        || RuntimePosture.PROVENANCE_LEGACY.equals(trace.posture().postureProvenance()),
                "never invent forced posture from legacy");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

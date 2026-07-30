package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.domain.pathdebug.TraceExitReason;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 说明：TracePlan vs PathTrace diff 验收（PATH/TRIAGE 注入+probe 优先级）。
 */
public final class TracePlanObservationDiffAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        missingEffectsDetected();
        formatAndPrioritize();
        System.out.println("TracePlanObservationDiffAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void missingEffectsDetected() {
        ApiDtos.EntryDto entry = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "project-tp", "b".repeat(64), "scan-tp",
                "entry-x", "HTTP", "GET", "/x", "demo.X", "demo",
                List.of("q="), List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of());
        TracePlan plan = TracePlanCompiler.compile(
                entry,
                List.of("demo.Service#run"),
                List.of("effect:SQL_INJECTION:demo.Repo#q", "SINK:SQL:sink-1"),
                List.of("GUARD:AUTH"),
                List.of());
        PathTrace trace = new PathTrace(
                PathTrace.SCHEMA_VERSION,
                "pathtrace-1",
                "pathrun-1",
                "probe-1",
                "exp-1",
                plan.tracePlanId(),
                entry.id(),
                "UNAUTH",
                RuntimePosture.legacyIncomplete(),
                "world-1",
                "corr-1",
                1,
                List.of(
                        new TraceEvent(0, TraceEventKind.ENTRY_HIT, "hit", entry.id(),
                                "", false, Map.of(), ""),
                        new TraceEvent(1, TraceEventKind.METHOD_HOP, "hop", "demo.Controller#x",
                                "", false, Map.of(), "")),
                List.of(),
                TraceExitReason.COMPLETED,
                "demo.Controller#x",
                List.of(),
                false);
        TracePlanObservationDiff.Diff diff = TracePlanObservationDiff.diff(plan, trace);
        check(diff.entryObserved(), "ENTRY_HIT observed");
        check(!diff.expectedEffectsMissing().isEmpty(), "expected effects still missing");
        check(diff.hasGaps(), "hasGaps when effects missing");
        List<String> gapEntries = TracePlanObservationDiff.entriesWithMissingEffects(List.of(diff));
        check(gapEntries.contains("entry-x"), "entriesWithMissingEffects lists entry");
    }

    private static void formatAndPrioritize() {
        ApiDtos.EntryDto filled = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "project-tp", "b".repeat(64), "scan-tp",
                "entry-ok", "HTTP", "GET", "/ok", "demo.Ok", "demo",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of());
        ApiDtos.EntryDto gap = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "project-tp", "b".repeat(64), "scan-tp",
                "entry-gap", "HTTP", "GET", "/gap", "demo.Gap", "demo",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of());
        TracePlan planOk = TracePlanCompiler.compile(
                filled, List.of(), List.of("effect:SQL:done"), List.of(), List.of());
        TracePlan planGap = TracePlanCompiler.compile(
                gap, List.of(), List.of("effect:SQL:missing"), List.of(), List.of());
        PathTrace hit = new PathTrace(
                PathTrace.SCHEMA_VERSION,
                "pathtrace-ok", "pathrun-ok", "", "", planOk.tracePlanId(), filled.id(),
                "UNAUTH", RuntimePosture.legacyIncomplete(), "", "", 1,
                List.of(new TraceEvent(0, TraceEventKind.EFFECT_TRIGGERED, "sql",
                        "effect:SQL:done", "", false, Map.of(), "")),
                List.of(), TraceExitReason.COMPLETED, "", List.of("effect:SQL:done"), false);
        List<TracePlanObservationDiff.Diff> diffs = TracePlanObservationDiff.prioritizeGaps(
                TracePlanObservationDiff.diffAll(List.of(planOk, planGap), List.of(hit)));
        check(!diffs.isEmpty(), "diffAll emits rows");
        check("entry-gap".equals(diffs.get(0).entryRef()), "prioritizeGaps puts missingEffects first");
        String prompt = TracePlanObservationDiff.formatForPrompt(diffs, false, 8);
        check(prompt.contains("TRACE_PLAN_VS_ACTUAL"), "prompt header present");
        check(prompt.contains("missingEffects") || prompt.contains("entry-gap"),
                "prompt surfaces gap entry");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

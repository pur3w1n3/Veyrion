package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-21: TracePlanCompiler acceptance.
 */
public final class TracePlanCompilerAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        zeroParamEntryRationale();
        effectHintsProjected();
        unresolvedPointsCaptured();
        compileAllBudget();
        System.out.println("TracePlanCompilerAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static ApiDtos.EntryDto sampleEntry(String id, String route, List<String> params) {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "project-tp", "b".repeat(64), "scan-tp",
                id, "HTTP", "GET", route, "demo.Controller", "demo",
                params, List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of());
    }

    private static void zeroParamEntryRationale() {
        TracePlan plan = TracePlanCompiler.compile(
                sampleEntry("entry-empty", "/api/ping", List.of()),
                List.of(), List.of(), List.of(), List.of());
        check(!plan.emptyInputRationale().isBlank(), "0-param entry carries emptyInputRationale");
        check(plan.parameters().size() == 1, "0-param entry has empty parameter spec");
        check(plan.parameters().get(0).emptyLegal(), "empty input legal");
        check(plan.tracePlanId().startsWith("traceplan:"), "tracePlanId stamped");
    }

    private static void effectHintsProjected() {
        TracePlan plan = TracePlanCompiler.compile(
                sampleEntry("entry-code", "/code", List.of("code=")),
                List.of("CodeController#handle -> CodeService#handle"),
                List.of("SINK:SQL", "TAINT:query.code", "JDBC query"),
                List.of("GUARD:AUTH"),
                List.of());
        check(plan.expectedHops().stream().anyMatch(h -> h.contains("CodeService")),
                "call edge hints → expectedHops");
        check(plan.expectedEffectRefs().stream().anyMatch(e -> e.startsWith("SINK:")),
                "sink hints → expectedEffectRefs");
        check(plan.expectedEffectRefs().stream().anyMatch(e -> e.contains("EFFECT:")),
                "effect-like strings normalized");
        check(plan.expectedGuardRefs().contains("GUARD:AUTH"), "guard hints projected");
    }

    private static void unresolvedPointsCaptured() {
        TracePlan plan = TracePlanCompiler.compile(
                sampleEntry("entry-dyn", "/dynamic", List.of()),
                List.of("UNRESOLVED:invokevirtual"),
                List.of("REFLECTION:Method.invoke"),
                List.of(),
                List.of("DYNAMIC_DISPATCH:handler"));
        check(!plan.unresolvedPoints().isEmpty(), "unresolved points captured");
        check(plan.unresolvedPoints().stream().anyMatch(u -> u.toUpperCase().contains("REFLECTION")
                        || u.toUpperCase().contains("UNRESOLVED")
                        || u.toUpperCase().contains("DYNAMIC")),
                "reflection/dynamic/unresolved merged");
    }

    private static void compileAllBudget() {
        List<TracePlan> plans = TracePlanCompiler.compileAll(
                List.of(
                        sampleEntry("e1", "/a", List.of()),
                        sampleEntry("e2", "/b", List.of()),
                        sampleEntry("e3", "/c", List.of())),
                List.of(), List.of(), List.of(), List.of(),
                2);
        check(plans.size() == 2, "compileAll respects budget");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

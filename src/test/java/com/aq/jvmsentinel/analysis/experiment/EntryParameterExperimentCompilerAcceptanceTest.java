package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-18: entry × 0-n parameter compilation with empty-input rationale.
 */
public final class EntryParameterExperimentCompilerAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        emptyEntryProducesRationale();
        declaredParametersCompileQuery();
        System.out.println("EntryParameterExperimentCompilerAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void emptyEntryProducesRationale() {
        ApiDtos.EntryDto entry = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "project-ep", "b".repeat(64), "scan-ep",
                "entry-empty", "HTTP", "GET", "/api/ping", "demo.PingController", "demo",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of());
        List<EntryParameterExperimentCompiler.CompiledExperiment> plans =
                EntryParameterExperimentCompiler.compile(List.of(entry), List.of(), 8);
        check(!plans.isEmpty(), "compiled at least one plan");
        EntryParameterExperimentCompiler.CompiledExperiment plan = plans.get(0);
        check(plan.kind() == ExperimentPlanKind.REACHABILITY, "default kind REACHABILITY");
        check(!plan.emptyInputRationale().isBlank(), "empty-input rationale present");
        check(plan.query().isBlank(), "empty query remains blank");
        check(plan.toWireMap().get("producer").equals(EntryParameterExperimentCompiler.PRODUCER),
                "producer stamped");
        check("EXECUTABLE".equals(plan.readiness()), "no-auth entry is EXECUTABLE");
    }

    private static void declaredParametersCompileQuery() {
        ApiDtos.EntryDto entry = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "project-ep", "b".repeat(64), "scan-ep",
                "entry-q", "HTTP", "GET", "/api/search", "demo.SearchController", "demo",
                List.of("q=test", "page=1"), List.of("AUTH"), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of());
        List<EntryParameterExperimentCompiler.CompiledExperiment> plans =
                EntryParameterExperimentCompiler.compile(List.of(entry), List.of(), 8);
        check(!plans.isEmpty(), "parameterized entry compiled");
        EntryParameterExperimentCompiler.CompiledExperiment plan = plans.get(0);
        check(plan.query().contains("q=test"), "query includes declared sample");
        check("MISSING_IDENTITY".equals(plan.readiness()), "AUTH precondition → MISSING_IDENTITY");
        check(plan.parameters().stream().anyMatch(p -> "q".equals(p.name())), "parameter q present");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

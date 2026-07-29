package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-21: PostureExperimentCompiler acceptance.
 */
public final class PostureExperimentCompilerAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        defaultPosturesCompiled();
        bypassOnlyWhenCandidate();
        requiredFieldsPresent();
        identityTrackWired();
        blankExperimentPlanIdRejected();
        System.out.println("PostureExperimentCompilerAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static ApiDtos.EntryDto sampleEntry() {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "project-pe", "b".repeat(64), "scan-pe",
                "entry-admin", "HTTP", "GET", "/api/admin", "demo.AdminController", "demo",
                List.of("id=1"), List.of("AUTH"), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of());
    }

    private static void defaultPosturesCompiled() {
        List<PostureExperimentCompiler.CompiledPostureExperiment> plans =
                PostureExperimentCompiler.compile(
                        sampleEntry(),
                        "scan-pe",
                        List.of(),
                        List.of("SINK:SQL"),
                        List.of("GUARD:AUTH"),
                        List.of(),
                        List.of(),
                        16);
        check(plans.stream().anyMatch(p -> p.posture().postureKind() == RuntimePostureKind.UNAUTH),
                "UNAUTH posture compiled");
        check(plans.stream().anyMatch(p -> p.posture().postureKind() == RuntimePostureKind.COVERAGE_POSTURE),
                "COVERAGE_POSTURE compiled");
        check(plans.stream().anyMatch(p -> p.posture().postureKind() == RuntimePostureKind.FORCED_REACHABILITY),
                "FORCED_REACHABILITY compiled");
        check(plans.stream().noneMatch(p -> p.posture().postureKind() == RuntimePostureKind.BYPASS),
                "BYPASS omitted without candidate");
    }

    private static void bypassOnlyWhenCandidate() {
        List<PostureExperimentCompiler.CompiledPostureExperiment> plans =
                PostureExperimentCompiler.compile(
                        sampleEntry(),
                        "scan-pe",
                        List.of(), List.of(), List.of("GUARD:AUTH"), List.of(),
                        List.of("entry-admin"),
                        16);
        check(plans.stream().anyMatch(p -> p.posture().postureKind() == RuntimePostureKind.BYPASS),
                "BYPASS when bypass candidate provided");
    }

    private static void requiredFieldsPresent() {
        PostureExperimentCompiler.CompiledPostureExperiment plan =
                PostureExperimentCompiler.compile(
                        sampleEntry(), "scan-pe", List.of(), List.of(), List.of("GUARD:AUTH"),
                        List.of(), List.of(), 8).get(0);
        check(!plan.experimentPlanId().isBlank(), "experimentPlanId present");
        check(!plan.tracePlanId().isBlank(), "tracePlanId present");
        check(!plan.worldPackId().isBlank(), "worldPackId present");
        check(!plan.expectedSignals().isEmpty(), "expectedSignals present");
        check(!plan.counterSignals().isEmpty(), "counterSignals present");
        check(!plan.stopCondition().isBlank(), "stopCondition present");
        check(plan.toWireMap().get("producer").equals(PostureExperimentCompiler.PRODUCER),
                "producer stamped");
    }

    private static void identityTrackWired() {
        List<PostureExperimentCompiler.CompiledPostureExperiment> plans =
                PostureExperimentCompiler.compile(
                        sampleEntry(), "scan-pe", List.of(), List.of(), List.of("GUARD:AUTH"),
                        List.of(), List.of(), 8);
        PostureExperimentCompiler.CompiledPostureExperiment unauth = plans.stream()
                .filter(p -> p.posture().postureKind() == RuntimePostureKind.UNAUTH)
                .findFirst().orElseThrow();
        PostureExperimentCompiler.CompiledPostureExperiment coverage = plans.stream()
                .filter(p -> p.posture().postureKind() == RuntimePostureKind.COVERAGE_POSTURE)
                .findFirst().orElseThrow();
        check(unauth.track() == IdentityTrack.UNAUTH, "UNAUTH → UNAUTH track");
        check(coverage.track() == IdentityTrack.ADMIN, "COVERAGE → ADMIN track via identityTrackWire");
    }

    private static void blankExperimentPlanIdRejected() {
        try {
            new PostureExperimentCompiler.CompiledPostureExperiment(
                    "",
                    "traceplan:x",
                    "worldpack:x",
                    "entry:x",
                    "GET",
                    "/x",
                    com.aq.jvmsentinel.domain.pathdebug.RuntimePosture.unauth(),
                    IdentityTrack.UNAUTH,
                    List.of(),
                    "",
                    "",
                    "",
                    List.of(),
                    List.of(),
                    "BUDGET");
            check(false, "blank experimentPlanId must throw");
        } catch (IllegalArgumentException expected) {
            check(true, "blank experimentPlanId rejected");
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.ExperimentSignal;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Server-side default ExperimentPlan candidates from SecurityHypothesis (P1-06).
 * Deterministic; models must not author these defaults.
 */
public final class DefaultExperimentPlanFactory {
    public static final String PRODUCER = "server-default-experiment-plan/0.1";

    private DefaultExperimentPlanFactory() {
    }

    public static List<HypothesisExperimentPlan> fromHypothesis(SecurityHypothesis hypothesis) {
        return fromHypothesis(hypothesis, "", IdentityTrack.UNAUTH);
    }

    public static List<HypothesisExperimentPlan> fromHypothesis(SecurityHypothesis hypothesis,
                                                                String entrypointRef,
                                                                IdentityTrack track) {
        Objects.requireNonNull(hypothesis, "hypothesis");
        IdentityTrack safeTrack = track == null ? IdentityTrack.UNAUTH : track;
        String entry = entrypointRef == null ? "" : entrypointRef.trim();
        List<HypothesisExperimentPlan> plans = new ArrayList<>();
        for (ExperimentPlanKind kind : kindsFor(hypothesis.family())) {
            plans.add(build(hypothesis, kind, entry, safeTrack));
        }
        return List.copyOf(plans);
    }

    public static List<HypothesisExperimentPlan> fromHypotheses(List<SecurityHypothesis> hypotheses) {
        if (hypotheses == null || hypotheses.isEmpty()) {
            return List.of();
        }
        List<HypothesisExperimentPlan> plans = new ArrayList<>();
        for (SecurityHypothesis hypothesis : hypotheses) {
            if (hypothesis == null) continue;
            plans.addAll(fromHypothesis(hypothesis));
        }
        return List.copyOf(plans);
    }

    private static List<ExperimentPlanKind> kindsFor(HypothesisFamily family) {
        return switch (family) {
            case DATAFLOW -> List.of(ExperimentPlanKind.REACHABILITY, ExperimentPlanKind.DATAFLOW_DIFF);
            case GUARD_COVERAGE -> List.of(ExperimentPlanKind.GUARD_DIFF, ExperimentPlanKind.REACHABILITY);
            case STATE -> List.of(ExperimentPlanKind.STATE_SEQUENCE, ExperimentPlanKind.REACHABILITY);
            case TYPESTATE -> List.of(ExperimentPlanKind.TYPESTATE_API);
            case CONCURRENCY -> List.of(ExperimentPlanKind.CONCURRENCY_RESOURCE);
            case CONFIG, DEPENDENCY -> List.of(ExperimentPlanKind.REACHABILITY, ExperimentPlanKind.TYPESTATE_API);
            case COMPOSITION -> List.of(
                    ExperimentPlanKind.REACHABILITY,
                    ExperimentPlanKind.GUARD_DIFF,
                    ExperimentPlanKind.DATAFLOW_DIFF);
            case UNKNOWN -> List.of(ExperimentPlanKind.REACHABILITY);
        };
    }

    private static HypothesisExperimentPlan build(SecurityHypothesis hypothesis,
                                                  ExperimentPlanKind kind,
                                                  String entrypointRef,
                                                  IdentityTrack track) {
        String planId = "plan:hyp:" + hypothesis.hypothesisId() + ":" + kind.name().toLowerCase();
        return new HypothesisExperimentPlan(
                HypothesisExperimentPlan.SCHEMA_VERSION,
                planId,
                hypothesis.hypothesisId(),
                hypothesis.scanId(),
                kind,
                entrypointRef,
                track,
                expectedFor(kind),
                counterFor(kind),
                "COMPLETED",
                2,
                "",
                ""
        );
    }

    private static List<ExperimentSignal> expectedFor(ExperimentPlanKind kind) {
        return switch (kind) {
            case REACHABILITY -> List.of(
                    ExperimentSignal.of("ENTRY_HIT"),
                    ExperimentSignal.of("EFFECT_HIT"));
            case DATAFLOW_DIFF -> List.of(
                    ExperimentSignal.of("EFFECT_STRUCTURE_DIFF"),
                    ExperimentSignal.of("MALICIOUS_FRAGMENT"));
            case GUARD_DIFF -> List.of(
                    ExperimentSignal.of("GUARD_BYPASS"),
                    ExperimentSignal.of("SAME_EFFECT_DIFF_IDENTITY"));
            case STATE_SEQUENCE -> List.of(
                    ExperimentSignal.of("STATE_TRANSITION"),
                    ExperimentSignal.of("INVARIANT_BROKEN"));
            case TYPESTATE_API -> List.of(
                    ExperimentSignal.of("TYPESTATE_MISUSE"),
                    ExperimentSignal.of("UNSAFE_API_SEQUENCE"));
            case CONCURRENCY_RESOURCE -> List.of(
                    ExperimentSignal.of("RACE_WINDOW"),
                    ExperimentSignal.of("TOCTOU_HIT"));
        };
    }

    private static List<ExperimentSignal> counterFor(ExperimentPlanKind kind) {
        return switch (kind) {
            case REACHABILITY -> List.of(
                    ExperimentSignal.of("AUTH_CHALLENGE"),
                    ExperimentSignal.of("UNREACHED"));
            case DATAFLOW_DIFF -> List.of(
                    ExperimentSignal.of("PARAMETERIZED_BLOCK"),
                    ExperimentSignal.of("SANITIZER_HIT"));
            case GUARD_DIFF -> List.of(
                    ExperimentSignal.of("GUARD_DENY"),
                    ExperimentSignal.of("IDENTITY_UNAVAILABLE"));
            case STATE_SEQUENCE -> List.of(
                    ExperimentSignal.of("INVARIANT_HELD"),
                    ExperimentSignal.of("SEQUENCE_REJECTED"));
            case TYPESTATE_API -> List.of(
                    ExperimentSignal.of("SAFE_REJECT"),
                    ExperimentSignal.of("PROTOCOL_OK"));
            case CONCURRENCY_RESOURCE -> List.of(
                    ExperimentSignal.of("LOCK_SERIALIZED"),
                    ExperimentSignal.of("NO_RACE"));
        };
    }
}

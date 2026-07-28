package com.aq.jvmsentinel.domain.experiment;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;

import java.util.Objects;
import java.util.Optional;

/**
 * Strict server-side lifecycle gate for hypothesis experiments (P1-06).
 *
 * <ul>
 *   <li>Failed / empty projections never change lifecycle.</li>
 *   <li>Only {@link HypothesisLifecycle#CANDIDATE} may advance to SUPPORTED or CONTRADICTED.</li>
 *   <li>Never elevates finding verification status to VERIFIED / DYNAMIC_CONFIRMED.</li>
 * </ul>
 */
public final class HypothesisExperimentGate {
    private HypothesisExperimentGate() {
    }

    public enum Verdict {
        NO_CHANGE,
        SUPPORTED,
        CONTRADICTED
    }

    public record Decision(Verdict verdict, HypothesisLifecycle nextLifecycle, String reason) {
        public Decision {
            Objects.requireNonNull(verdict, "verdict");
            Objects.requireNonNull(nextLifecycle, "nextLifecycle");
            reason = reason == null ? "" : reason;
        }

        public boolean changed() {
            return verdict != Verdict.NO_CHANGE;
        }
    }

    public static Decision evaluate(HypothesisLifecycle current,
                                    HypothesisExperimentPlan plan,
                                    RuntimeObservation observation) {
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(observation, "observation");

        if (observation.isEmptyOrFailed() || !observation.successfulProjection()) {
            return unchanged(current, "EMPTY_OR_FAILED_PROJECTION");
        }
        if (current != HypothesisLifecycle.CANDIDATE) {
            return unchanged(current, "LIFECYCLE_NOT_CANDIDATE");
        }
        if (!plan.hypothesisId().equals(observation.hypothesisId())) {
            return unchanged(current, "HYPOTHESIS_MISMATCH");
        }
        if (observation.planKind() != null && observation.planKind() != plan.planKind()) {
            return unchanged(current, "PLAN_KIND_MISMATCH");
        }
        String signal = observation.signalCode();
        for (ExperimentSignal counter : plan.counterSignals()) {
            if (counter.matches(signal)) {
                return new Decision(Verdict.CONTRADICTED, HypothesisLifecycle.CONTRADICTED,
                        "COUNTER_SIGNAL:" + counter.code());
            }
        }
        for (ExperimentSignal expected : plan.expectedSignals()) {
            if (expected.matches(signal)) {
                return new Decision(Verdict.SUPPORTED, HypothesisLifecycle.SUPPORTED,
                        "EXPECTED_SIGNAL:" + expected.code());
            }
        }
        return unchanged(current, "SIGNAL_NO_MATCH");
    }

    public static Optional<HypothesisLifecycle> nextLifecycle(HypothesisLifecycle current,
                                                              HypothesisExperimentPlan plan,
                                                              RuntimeObservation observation) {
        Decision decision = evaluate(current, plan, observation);
        return decision.changed() ? Optional.of(decision.nextLifecycle()) : Optional.empty();
    }

    private static Decision unchanged(HypothesisLifecycle current, String reason) {
        return new Decision(Verdict.NO_CHANGE, current, reason);
    }
}

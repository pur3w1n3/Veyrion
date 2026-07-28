package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Server gate for hypothesis-bound experiment plans (P1-06).
 * Extends ExperimentPlan safety rules without altering P0-08 plan identity semantics.
 */
public final class HypothesisExperimentPlanValidator {
    private static final Set<String> DESTRUCTIVE = Set.of(
            "drop ", "truncate ", "rm -rf", "runtime.exec", "processbuilder",
            "memshell", "memory shell", "/bin/sh", "powershell");

    private HypothesisExperimentPlanValidator() {
    }

    public static void validate(HypothesisExperimentPlan plan, int remainingBudget) {
        Objects.requireNonNull(plan, "plan");
        if (remainingBudget < 1) {
            throw new IllegalArgumentException("PROBE_BUDGET");
        }
        if (plan.maxAttempts() > remainingBudget) {
            throw new IllegalArgumentException("PROBE_BUDGET");
        }
        if (!plan.entrypointRef().isBlank() && !plan.entrypointRef().startsWith("entry:")) {
            throw new IllegalArgumentException("entrypointRef must be entry:*");
        }
        ExperimentPlanKind kind = plan.planKind();
        if (kind == null) {
            throw new IllegalArgumentException("UNKNOWN_PLAN_KIND");
        }
        String blob = (plan.experimentPlanId() + " " + plan.hypothesisId() + " " + plan.stopCondition())
                .toLowerCase(Locale.ROOT);
        for (String token : DESTRUCTIVE) {
            if (blob.contains(token)) {
                throw new IllegalArgumentException("destructive payload rejected");
            }
        }
        if (plan.expectedSignals().isEmpty() && plan.counterSignals().isEmpty()) {
            throw new IllegalArgumentException("expected or counter signals required");
        }
    }

    public static ExperimentPlanKind requirePlanKind(String raw) {
        return ExperimentPlanKind.tryParse(raw)
                .orElseThrow(() -> new IllegalArgumentException("UNKNOWN_PLAN_KIND"));
    }
}

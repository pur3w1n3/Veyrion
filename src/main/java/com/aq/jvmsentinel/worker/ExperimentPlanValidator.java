package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.util.Locale;
import java.util.Set;

/**
 * Server gate for AI-proposed experiment plans. Rejects unsafe or over-budget plans.
 */
public final class ExperimentPlanValidator {
    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain");
    private static final Set<String> ALLOWED_METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE");
    private static final Set<String> DESTRUCTIVE = Set.of(
            "drop ", "truncate ", "rm -rf", "runtime.exec", "processbuilder",
            "memshell", "memory shell", "/bin/sh", "powershell");

    private ExperimentPlanValidator() { }

    public static void validate(ExperimentPlan plan, int remainingBudget) {
        if (plan == null) throw new IllegalArgumentException("experiment plan is required");
        if (remainingBudget < 1) throw new IllegalArgumentException("PROBE_BUDGET");
        if (plan.entrypointRef() == null || !plan.entrypointRef().startsWith("entry:")) {
            throw new IllegalArgumentException("entrypointRef must be entry:*");
        }
        if (!ALLOWED_METHODS.contains(plan.method().toUpperCase(Locale.ROOT))) {
            throw new IllegalArgumentException("method is not allowlisted");
        }
        String contentType = plan.contentType().toLowerCase(Locale.ROOT);
        boolean allowedType = ALLOWED_CONTENT_TYPES.stream().anyMatch(contentType::startsWith);
        if (!allowedType) throw new IllegalArgumentException("contentType is not allowlisted");
        if (plan.maxAttempts() > remainingBudget) {
            throw new IllegalArgumentException("PROBE_BUDGET");
        }
        String blob = (plan.successHttpHint() + " " + plan.successJsonPath()
                + " " + String.join(" ", plan.requiredParameters())).toLowerCase(Locale.ROOT);
        for (String token : DESTRUCTIVE) {
            if (blob.contains(token)) {
                throw new IllegalArgumentException("destructive payload rejected");
            }
        }
        if (plan.track() == IdentityTrack.BYPASS_CANDIDATE && !plan.authRequired()) {
            // Allowed: bypass candidates may probe without claiming authRequired.
        }
    }
}

package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.Locale;
import java.util.Objects;

/**
 * Server-only H3 gate: upgrades DYNAMIC_SUSPECTED → DYNAMIC_CONFIRMED when a malicious
 * fragment is present in the actual JDBC/mock SQL without parameterization.
 * Models cannot invoke this upgrade.
 */
public final class DynamicConfirmedGate {
    private DynamicConfirmedGate() { }

    public static VerificationStatus evaluate(PathRun run, String probeMarker) {
        Objects.requireNonNull(run, "run");
        if (run.sqlEvents().isEmpty()) return VerificationStatus.DYNAMIC_SUSPECTED;
        String marker = probeMarker == null ? "" : probeMarker.trim();
        if (marker.isBlank()) return VerificationStatus.DYNAMIC_SUSPECTED;
        String needle = marker.toLowerCase(Locale.ROOT);
        boolean hit = false;
        boolean parameterizedBlock = false;
        for (SqlEvent event : run.sqlEvents()) {
            String sql = event.sqlText() == null ? "" : event.sqlText().toLowerCase(Locale.ROOT);
            if (sql.contains(needle) || event.maliciousFragmentPresent()) {
                hit = true;
                if (event.parameterized()) parameterizedBlock = true;
            }
        }
        if (!hit) return VerificationStatus.DYNAMIC_SUSPECTED;
        if (parameterizedBlock) return VerificationStatus.DYNAMIC_SUSPECTED;
        return VerificationStatus.DYNAMIC_CONFIRMED;
    }

    public static PathRun apply(PathRun run, String probeMarker) {
        VerificationStatus status = evaluate(run, probeMarker);
        if (status != VerificationStatus.DYNAMIC_CONFIRMED) return run;
        return new PathRun(
                run.pathRunId(), run.scanId(), run.entrypointRef(), run.track(), run.attemptId(),
                run.experimentPlanId(), run.method(), run.contentType(), run.requestSummary(),
                run.outcomeClass(), run.httpStatus(), run.entryHit(), run.parameterBound(),
                run.sqlEvents(), run.stopReason(), status.name(), run.evidenceRefs(),
                run.identityProvenance(), run.identityPrecondition());
    }
}

package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.Locale;
import java.util.Objects;

/**
 * Server-only verification gate.
 *
 * <p>H3 (SQL dataflow): may upgrade {@code DYNAMIC_SUSPECTED → DYNAMIC_CONFIRMED} when a
 * malicious fragment is present in actual JDBC/mock SQL without parameterization.
 *
 * <p>P2 family fail-closed: Guard / State / Typestate / other non-SQL-dataflow families are
 * capped at {@code DYNAMIC_SUSPECTED} until an independent family audit lands. Models cannot
 * invoke this upgrade.
 */
public final class DynamicConfirmedGate {
    private DynamicConfirmedGate() { }

    /**
     * SQL dataflow H3 path (default). Equivalent to
     * {@link #evaluate(PathRun, String, HypothesisFamily)} with {@link HypothesisFamily#DATAFLOW}.
     */
    public static VerificationStatus evaluate(PathRun run, String probeMarker) {
        return evaluate(run, probeMarker, HypothesisFamily.DATAFLOW);
    }

    /**
     * Family-aware evaluation. Non-{@link HypothesisFamily#DATAFLOW} families never return
     * {@link VerificationStatus#DYNAMIC_CONFIRMED} (P2 scaffolding / unaudited).
     */
    public static VerificationStatus evaluate(PathRun run, String probeMarker,
                                              HypothesisFamily family) {
        Objects.requireNonNull(run, "run");
        HypothesisFamily resolved = family == null ? HypothesisFamily.UNKNOWN : family;
        if (!allowsDynamicConfirmed(resolved)) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        // H3 requires same-PathRun statement evidence + replayable evidence refs (P0-06).
        if (run.sqlEvents().isEmpty()) return VerificationStatus.DYNAMIC_SUSPECTED;
        if (run.evidenceRefs() == null || run.evidenceRefs().isEmpty()) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        if (Boolean.FALSE.equals(run.entryHit())) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        String marker = probeMarker == null ? "" : probeMarker.trim();
        if (marker.isBlank()) return VerificationStatus.DYNAMIC_SUSPECTED;
        String needle = marker.toLowerCase(Locale.ROOT);
        boolean hit = false;
        boolean parameterizedBlock = false;
        for (SqlEvent event : run.sqlEvents()) {
            // Protocol listen/meta must never satisfy H3; only statement text counts.
            if (!isStatementEvidence(event)) continue;
            // Fail-closed: MOCK metadata flags / maliciousFragmentPresent alone cannot upgrade.
            // H3 requires the probe marker to appear in actual statement SQL text.
            String sql = event.sqlText() == null ? "" : event.sqlText().toLowerCase(Locale.ROOT);
            if (!sql.contains(needle)) continue;
            hit = true;
            if (event.parameterized()) parameterizedBlock = true;
        }
        if (!hit) return VerificationStatus.DYNAMIC_SUSPECTED;
        if (parameterizedBlock) return VerificationStatus.DYNAMIC_SUSPECTED;
        return VerificationStatus.DYNAMIC_CONFIRMED;
    }

    public static PathRun apply(PathRun run, String probeMarker) {
        return apply(run, probeMarker, HypothesisFamily.DATAFLOW);
    }

    public static PathRun apply(PathRun run, String probeMarker, HypothesisFamily family) {
        VerificationStatus status = evaluate(run, probeMarker, family);
        if (status != VerificationStatus.DYNAMIC_CONFIRMED) return run;
        return new PathRun(
                run.pathRunId(), run.scanId(), run.entrypointRef(), run.track(), run.attemptId(),
                run.experimentPlanId(), run.method(), run.contentType(), run.requestSummary(),
                run.outcomeClass(), run.httpStatus(), run.entryHit(), run.parameterBound(),
                run.sqlEvents(), run.stopReason(), status.name(), run.evidenceRefs(),
                run.identityProvenance(), run.identityPrecondition(), run.branchHitMap());
    }

    /**
     * Clamp a proposed status for a hypothesis family. Non-SQL-dataflow families cannot exceed
     * {@link VerificationStatus#DYNAMIC_SUSPECTED}; {@code VERIFIED} remains globally closed.
     */
    public static VerificationStatus capForFamily(VerificationStatus proposed,
                                                  HypothesisFamily family) {
        VerificationStatus status = proposed == null
                ? VerificationStatus.DYNAMIC_SUSPECTED : proposed;
        if (status == VerificationStatus.VERIFIED) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        if (status == VerificationStatus.DYNAMIC_CONFIRMED
                && !allowsDynamicConfirmed(family == null ? HypothesisFamily.UNKNOWN : family)) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        return status;
    }

    /**
     * Only the SQL dataflow H3 path may reach {@code DYNAMIC_CONFIRMED} until independent
     * Guard/State/Typestate (and other non-SQL) family audits complete.
     */
    public static boolean allowsDynamicConfirmed(HypothesisFamily family) {
        return family == HypothesisFamily.DATAFLOW;
    }

    private static boolean isStatementEvidence(SqlEvent event) {
        if (event == null) return false;
        String sql = event.sqlText() == null ? "" : event.sqlText().trim();
        if (sql.isBlank()) return false;
        String lower = sql.toLowerCase(Locale.ROOT);
        if (lower.startsWith("port=") || lower.startsWith("sqlclass=")
                || lower.contains("accepted-without-credential")) {
            return false;
        }
        String capture = event.captureMode() == null ? "" : event.captureMode();
        if ("DEPENDENCY_PROTOCOL_MOCK".equals(capture)
                && !(lower.startsWith("select") || lower.startsWith("insert")
                || lower.startsWith("update") || lower.startsWith("delete")
                || lower.startsWith("replace") || lower.contains("?"))) {
            return false;
        }
        return true;
    }
}

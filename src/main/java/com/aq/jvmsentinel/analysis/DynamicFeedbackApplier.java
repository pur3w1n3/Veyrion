package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Applies dynamic PathRun observations back as bounded evidence updates.
 * Never opens VERIFIED; max DYNAMIC_SUSPECTED / DYNAMIC_CONFIRMED via server gates.
 */
public final class DynamicFeedbackApplier {
    public static final String EVIDENCE_KIND = "DYNAMIC_TAINT_UPDATE";

    private DynamicFeedbackApplier() {
    }

    public record FeedbackResult(List<ApiDtos.EvidenceDto> evidence, int upgradedCount) {
        public FeedbackResult {
            evidence = List.copyOf(evidence == null ? List.of() : evidence);
        }
    }

    public static FeedbackResult apply(
            String projectId, String artifactDigest, String scanId,
            List<ApiDtos.PathRunDto> pathRuns, String observedAt) {
        Objects.requireNonNull(scanId, "scanId");
        List<ApiDtos.EvidenceDto> evidence = new ArrayList<>();
        int upgraded = 0;
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;
        for (ApiDtos.PathRunDto run : runs) {
            if (run == null) continue;
            boolean entryHit = Boolean.TRUE.equals(run.entryHit());
            boolean bound = Boolean.TRUE.equals(run.parameterBound());
            boolean sqlFragments = run.sqlEvents() != null && run.sqlEvents().stream()
                    .anyMatch(sql -> sql != null && sql.sqlText() != null && !sql.sqlText().isBlank());
            if (!(entryHit && bound && sqlFragments)) continue;
            upgraded++;
            String id = "evidence-dynamic-taint-" + run.pathRunId();
            String when = observedAt == null || observedAt.isBlank()
                    ? Instant.now().toString() : observedAt;
            evidence.add(new ApiDtos.EvidenceDto(
                    ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId, id,
                    "RUNTIME_OBSERVED", EVIDENCE_KIND + ":" + run.pathRunId(), 0.7,
                    "TaintPath candidate upgraded by PathRun " + run.pathRunId()
                            + ": STATIC_INFERRED → " + cappedStatus(run),
                    when, "veyrion-feedback/1", "none",
                    "pathrun:" + run.pathRunId(), ApiDtos.MOCK, cappedStatus(run)));
        }
        return new FeedbackResult(evidence, upgraded);
    }

    private static String cappedStatus(ApiDtos.PathRunDto run) {
        if (VerificationStatus.DYNAMIC_CONFIRMED.name().equals(run.verificationStatus())) {
            return VerificationStatus.DYNAMIC_CONFIRMED.name();
        }
        // DynamicConfirmedGate remains the only path to DYNAMIC_CONFIRMED.
        return VerificationStatus.DYNAMIC_SUSPECTED.name();
    }
}

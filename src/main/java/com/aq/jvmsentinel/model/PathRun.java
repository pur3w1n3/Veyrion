package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * First-class path experiment session: scanId + entryId + track + attemptId.
 */
public record PathRun(
        String pathRunId,
        String scanId,
        String entrypointRef,
        IdentityTrack track,
        String attemptId,
        String experimentPlanId,
        String method,
        String contentType,
        String requestSummary,
        PathOutcomeClass outcomeClass,
        int httpStatus,
        Boolean entryHit,
        Boolean parameterBound,
        List<SqlEvent> sqlEvents,
        String stopReason,
        String verificationStatus,
        List<String> evidenceRefs,
        String identityProvenance,
        String identityPrecondition
) {
    public PathRun {
        Objects.requireNonNull(pathRunId, "pathRunId");
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(entrypointRef, "entrypointRef");
        Objects.requireNonNull(track, "track");
        Objects.requireNonNull(attemptId, "attemptId");
        Objects.requireNonNull(outcomeClass, "outcomeClass");
        method = Objects.requireNonNullElse(method, "GET");
        contentType = Objects.requireNonNullElse(contentType, "application/json");
        requestSummary = Objects.requireNonNullElse(requestSummary, "");
        sqlEvents = List.copyOf(sqlEvents == null ? List.of() : sqlEvents);
        stopReason = Objects.requireNonNullElse(stopReason, "UNKNOWN");
        verificationStatus = Objects.requireNonNullElse(verificationStatus, "DYNAMIC_SUSPECTED");
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        identityProvenance = Objects.requireNonNullElse(identityProvenance, "MOCK");
        identityPrecondition = Objects.requireNonNullElse(identityPrecondition, "");
    }
}

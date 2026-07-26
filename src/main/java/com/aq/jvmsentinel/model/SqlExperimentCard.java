package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * D3 replayable SQL experiment card: identity track, bounded inputs, SQL before/after,
 * and stop conditions. Default verification is at most {@link VerificationStatus#DYNAMIC_SUSPECTED};
 * only the server H3 gate may raise {@link VerificationStatus#DYNAMIC_CONFIRMED}.
 */
public record SqlExperimentCard(
        String cardId,
        String scanId,
        String entrypointRef,
        IdentityTrack track,
        String experimentPlanId,
        String benignInput,
        String metaInput,
        String sqlBefore,
        String sqlAfter,
        boolean structureInfluenced,
        String stopCondition,
        String dependencyMode,
        String verificationStatus,
        List<String> pathRunRefs,
        List<String> evidenceRefs
) {
    public SqlExperimentCard {
        Objects.requireNonNull(cardId, "cardId");
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(entrypointRef, "entrypointRef");
        Objects.requireNonNull(track, "track");
        benignInput = benignInput == null ? "" : benignInput;
        metaInput = metaInput == null ? "" : metaInput;
        sqlBefore = sqlBefore == null ? "" : sqlBefore;
        sqlAfter = sqlAfter == null ? "" : sqlAfter;
        stopCondition = stopCondition == null || stopCondition.isBlank() ? "UNKNOWN" : stopCondition;
        dependencyMode = dependencyMode == null || dependencyMode.isBlank() ? "MOCK" : dependencyMode;
        verificationStatus = verificationStatus == null || verificationStatus.isBlank()
                ? VerificationStatus.DYNAMIC_SUSPECTED.name() : verificationStatus;
        if (VerificationStatus.VERIFIED.name().equals(verificationStatus)) {
            throw new IllegalArgumentException("D3 cards must not claim VERIFIED");
        }
        pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
    }
}

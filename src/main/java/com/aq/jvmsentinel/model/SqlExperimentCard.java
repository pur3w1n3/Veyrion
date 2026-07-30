package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * D3 可 replay 的 SQL 实验 card：identity track、有界 input、SQL before/after
 * 与 stop condition。默认 verification 至多 {@link VerificationStatus#DYNAMIC_SUSPECTED}；
 * 仅服务端 H3 gate 可提升为 {@link VerificationStatus#DYNAMIC_CONFIRMED}。
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

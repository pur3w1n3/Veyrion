package com.aq.jvmsentinel.domain.analyzer;

import com.aq.jvmsentinel.domain.universe.CoverageGap;
import com.aq.jvmsentinel.domain.universe.UniverseScope;

import java.util.Objects;

/** Wire-form coverage gap contributed by Analyzer (maps to domain.universe.CoverageGap). */
public record AnalyzerCoverageGapDto(
        String id,
        String kind,
        String detail,
        String stopReason,
        String evidenceRef
) {
    public AnalyzerCoverageGapDto {
        id = AnalyzerContracts.id(id, "id");
        Objects.requireNonNull(kind, "kind");
        if (kind.isBlank()) {
            throw new IllegalArgumentException("kind must not be blank");
        }
        detail = detail == null ? "" : detail;
        stopReason = stopReason == null ? "" : stopReason;
        evidenceRef = evidenceRef == null ? "" : evidenceRef;
    }

    public CoverageGap toDomain() {
        return new CoverageGap(id, kind, detail, UniverseScope.UNKNOWN, stopReason, evidenceRef);
    }
}

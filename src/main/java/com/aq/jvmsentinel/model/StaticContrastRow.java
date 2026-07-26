package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * One ledger row: sink-perspective static projection joined (optionally) to PathRuns.
 * Engine FACT/INFERENCE only — never VERIFIED / bypass-confirmed by itself.
 */
public record StaticContrastRow(
        String rowId,
        String sinkId,
        String category,
        String sinkSymbol,
        List<String> entryRefs,
        String taintPathId,
        String track,
        ContrastStatus contrastStatus,
        List<String> pathRunRefs,
        String stopReason,
        boolean truncated
) {
    public StaticContrastRow {
        Objects.requireNonNull(rowId, "rowId");
        Objects.requireNonNull(sinkId, "sinkId");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(sinkSymbol, "sinkSymbol");
        Objects.requireNonNull(contrastStatus, "contrastStatus");
        entryRefs = List.copyOf(entryRefs == null ? List.of() : entryRefs);
        taintPathId = taintPathId == null ? "" : taintPathId;
        track = track == null ? "" : track;
        pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
        stopReason = stopReason == null ? "" : stopReason;
    }

    public boolean hasTaintPath() {
        return taintPathId != null && !taintPathId.isBlank();
    }

    public boolean isStaticOnly() {
        return contrastStatus == ContrastStatus.STATIC_ONLY;
    }
}

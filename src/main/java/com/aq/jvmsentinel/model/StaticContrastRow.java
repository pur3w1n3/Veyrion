package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * 一条 ledger 行：sink 视角静态投影（可选）关联 PathRun。
 * 仅 Engine FACT/INFERENCE — 自身永非 VERIFIED / bypass-confirmed。
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
        boolean truncated,
        String snapshotId,
        int roundIndex,
        int firstSeenRound,
        int lastHitRound,
        int hitCount
) {
    public StaticContrastRow(
            String rowId, String sinkId, String category, String sinkSymbol,
            List<String> entryRefs, String taintPathId, String track,
            ContrastStatus contrastStatus, List<String> pathRunRefs,
            String stopReason, boolean truncated) {
        this(rowId, sinkId, category, sinkSymbol, entryRefs, taintPathId, track,
                contrastStatus, pathRunRefs, stopReason, truncated, "", 0, 0, 0, 0);
    }

    public StaticContrastRow(
            String rowId, String sinkId, String category, String sinkSymbol,
            List<String> entryRefs, String taintPathId, String track,
            ContrastStatus contrastStatus, List<String> pathRunRefs,
            String stopReason, boolean truncated, String snapshotId, int roundIndex) {
        this(rowId, sinkId, category, sinkSymbol, entryRefs, taintPathId, track,
                contrastStatus, pathRunRefs, stopReason, truncated, snapshotId, roundIndex,
                roundIndex,
                isHit(contrastStatus) ? roundIndex : 0,
                isHit(contrastStatus) ? 1 : 0);
    }

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
        snapshotId = snapshotId == null ? "" : snapshotId;
        if (roundIndex < 0) throw new IllegalArgumentException("roundIndex must not be negative");
        if (firstSeenRound < 0) throw new IllegalArgumentException("firstSeenRound must not be negative");
        if (lastHitRound < 0) throw new IllegalArgumentException("lastHitRound must not be negative");
        if (hitCount < 0) throw new IllegalArgumentException("hitCount must not be negative");
    }

    public boolean hasTaintPath() {
        return taintPathId != null && !taintPathId.isBlank();
    }

    public boolean isStaticOnly() {
        return contrastStatus == ContrastStatus.STATIC_ONLY;
    }

    private static boolean isHit(ContrastStatus status) {
        return status == ContrastStatus.MATCHED
                || status == ContrastStatus.PARTIAL
                || status == ContrastStatus.DYNAMIC_REACHED;
    }
}

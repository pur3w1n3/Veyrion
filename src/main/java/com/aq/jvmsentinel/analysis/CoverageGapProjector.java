package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.ParameterConstraint;
import com.aq.jvmsentinel.model.ParameterSpec;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Projects STATIC_ONLY / uncovered taint steps into bounded CoverageGap hints for PATH_EXPLORATION.
 */
public final class CoverageGapProjector {
    public static final int MAX_GAPS = 16;

    private CoverageGapProjector() {
    }

    public record CoverageGap(
            String taintPathId,
            String uncoveredStep,
            String branchCondition,
            String suggestedTrack,
            String suggestedInput,
            double confidence
    ) {
        public CoverageGap {
            Objects.requireNonNull(taintPathId, "taintPathId");
            uncoveredStep = uncoveredStep == null ? "" : uncoveredStep;
            branchCondition = branchCondition == null ? "" : branchCondition;
            suggestedTrack = suggestedTrack == null || suggestedTrack.isBlank()
                    ? IdentityTrack.ADMIN.name() : suggestedTrack;
            suggestedInput = suggestedInput == null ? "" : suggestedInput;
            if (!Double.isFinite(confidence) || confidence < 0 || confidence > 1) {
                throw new IllegalArgumentException("confidence must be 0..1");
            }
        }
    }

    public static List<CoverageGap> project(
            List<BytecodeFactIndex.TaintPath> taintPaths,
            List<StaticContrastRow> contrastRows,
            List<ApiDtos.EntryDto> entries) {
        List<CoverageGap> gaps = new ArrayList<>();
        List<StaticContrastRow> rows = contrastRows == null ? List.of() : contrastRows;
        for (StaticContrastRow row : rows) {
            if (gaps.size() >= MAX_GAPS) break;
            if (row.contrastStatus() != ContrastStatus.STATIC_ONLY
                    && row.contrastStatus() != ContrastStatus.UNKNOWN) {
                continue;
            }
            String track = suggestTrack(row, entries);
            String condition = row.stopReason() == null || row.stopReason().isBlank()
                    ? "unreached dynamic join" : row.stopReason();
            gaps.add(new CoverageGap(
                    row.taintPathId().isBlank() ? "tp-" + row.sinkId() : row.taintPathId(),
                    row.sinkId() + " #" + row.category(),
                    condition,
                    track,
                    suggestInput(entries, track),
                    0.55));
        }
        if (gaps.isEmpty() && taintPaths != null) {
            for (BytecodeFactIndex.TaintPath path : taintPaths) {
                if (gaps.size() >= MAX_GAPS) break;
                gaps.add(new CoverageGap(
                        path.id(),
                        path.sourceOwner() + "#" + path.sourceMethod()
                                + " → " + path.sinkOwner() + "#" + path.sinkMethod(),
                        "STATIC_ONLY taint path without dynamic coverage",
                        IdentityTrack.ADMIN.name(),
                        suggestInput(entries, IdentityTrack.ADMIN.name()),
                        0.5));
            }
        }
        return List.copyOf(gaps);
    }

    private static String suggestTrack(StaticContrastRow row, List<ApiDtos.EntryDto> entries) {
        String blob = (row.category() + " " + row.stopReason()).toLowerCase(Locale.ROOT);
        if (blob.contains("admin") || blob.contains("role")) return IdentityTrack.ADMIN.name();
        if (entries != null) {
            for (ApiDtos.EntryDto entry : entries) {
                if (row.entryRefs().stream().anyMatch(ref -> ref.contains(entry.id()))) {
                    boolean auth = entry.preconditions().stream().anyMatch(pre ->
                            pre != null && pre.toUpperCase(Locale.ROOT).contains("ROLE="));
                    if (auth) return IdentityTrack.ADMIN.name();
                }
            }
        }
        return IdentityTrack.USER.name();
    }

    private static String suggestInput(List<ApiDtos.EntryDto> entries, String track) {
        if (entries == null || entries.isEmpty()) return "id=1";
        for (ApiDtos.EntryDto entry : entries) {
            if (entry.parameters() == null || entry.parameters().isEmpty()) continue;
            ParameterSpec spec = ParameterSpec.fromLegacy(entry.parameters().get(0));
            String value = "ADMIN".equals(track) ? "1" : "synthetic";
            for (var constraint : spec.constraints()) {
                if (constraint.type() == ParameterConstraint.ConstraintType.EQUALS
                        && !constraint.literal().isBlank()) {
                    value = constraint.literal();
                    break;
                }
            }
            return spec.name() + "=" + value;
        }
        return "id=1";
    }
}

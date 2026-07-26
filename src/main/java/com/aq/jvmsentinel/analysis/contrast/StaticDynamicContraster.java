package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Joins static contrast rows to PathRuns by {@code entryRef × track}.
 *
 * <p>All-401 / AUTH_CHALLENGE PathRuns yield {@link ContrastStatus#STATIC_ONLY} —
 * never MATCHED and never a bypass-confirmed claim.
 */
public final class StaticDynamicContraster {
    public static final String STOP_AUTH_CHALLENGE_ONLY = "PATHRUN_AUTH_CHALLENGE_ONLY";
    public static final String STOP_NO_PATHRUN = "NO_PATHRUN_FOR_ENTRY";
    public static final String STOP_PASS_GATE = "PATHRUN_PASS_GATE";
    public static final String STOP_PARTIAL_BIND = "PATHRUN_PARTIAL_BIND";
    public static final String STOP_DYNAMIC_ONLY = "DYNAMIC_ONLY_NO_STATIC_SINK";

    public record Result(List<StaticContrastRow> rows, int staticOnlyCount, int matchedCount,
                         int partialCount, int dynamicOnlyCount, boolean truncated) {
        public Result {
            rows = List.copyOf(rows == null ? List.of() : rows);
        }
    }

    public Result join(List<StaticContrastRow> staticRows, List<ApiDtos.PathRunDto> pathRuns) {
        List<StaticContrastRow> projected = staticRows == null ? List.of() : staticRows;
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;

        Map<String, List<ApiDtos.PathRunDto>> byEntry = new LinkedHashMap<>();
        for (ApiDtos.PathRunDto run : runs) {
            String entryRef = normalizeEntryRef(run.entrypointRef());
            byEntry.computeIfAbsent(entryRef, ignored -> new ArrayList<>()).add(run);
        }

        List<StaticContrastRow> out = new ArrayList<>();
        Set<String> consumedPathRuns = new LinkedHashSet<>();
        int staticOnly = 0;
        int matched = 0;
        int partial = 0;
        boolean truncated = false;

        for (StaticContrastRow row : projected) {
            if (row.truncated()) truncated = true;
            List<ApiDtos.PathRunDto> related = new ArrayList<>();
            for (String entryRef : row.entryRefs()) {
                List<ApiDtos.PathRunDto> forEntry = byEntry.getOrDefault(normalizeEntryRef(entryRef), List.of());
                related.addAll(forEntry);
            }
            ContrastDecision decision = classify(related);
            for (ApiDtos.PathRunDto run : related) {
                consumedPathRuns.add(run.pathRunId());
            }
            String track = decision.preferredTrack();
            StaticContrastRow joined = new StaticContrastRow(
                    row.rowId(),
                    row.sinkId(),
                    row.category(),
                    row.sinkSymbol(),
                    row.entryRefs(),
                    row.taintPathId(),
                    track,
                    decision.status(),
                    decision.pathRunRefs(),
                    decision.stopReason(),
                    row.truncated());
            out.add(joined);
            switch (decision.status()) {
                case STATIC_ONLY -> staticOnly++;
                case MATCHED -> matched++;
                case PARTIAL -> partial++;
                default -> { }
            }
        }

        int dynamicOnly = 0;
        for (ApiDtos.PathRunDto run : runs) {
            if (consumedPathRuns.contains(run.pathRunId())) continue;
            if (out.size() >= StaticContrastProjector.MAX_ROWS) {
                truncated = true;
                break;
            }
            dynamicOnly++;
            out.add(new StaticContrastRow(
                    "contrast-dyn-" + (dynamicOnly),
                    "",
                    "DYNAMIC",
                    run.method() + " " + run.entrypointRef(),
                    List.of(normalizeEntryRef(run.entrypointRef())),
                    "",
                    run.track() == null ? "" : run.track(),
                    ContrastStatus.DYNAMIC_ONLY,
                    List.of(run.pathRunId()),
                    STOP_DYNAMIC_ONLY,
                    truncated));
        }

        return new Result(out, staticOnly, matched, partial, dynamicOnly, truncated);
    }

    /**
     * STATIC_ONLY / unmatched rows must never be narrated as bypassed/confirmed.
     * Returns true when text claims a confirmed bypass for a STATIC_ONLY context.
     */
    public static boolean claimsBypassConfirmed(String text) {
        if (text == null || text.isBlank()) return false;
        String lower = text.toLowerCase(Locale.ROOT);
        boolean claimsBypass = lower.contains("已绕过") || lower.contains("bypass confirmed")
                || lower.contains("已确认绕过") || lower.contains("confirmed bypass");
        boolean staticOnlyContext = lower.contains("static_only") || lower.contains("静态未")
                || lower.contains("auth_challenge") || lower.contains("401");
        return claimsBypass && staticOnlyContext;
    }

    private static ContrastDecision classify(List<ApiDtos.PathRunDto> related) {
        if (related == null || related.isEmpty()) {
            return new ContrastDecision(ContrastStatus.STATIC_ONLY, List.of(), "", STOP_NO_PATHRUN);
        }
        List<String> refs = new ArrayList<>();
        boolean anyPassGate = false;
        boolean anyChallenge = false;
        boolean anyPartial = false;
        String preferredTrack = "";
        for (ApiDtos.PathRunDto run : related) {
            refs.add(run.pathRunId());
            if (preferredTrack.isBlank() && run.track() != null) preferredTrack = run.track();
            if (isAuthChallenge(run)) {
                anyChallenge = true;
                continue;
            }
            if (isPassGate(run)) {
                anyPassGate = true;
                if (Boolean.TRUE.equals(run.entryHit())
                        && (run.parameterBound() == null
                        || Boolean.TRUE.equals(run.parameterBound()))) {
                    // Stronger match — keep scanning for completeness.
                } else {
                    anyPartial = true;
                }
            } else {
                anyPartial = true;
            }
        }
        if (anyPassGate && !anyPartial) {
            return new ContrastDecision(ContrastStatus.MATCHED, refs, preferredTrack, STOP_PASS_GATE);
        }
        if (anyPassGate) {
            return new ContrastDecision(ContrastStatus.PARTIAL, refs, preferredTrack, STOP_PARTIAL_BIND);
        }
        if (anyChallenge) {
            // All 401 / AUTH_CHALLENGE — static candidate remains unconfirmed.
            return new ContrastDecision(ContrastStatus.STATIC_ONLY, refs, preferredTrack,
                    STOP_AUTH_CHALLENGE_ONLY);
        }
        return new ContrastDecision(ContrastStatus.PARTIAL, refs, preferredTrack, STOP_PARTIAL_BIND);
    }

    static boolean isAuthChallenge(ApiDtos.PathRunDto run) {
        if (run == null) return false;
        String outcome = run.outcomeClass() == null ? "" : run.outcomeClass().toUpperCase(Locale.ROOT);
        if ("AUTH_CHALLENGE".equals(outcome)) return true;
        int status = run.httpStatus();
        return status == 401 || status == 403;
    }

    static boolean isPassGate(ApiDtos.PathRunDto run) {
        if (run == null) return false;
        if (isAuthChallenge(run)) return false;
        int status = run.httpStatus();
        return status >= 200 && status < 400;
    }

    static String normalizeEntryRef(String ref) {
        if (ref == null || ref.isBlank()) return "";
        String trimmed = ref.trim();
        if (trimmed.startsWith("entry:")) return trimmed;
        if (trimmed.startsWith("entry-")) return "entry:" + trimmed;
        return "entry:" + trimmed;
    }

    private record ContrastDecision(ContrastStatus status, List<String> pathRunRefs,
                                    String preferredTrack, String stopReason) {
        private ContrastDecision {
            pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
            preferredTrack = preferredTrack == null ? "" : preferredTrack;
            stopReason = stopReason == null ? "" : stopReason;
        }
    }
}

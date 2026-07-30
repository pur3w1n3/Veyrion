package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
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
 * 按 {@code entryRef × track} 将 static contrast 行 join PathRun。
 *
 * <p>Entry refs are joined through {@link EntryRefResolver} aliases so
 * {@code entry:entry-ann-*} rows match PathRuns keyed as {@code entry:METHOD:/route}.
 *
 * <p>All-401 / AUTH_CHALLENGE PathRuns yield {@link ContrastStatus#STATIC_ONLY} —
 * 永非 MATCHED，永非 bypass-confirmed 声称。
 */
public final class StaticDynamicContraster {
    public static final String STOP_AUTH_CHALLENGE_ONLY = "PATHRUN_AUTH_CHALLENGE_ONLY";
    public static final String STOP_NO_PATHRUN = "NO_PATHRUN_FOR_ENTRY";
    public static final String STOP_PASS_GATE = "PATHRUN_PASS_GATE";
    public static final String STOP_PARTIAL_BIND = "PATHRUN_PARTIAL_BIND";
    public static final String STOP_DYNAMIC_ONLY = "DYNAMIC_ONLY_NO_STATIC_SINK";

    public record Result(List<StaticContrastRow> rows, int staticOnlyCount, int matchedCount,
                         int partialCount, int dynamicReachedCount,
                         int dynamicOnlyCount, boolean truncated) {
        public Result {
            rows = List.copyOf(rows == null ? List.of() : rows);
        }
    }

    public Result join(List<StaticContrastRow> staticRows, List<ApiDtos.PathRunDto> pathRuns) {
        return join(staticRows, pathRuns, List.of(), "", 0, List.of());
    }

    public Result join(
            List<StaticContrastRow> staticRows,
            List<ApiDtos.PathRunDto> pathRuns,
            List<TaintPathCoverageJoiner.StatusUpgrade> coverageUpgrades,
            String snapshotId,
            int roundIndex) {
        return join(staticRows, pathRuns, coverageUpgrades, snapshotId, roundIndex, List.of());
    }

    public Result join(
            List<StaticContrastRow> staticRows,
            List<ApiDtos.PathRunDto> pathRuns,
            List<TaintPathCoverageJoiner.StatusUpgrade> coverageUpgrades,
            String snapshotId,
            int roundIndex,
            List<ApiDtos.EntryDto> entries) {
        List<StaticContrastRow> projected = staticRows == null ? List.of() : staticRows;
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;
        List<ApiDtos.EntryDto> catalog = entries == null ? List.of() : entries;
        Map<String, TaintPathCoverageJoiner.StatusUpgrade> upgrades = new LinkedHashMap<>();
        if (coverageUpgrades != null) {
            for (TaintPathCoverageJoiner.StatusUpgrade upgrade : coverageUpgrades) {
                upgrades.putIfAbsent(upgrade.taintPathId(), upgrade);
            }
        }

        Map<String, List<ApiDtos.PathRunDto>> byEntry = new LinkedHashMap<>();
        for (ApiDtos.PathRunDto run : runs) {
            for (String key : EntryRefResolver.joinKeys(catalog, run.entrypointRef())) {
                byEntry.computeIfAbsent(key, ignored -> new ArrayList<>()).add(run);
            }
        }

        List<StaticContrastRow> out = new ArrayList<>();
        Set<String> consumedPathRuns = new LinkedHashSet<>();
        int staticOnly = 0;
        int matched = 0;
        int partial = 0;
        int dynamicReached = 0;
        boolean truncated = false;

        for (StaticContrastRow row : projected) {
            if (row.truncated()) truncated = true;
            LinkedHashMap<String, ApiDtos.PathRunDto> relatedById = new LinkedHashMap<>();
            for (String entryRef : row.entryRefs()) {
                for (String key : EntryRefResolver.joinKeys(catalog, entryRef)) {
                    for (ApiDtos.PathRunDto run : byEntry.getOrDefault(key, List.of())) {
                        relatedById.putIfAbsent(run.pathRunId(), run);
                    }
                }
            }
            List<ApiDtos.PathRunDto> related = List.copyOf(relatedById.values());
            ContrastDecision decision = classify(related);
            for (ApiDtos.PathRunDto run : related) {
                consumedPathRuns.add(run.pathRunId());
            }
            TaintPathCoverageJoiner.StatusUpgrade upgrade = upgrades.get(row.taintPathId());
            ContrastStatus status = upgrade == null ? decision.status() : upgrade.status();
            List<String> pathRunRefs = upgrade == null
                    ? decision.pathRunRefs()
                    : mergeRefs(decision.pathRunRefs(), upgrade.pathRunRefs());
            String stopReason = upgrade == null ? decision.stopReason() : upgrade.stopReason();
            for (String ref : pathRunRefs) consumedPathRuns.add(ref);
            String track = decision.preferredTrack();
            StaticContrastRow joined = new StaticContrastRow(
                    row.rowId(),
                    row.sinkId(),
                    row.category(),
                    row.sinkSymbol(),
                    row.entryRefs(),
                    row.taintPathId(),
                    track,
                    status,
                    pathRunRefs,
                    stopReason,
                    row.truncated(),
                    snapshotId,
                    roundIndex);
            out.add(joined);
            switch (status) {
                case STATIC_ONLY -> staticOnly++;
                case MATCHED -> matched++;
                case PARTIAL -> partial++;
                case DYNAMIC_REACHED -> dynamicReached++;
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
                    truncated,
                    snapshotId,
                    roundIndex));
        }

        return new Result(out, staticOnly, matched, partial, dynamicReached, dynamicOnly, truncated);
    }

    private static List<String> mergeRefs(List<String> first, List<String> second) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        if (first != null) merged.addAll(first);
        if (second != null) merged.addAll(second);
        return List.copyOf(merged);
    }

    /**
     * STATIC_ONLY/unmatched 行永不得叙述为 bypassed/confirmed。
     * 文本对 STATIC_ONLY 上下文声称 confirmed bypass 时返回 true。
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
                    // 更强 match — 继续扫描以求完整。
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
            // 全部 401 / AUTH_CHALLENGE — 静态候选仍 unconfirmed。
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
        return EntryRefResolver.normalizeJoinRef(ref);
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

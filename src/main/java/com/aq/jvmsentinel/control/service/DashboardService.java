package com.aq.jvmsentinel.control.service;

import com.aq.jvmsentinel.analysis.CandidateRanker;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.contrast.LedgerDiff;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 聚合 dashboard contrast / ranking / ledger-diff 视图（Step 4）。 */
public final class DashboardService {
    private DashboardService() {
    }

    public static Map<String, Object> emptyProjectDashboard(String projectId) {
        Map<String, Object> empty = new LinkedHashMap<>();
        empty.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        empty.put("projectId", projectId);
        empty.put("artifactDigest", "unscanned");
        empty.put("scanId", "unscanned");
        empty.put("verificationStatus", "UNREACHED");
        empty.put("dependencyMode", ApiDtos.MOCK);
        empty.put("evidenceRefs", List.of());
        empty.put("entries", List.of());
        empty.put("findings", List.of());
        empty.put("paths", List.of());
        empty.put("pathRuns", List.of());
        empty.put("path", List.of());
        empty.put("sqlExperimentCards", List.of());
        empty.put("experimentPlans", List.of());
        empty.put("experimentShapes", List.of());
        empty.put("analysisPacks", List.of());
        empty.put("probeBudget", Map.of(
                "maxProbes", 0, "plannedProbes", 0, "unreachedEntries", 0,
                "strategy", "", "entryTrackPlans", List.of()));
        empty.put("rankedSinks", List.of());
        empty.put("ledgerDiff", Map.of(
                "newlyMatched", List.of(), "regressions", List.of(),
                "unchangedCount", 0, "coverageDelta", 0f, "summary", ""));
        empty.put("verifiedFindings", List.of());
        return empty;
    }

    public static List<Object> rankedSinkMaps(
            List<ApiDtos.SinkDto> sinks,
            List<BytecodeFactIndex.TaintPath> taintPaths,
            List<ApiDtos.EntryDto> entries,
            List<StaticContrastRow> rows) {
        List<CandidateRanker.RankedSinkView> ranked = CandidateRanker.rank(
                sinks, taintPaths, entries, rows);
        List<Object> rankedMaps = new ArrayList<>();
        for (CandidateRanker.RankedSinkView view : ranked) {
            if (rankedMaps.size() >= 20) break;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sinkId", view.sinkId());
            row.put("rank", view.rank());
            row.put("score", view.score());
            row.put("category", view.category());
            row.put("symbol", view.symbol());
            row.put("rankReasons", view.rankReasons());
            rankedMaps.add(row);
        }
        return rankedMaps;
    }

    public static Map<String, Object> ledgerDiffMap(
            ContrastLedger.Ledger previous, ContrastLedger.Ledger current) {
        LedgerDiff.LedgerDiffResult diff = LedgerDiff.diff(previous, current);
        Map<String, Object> ledgerDiffMap = new LinkedHashMap<>();
        ledgerDiffMap.put("newlyMatched", diff.newlyMatched());
        ledgerDiffMap.put("regressions", diff.regressions());
        ledgerDiffMap.put("unchangedCount", diff.unchangedCount());
        ledgerDiffMap.put("coverageDelta", diff.coverageDelta());
        ledgerDiffMap.put("summary", LedgerDiff.formatSummary(diff, true));
        return ledgerDiffMap;
    }
}

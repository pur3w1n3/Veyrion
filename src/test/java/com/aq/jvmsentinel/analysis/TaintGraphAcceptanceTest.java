package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.contrast.LedgerDiff;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/** MVP-3 acceptance: TaintGraph projection, LedgerDiff, DynamicFeedbackApplier. */
public final class TaintGraphAcceptanceTest {
    public static void main(String[] args) {
        taintGraphHasAtLeastThreeNodes();
        ledgerDiffNewlyMatched();
        dynamicFeedbackUpgrades();
        System.out.println("TaintGraphAcceptanceTest: PASS");
    }

    private static void taintGraphHasAtLeastThreeNodes() {
        BytecodeFactIndex.TaintPath path = new BytecodeFactIndex.TaintPath(
                "tp-1", "com.Example", "entry", "(Ljava/lang/String;)V", 0,
                "com.Example", "sink", "(Ljava/lang/String;)V", "SQL",
                List.of(
                        new BytecodeFactIndex.TaintStep(
                                "TRANSFORM", "com.Example#bridge", "DIRECT",
                                "e1", "bridge"),
                        new BytecodeFactIndex.TaintStep(
                                "TRANSFORM", "com.Example#dao", "DIRECT",
                                "e2", "dao")),
                "STATIC_INFERRED");
        TaintGraph graph = TaintGraphProjector.project(List.of(path));
        check(graph.nodes().size() >= 3, "taint graph nodes >= 3, got " + graph.nodes().size());
        check(!graph.edges().isEmpty(), "taint graph has edges");
        TaintGraph sub = TaintGraphProjector.subgraph(graph, "sink");
        check(!sub.nodes().isEmpty(), "subgraph by sink keeps nodes");
        check(new BytecodeFactIndex(List.of(), List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(path), BytecodeFactIndex.AnalysisCoverage.empty())
                .taintGraph().nodes().size() >= 3, "BytecodeFactIndex.taintGraph()");
    }

    private static void ledgerDiffNewlyMatched() {
        StaticContrastRow prior = new StaticContrastRow(
                "row-1", "sink-1", "SQL", "com.Example#sink",
                List.of("entry:e1"), "tp-1", "UNAUTH", ContrastStatus.STATIC_ONLY,
                List.of(), "NO_PATHRUN", false, "snap-0", 0);
        StaticContrastRow current = new StaticContrastRow(
                "row-1", "sink-1", "SQL", "com.Example#sink",
                List.of("entry:e1"), "tp-1", "UNAUTH", ContrastStatus.DYNAMIC_REACHED,
                List.of("pr-1"), "BRANCH_HIT", false, "snap-1", 1);
        LedgerDiff.LedgerDiffResult diff = LedgerDiff.diff(
                new ContrastLedger.Ledger(List.of(prior), 1, false, "", "snap-0", 0),
                new ContrastLedger.Ledger(List.of(current), 0, false, "", "snap-1", 1));
        check(!diff.newlyMatched().isEmpty(), "newlyMatched non-empty");
        check(diff.coverageDelta() > 0, "coverageDelta positive");
        check(LedgerDiff.formatSummary(diff, true).contains("LEDGER_DIFF_SUMMARY"),
                "summary marker");
    }

    private static void dynamicFeedbackUpgrades() {
        ApiDtos.PathRunDto run = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-fb-1", "scan-1", "entry:e1", "UNAUTH",
                "attempt-0", null, "GET", "application/json", "q=1", "PASS",
                200, true, true,
                List.of(new ApiDtos.SqlEventDto("SELECT 1", "?", "READ", false, false, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of(), "MOCK", "",
                Map.of());
        DynamicFeedbackApplier.FeedbackResult result = DynamicFeedbackApplier.apply(
                "p", "d".repeat(64), "scan-1", List.of(run), "2026-07-27T00:00:00Z");
        check(result.upgradedCount() == 1, "one PathRun upgraded");
        check(result.evidence().size() == 1, "one evidence row");
        check(result.evidence().get(0).source().startsWith(DynamicFeedbackApplier.EVIDENCE_KIND),
                "DYNAMIC_TAINT_UPDATE evidence");
        AtomicBoolean noVerified = new AtomicBoolean(true);
        for (ApiDtos.EvidenceDto ev : result.evidence()) {
            if ("VERIFIED".equals(ev.verificationStatus())) noVerified.set(false);
        }
        check(noVerified.get(), "feedback must not claim VERIFIED");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

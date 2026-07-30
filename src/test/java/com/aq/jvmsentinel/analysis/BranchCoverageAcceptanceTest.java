package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.contrast.TaintPathCoverageJoiner;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.worker.AgentJsonlTraceConverter;
import com.aq.jvmsentinel.worker.TraceProjectionService;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * MVP-1 验收：BRANCH_COVERAGE allowlist、PathRun branchHitMap join、排序、ledger round。
 * 说明：Live Docker JAR coverage 经 VEYRION_TEST_ARTIFACT_JAR 仍可选（此处不要求）。
 */
public final class BranchCoverageAcceptanceTest {
    public static void main(String[] args) {
        converterAcceptsBranchCoverage();
        branchHitsJoinToDynamicReached();
        rankingAndLedgerRound();
        System.out.println("BranchCoverageAcceptanceTest: PASS");
    }

    private static void converterAcceptsBranchCoverage() {
        String line = """
                {"schemaVersion":1,"sequence":0,"eventType":"BRANCH_COVERAGE",\
                "provenanceKind":"AGENT_INSTRUMENTED","verificationStatus":"DYNAMIC_SUSPECTED",\
                "class":"com.example.UserController","method":"getUser(Ljava/lang/String;)V",\
                "timestamp":"2026-07-27T00:00:00Z","thread":"main",\
                "detail":{"captureMode":"JVM_BRANCH_SITE","encoding":"COMMA_SEPARATED_HIT_INDICES",\
                "classname":"com.example.UserController","methodDesc":"getUser(Ljava/lang/String;)V",\
                "hits":"0,2"}}
                """.replace("\\\n", "").replace("\n", "");
        AgentJsonlTraceConverter.AgentEvent event = AgentJsonlTraceConverter.parseAcceptedLine(
                line.getBytes(StandardCharsets.UTF_8), line.length(), 0);
        check("BRANCH_COVERAGE".equals(event.eventType()), "converter must allow BRANCH_COVERAGE");
        check("0,2".equals(event.detail().get("hits")), "hits detail preserved");
    }

    private static void branchHitsJoinToDynamicReached() {
        ApiDtos.PathRunDto run = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pathrun-1", "scan-1", "entry:GET:/api/user",
                "UNAUTH", "attempt-0", null, "GET", "application/json",
                "GET /api/user", "REACHED_NO_BIND", 200, true, false, List.of(),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-1"), "MOCK", "",
                Map.of("com.example.UserController#getUser(Ljava/lang/String;)V", List.of(0, 2)));
        BytecodeFactIndex.TaintPath path = new BytecodeFactIndex.TaintPath(
                "tp-001", "com.example.UserController", "getUser", "(Ljava/lang/String;)V", 0,
                "com.example.UserRepository", "findById", "(Ljava/lang/String;)Ljava/lang/Object;",
                "SQL", List.of(), "STATIC_INFERRED");
        List<TaintPathCoverageJoiner.StatusUpgrade> upgrades =
                new TaintPathCoverageJoiner().join(List.of(path), List.of(run));
        check(upgrades.size() == 1, "coverage join must upgrade matching taint path");
        check(upgrades.get(0).status() == ContrastStatus.DYNAMIC_REACHED, "status DYNAMIC_REACHED");
        check(upgrades.get(0).taintPathId().equals("tp-001"), "taint path id preserved");

        AgentJsonlTraceConverter.AgentEvent coverage = new AgentJsonlTraceConverter.AgentEvent(
                1L, "BRANCH_COVERAGE", "AGENT_INSTRUMENTED", "DYNAMIC_SUSPECTED",
                "com.example.UserController", "getUser(Ljava/lang/String;)V",
                "2026-07-27T00:00:00Z", "main",
                Map.of("classname", "com.example.UserController",
                        "methodDesc", "getUser(Ljava/lang/String;)V",
                        "hits", "1,3"));
        ApiDtos.PathRunDto empty = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pathrun-2", "scan-1", "entry:GET:/api/user",
                "UNAUTH", "attempt-1", null, "GET", "application/json",
                "GET /api/user", "REACHED_NO_BIND", 200, true, false, List.of(),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-2"), "MOCK", "");
        ApiDtos.PathRunDto merged = TraceProjectionService.mergeBranchCoverage(empty, coverage);
        check(!merged.branchHitMap().isEmpty(), "mergeBranchCoverage populates branchHitMap");
        check(merged.branchHitMap()
                        .get("com.example.UserController#getUser(Ljava/lang/String;)V")
                        .equals(List.of(1, 3)),
                "decoded hit indices");
    }

    private static void rankingAndLedgerRound() {
        ApiDtos.SinkDto sql = new ApiDtos.SinkDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "s", "sink-sql", "SQL",
                "com.example.UserRepository#findById(Ljava/lang/String;)Ljava/lang/Object;",
                "taint-path=tp-001", "STATIC_INFERRED", 0.78, List.of("ev-a"));
        ApiDtos.SinkDto other = new ApiDtos.SinkDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "s", "sink-file", "FILE",
                "com.example.FileStore#read(Ljava/lang/String;)[B",
                "rule", "STATIC_INFERRED", 0.62, List.of("ev-b"));
        ApiDtos.PathRunDto covered = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pathrun-r1", "s", "entry:GET:/api/user",
                "UNAUTH", "attempt-0", null, "GET", "application/json",
                "GET /api/user", "REACHED_NO_BIND", 200, true, false, List.of(),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of(), "MOCK", "",
                Map.of("com.example.UserRepository#findById(Ljava/lang/String;)Ljava/lang/Object;",
                        List.of(0)));
        ContrastLedger.Ledger ledger = ContrastLedger.build(
                List.of(), List.of(sql, other), Map.of(), List.of(covered));
        check(ledger.roundIndex() >= 1, "coverage observation opens round >= 1");
        check(ledger.snapshotId() != null && !ledger.snapshotId().isBlank(), "snapshotId present");
        check(ledger.rows().stream().anyMatch(row ->
                        row.contrastStatus() == ContrastStatus.DYNAMIC_REACHED
                                || "sink-sql".equals(row.sinkId())),
                "ledger includes sink/coverage join rows");

        List<CandidateRanker.RankedSinkView> ranked = CandidateRanker.rank(
                List.of(sql, other), ContrastLedger.taintPathsFromSinks(List.of(sql, other)),
                List.of(), ledger.rows());
        check(ranked.size() == 2, "both sinks ranked");
        check("sink-sql".equals(ranked.get(0).sinkId()), "SQL high-risk+taint ranks first");
        check(ranked.get(0).rankReasons().stream().anyMatch(r -> r.contains("highRisk")),
                "rankReason includes highRisk");
        check(ranked.get(0).score() > ranked.get(1).score(), "score ordering");
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}

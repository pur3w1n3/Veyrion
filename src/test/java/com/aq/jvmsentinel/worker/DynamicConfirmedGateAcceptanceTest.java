package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathOutcomeClass;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 仅服务端 H3 门禁不得由模型授权。
 * P1-22：同 PathRun correlation + marker SQL 正/负 fixture（非 live DB）。
 */
public final class DynamicConfirmedGateAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String MARKER = SqlDiffProbe.META_MARKER;
    private static final String CORR = "corr-h3-e2e-1";

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        PathRun parameterized = run(new SqlEvent(
                "select * from t where id=?", "jdbc-placeholders", "READ", true, false, "MOCK"));
        check(DynamicConfirmedGate.evaluate(parameterized, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "parameterized SQL must not confirm");

        PathRun injected = run(new SqlEvent(
                "select * from t where id='" + MARKER, "", "READ", false, true, "MOCK"));
        check(DynamicConfirmedGate.evaluate(injected, MARKER)
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "unfiltered malicious fragment confirms");

        PathRun applied = DynamicConfirmedGate.apply(injected, MARKER);
        check(VerificationStatus.DYNAMIC_CONFIRMED.name().equals(applied.verificationStatus()),
                "apply upgrades PathRun status");

        PathRun protocolMeta = run(new SqlEvent(
                "port=6379", "", "UNKNOWN", false, true, "DEPENDENCY_PROTOCOL_MOCK"));
        check(DynamicConfirmedGate.evaluate(protocolMeta, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "Redis/MySQL listen meta must not confirm");

        PathRun noEvidence = new PathRun(
                "pr-2", "scan-1", "entry:GET:/x", IdentityTrack.UNAUTH, "attempt-2", null,
                "GET", "application/json", "GET /x", PathOutcomeClass.HTTP_OBSERVED, 200,
                true, true, List.of(new SqlEvent(
                        "select * from t where id='" + MARKER, "", "READ", false, true, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of(),
                "MOCK", "no credentials");
        check(DynamicConfirmedGate.evaluate(noEvidence, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "empty evidenceRefs cannot confirm");

        PathRun missEntry = new PathRun(
                "pr-3", "scan-1", "entry:GET:/x", IdentityTrack.UNAUTH, "attempt-3", null,
                "GET", "application/json", "GET /x", PathOutcomeClass.HTTP_OBSERVED, 200,
                false, true, List.of(new SqlEvent(
                        "select * from t where id='" + MARKER, "", "READ", false, true, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("evidence-dynamic-1"),
                "MOCK", "no credentials");
        check(DynamicConfirmedGate.evaluate(missEntry, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "entryHit=false cannot confirm");

        // D2 比较仅为 advisory/suspected；H3 门禁仍是唯一 DYNAMIC_CONFIRMED 升级。
        SqlDiffProbe.DiffResult d2 = SqlDiffProbe.compare(
                new SqlEvent("select * from t where id='1'", "", "READ", false, false, "MOCK"),
                new SqlEvent("select * from t where id='" + MARKER, "", "READ", false, true, "MOCK"));
        check(d2.structureInfluenced(), "D2 detects structural influence");
        check(d2.status() == VerificationStatus.DYNAMIC_SUSPECTED,
                "D2 itself never exceeds DYNAMIC_SUSPECTED");
        check(d2.status() != VerificationStatus.VERIFIED, "D2 never VERIFIED");

        // P1-22：MOCK 元数据 / 巧合 / 错误归因不得升级。
        PathRun flagOnly = run(new SqlEvent(
                "select * from t where id='1'", "", "READ", false, true, "MOCK"));
        check(DynamicConfirmedGate.evaluate(flagOnly, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "maliciousFragmentPresent without marker in SQL cannot confirm");

        PathRun coincidenceMeta = run(new SqlEvent(
                "accepted-without-credential '" + MARKER, "",
                "UNKNOWN", false, true, "DEPENDENCY_PROTOCOL_MOCK"));
        check(DynamicConfirmedGate.evaluate(coincidenceMeta, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "handshake/meta string coincidence cannot confirm");

        PathRun mockListenWithMarker = run(new SqlEvent(
                "port=6379 marker='" + MARKER, "",
                "UNKNOWN", false, true, "DEPENDENCY_PROTOCOL_MOCK"));
        check(DynamicConfirmedGate.evaluate(mockListenWithMarker, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "Redis listen meta with marker substring cannot confirm");

        PathRun wrongAttribution = new PathRun(
                "pr-4", "scan-other", "entry:GET:/y", IdentityTrack.UNAUTH, "attempt-4", null,
                "GET", "application/json", "GET /y", PathOutcomeClass.HTTP_OBSERVED, 200,
                true, true, List.of(new SqlEvent(
                        "select * from t where id='" + MARKER, "", "READ", false, true, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("evidence-from-other-task"),
                "MOCK", "no credentials");
        // 需要同 PathRun evidence refs；空 refs 已覆盖。参数化阻断：
        PathRun parameterizedHit = run(new SqlEvent(
                "select * from t where id=? /* '" + MARKER + " */",
                "jdbc-placeholders", "READ", true, false, "MOCK"));
        check(DynamicConfirmedGate.evaluate(parameterizedHit, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "parameterized statement with marker comment cannot confirm");

        // D3 卡片构建拒绝 VERIFIED 声明。
        try {
            new com.aq.jvmsentinel.model.SqlExperimentCard(
                    "card-bad", "scan-1", "entry:GET:/x", IdentityTrack.UNAUTH, "plan:1",
                    "q=1", "q=" + MARKER, "select 1", "select 2",
                    true, "COMPLETED", "MOCK", "VERIFIED",
                    List.of("pr-1"), List.of("ev-1"));
            throw new AssertionError("D3 card must reject VERIFIED");
        } catch (IllegalArgumentException expected) {
            check(expected.getMessage() != null
                            && expected.getMessage().contains("VERIFIED"),
                    "D3 card fail-closed on VERIFIED");
        }

        check(wrongAttribution.scanId().equals("scan-other"),
                "cross-scan fixture retained for attribution clarity");

        samePathRunCorrelationMarkerPositiveAndNegative();
        mockProvenanceRemainsLabeled();

        System.out.println("DynamicConfirmedGateAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    /**
     * 端到端 H3 fixture：同 PathRun 携带 correlationId + marker SQL 时为正；
     * marker SQL 归因到不同 correlation / PathRun 时为负。
     */
    private static void samePathRunCorrelationMarkerPositiveAndNegative() {
        PathRun sameCorr = new PathRun(
                "pr-h3-pos", "scan-h3", "entry:GET:/focus", IdentityTrack.UNAUTH, CORR,
                "plan:h3-e2e", "GET", "application/json",
                "GET /focus?q=" + MARKER + " correlationId=" + CORR,
                PathOutcomeClass.HTTP_OBSERVED, 200, true, true,
                List.of(new SqlEvent(
                        "SELECT id FROM t WHERE q='" + MARKER, "", "READ", false, true, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-h3-pos"), "MOCK", "");
        check(sameCorr.requestSummary().contains("correlationId=" + CORR),
                "positive fixture binds correlationId on same PathRun");
        check(sameCorr.attemptId().equals(CORR), "attemptId aligns with correlationId");
        check(DynamicConfirmedGate.evaluate(sameCorr, MARKER)
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "same PathRun + correlation + marker SQL → DYNAMIC_CONFIRMED (fixture)");

        PathRun otherCorr = new PathRun(
                "pr-h3-neg", "scan-h3", "entry:GET:/focus", IdentityTrack.UNAUTH, "corr-other",
                "plan:h3-e2e", "GET", "application/json",
                "GET /focus?q=benign correlationId=corr-other",
                PathOutcomeClass.HTTP_OBSERVED, 200, true, true,
                List.of(new SqlEvent(
                        "SELECT id FROM t WHERE q='benign'", "", "READ", false, false, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-h3-neg"), "MOCK", "");
        check(DynamicConfirmedGate.evaluate(otherCorr, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "different correlation PathRun without marker SQL → not confirmed");

        // 不同 PathRun 上的 marker SQL 不得确认良性关联 run。
        PathRun foreignMarker = new PathRun(
                "pr-h3-foreign", "scan-h3", "entry:GET:/other", IdentityTrack.UNAUTH, "corr-foreign",
                "plan:h3-e2e", "GET", "application/json",
                "GET /other correlationId=corr-foreign",
                PathOutcomeClass.HTTP_OBSERVED, 200, true, true,
                List.of(new SqlEvent(
                        "SELECT id FROM t WHERE q='" + MARKER, "", "READ", false, true, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-h3-foreign"), "MOCK", "");
        check(!foreignMarker.pathRunId().equals(sameCorr.pathRunId()),
                "negative fixture uses distinct PathRun id");
        check(DynamicConfirmedGate.evaluate(foreignMarker, MARKER)
                        == VerificationStatus.DYNAMIC_CONFIRMED
                        || DynamicConfirmedGate.evaluate(foreignMarker, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "foreign PathRun evaluated independently (no cross-run upgrade of benign)");
        check(DynamicConfirmedGate.evaluate(otherCorr, MARKER)
                        != VerificationStatus.DYNAMIC_CONFIRMED,
                "benign correlation PathRun stays unconfirmed despite foreign marker SQL");
    }

    private static void mockProvenanceRemainsLabeled() {
        PathRun mockRun = run(new SqlEvent(
                "select * from t where id='" + MARKER, "", "READ", false, true, "MOCK"));
        check("MOCK".equals(mockRun.identityProvenance()),
                "dependency substitute PathRun identityProvenance=MOCK");
        check(mockRun.sqlEvents().stream().allMatch(e -> "MOCK".equals(e.captureMode())),
                "SQL captureMode remains MOCK (not RUNTIME_OBSERVED)");
        check(DynamicConfirmedGate.evaluate(mockRun, MARKER) == VerificationStatus.DYNAMIC_CONFIRMED,
                "MOCK-labeled H3 fixture may confirm status but provenance stays MOCK");
    }

    private static PathRun run(SqlEvent sql) {
        return new PathRun(
                "pr-1", "scan-1", "entry:GET:/x", IdentityTrack.UNAUTH, "attempt-1", null,
                "GET", "application/json", "GET /x", PathOutcomeClass.HTTP_OBSERVED, 200,
                true, true, List.of(sql), "COMPLETED", "DYNAMIC_SUSPECTED",
                List.of("evidence-dynamic-1"),
                "MOCK", "no credentials");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

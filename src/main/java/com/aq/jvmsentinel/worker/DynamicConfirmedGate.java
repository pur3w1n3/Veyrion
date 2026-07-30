package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.Locale;
import java.util.Objects;

/**
 * 仅服务端验证门禁。
 *
 * <p>H3（SQL 数据流）：当恶意片段出现在实际 JDBC/mock SQL 且未参数化时，
 * 可将 {@code DYNAMIC_SUSPECTED → DYNAMIC_CONFIRMED} 升级。
 *
 * <p>P2 family fail-closed：Guard / State / Typestate / 其他非 SQL 数据流 family
 * 上限为 {@code DYNAMIC_SUSPECTED}，直至独立 family 审计落地。模型不能调用此升级。
 */
public final class DynamicConfirmedGate {
    private DynamicConfirmedGate() { }

    /**
     * SQL 数据流 H3 路径（默认）。等价于
     * {@link #evaluate(PathRun, String, HypothesisFamily)} 且 {@link HypothesisFamily#DATAFLOW}。
     */
    public static VerificationStatus evaluate(PathRun run, String probeMarker) {
        return evaluate(run, probeMarker, HypothesisFamily.DATAFLOW);
    }

    /**
     * 按 family 评估。非 {@link HypothesisFamily#DATAFLOW} family 永不返回
     * {@link VerificationStatus#DYNAMIC_CONFIRMED}（P2 脚手架 / 未审计）。
     */
    public static VerificationStatus evaluate(PathRun run, String probeMarker,
                                              HypothesisFamily family) {
        Objects.requireNonNull(run, "run");
        HypothesisFamily resolved = family == null ? HypothesisFamily.UNKNOWN : family;
        if (!allowsDynamicConfirmed(resolved)) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        // H3 要求同 PathRun 语句证据 + 可重放 evidence refs（P0-06）。
        if (run.sqlEvents().isEmpty()) return VerificationStatus.DYNAMIC_SUSPECTED;
        if (run.evidenceRefs() == null || run.evidenceRefs().isEmpty()) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        if (Boolean.FALSE.equals(run.entryHit())) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        String marker = probeMarker == null ? "" : probeMarker.trim();
        if (marker.isBlank()) return VerificationStatus.DYNAMIC_SUSPECTED;
        String needle = marker.toLowerCase(Locale.ROOT);
        boolean hit = false;
        boolean parameterizedBlock = false;
        for (SqlEvent event : run.sqlEvents()) {
            // 协议 listen/meta 永不能满足 H3；仅语句文本计数。
            if (!isStatementEvidence(event)) continue;
            // Fail-closed：仅凭 MOCK 元数据标志 / maliciousFragmentPresent 不能升级。
            // H3 要求探针 marker 出现在实际语句 SQL 文本中。
            String sql = event.sqlText() == null ? "" : event.sqlText().toLowerCase(Locale.ROOT);
            if (!sql.contains(needle)) continue;
            hit = true;
            if (event.parameterized()) parameterizedBlock = true;
        }
        if (!hit) return VerificationStatus.DYNAMIC_SUSPECTED;
        if (parameterizedBlock) return VerificationStatus.DYNAMIC_SUSPECTED;
        return VerificationStatus.DYNAMIC_CONFIRMED;
    }

    public static PathRun apply(PathRun run, String probeMarker) {
        return apply(run, probeMarker, HypothesisFamily.DATAFLOW);
    }

    public static PathRun apply(PathRun run, String probeMarker, HypothesisFamily family) {
        VerificationStatus status = evaluate(run, probeMarker, family);
        if (status != VerificationStatus.DYNAMIC_CONFIRMED) return run;
        return new PathRun(
                run.pathRunId(), run.scanId(), run.entrypointRef(), run.track(), run.attemptId(),
                run.experimentPlanId(), run.method(), run.contentType(), run.requestSummary(),
                run.outcomeClass(), run.httpStatus(), run.entryHit(), run.parameterBound(),
                run.sqlEvents(), run.stopReason(), status.name(), run.evidenceRefs(),
                run.identityProvenance(), run.identityPrecondition(), run.branchHitMap());
    }

    /**
     * 为 hypothesis family 钳制提议状态。非 SQL 数据流 family 不能超过
     * {@link VerificationStatus#DYNAMIC_SUSPECTED}；{@code VERIFIED} 全局关闭。
     */
    public static VerificationStatus capForFamily(VerificationStatus proposed,
                                                  HypothesisFamily family) {
        VerificationStatus status = proposed == null
                ? VerificationStatus.DYNAMIC_SUSPECTED : proposed;
        if (status == VerificationStatus.VERIFIED) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        if (status == VerificationStatus.DYNAMIC_CONFIRMED
                && !allowsDynamicConfirmed(family == null ? HypothesisFamily.UNKNOWN : family)) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        return status;
    }

    /**
     * 在独立 Guard/State/Typestate（及其他非 SQL）family 审计完成前，
     * 仅 SQL 数据流 H3 路径可达 {@code DYNAMIC_CONFIRMED}。
     */
    public static boolean allowsDynamicConfirmed(HypothesisFamily family) {
        return family == HypothesisFamily.DATAFLOW;
    }

    private static boolean isStatementEvidence(SqlEvent event) {
        if (event == null) return false;
        String sql = event.sqlText() == null ? "" : event.sqlText().trim();
        if (sql.isBlank()) return false;
        String lower = sql.toLowerCase(Locale.ROOT);
        if (lower.startsWith("port=") || lower.startsWith("sqlclass=")
                || lower.contains("accepted-without-credential")) {
            return false;
        }
        String capture = event.captureMode() == null ? "" : event.captureMode();
        if ("DEPENDENCY_PROTOCOL_MOCK".equals(capture)
                && !(lower.startsWith("select") || lower.startsWith("insert")
                || lower.startsWith("update") || lower.startsWith("delete")
                || lower.startsWith("replace") || lower.contains("?"))) {
            return false;
        }
        return true;
    }
}

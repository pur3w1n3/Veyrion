package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.contrast.LedgerDiff;
import com.aq.jvmsentinel.analysis.experiment.TracePlanCompiler;
import com.aq.jvmsentinel.analysis.experiment.TracePlanObservationDiff;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/** 对照账本、ledger diff 与 TracePlan 对比。 */
public final class ContrastContextBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunContextBuilder pathRuns;

    public ContrastContextBuilder(ControlPlaneStore store, PathRunSource pathRunSource) {
        this(store, new PathRunContextBuilder(store, pathRunSource));
    }

    public ContrastContextBuilder(ControlPlaneStore store, PathRunContextBuilder pathRuns) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRuns = java.util.Objects.requireNonNull(pathRuns, "pathRuns");
    }

    public String ledgerDiffContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null || job.role() != AgentRole.REPORT_GENERATION) return "";
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            List<ApiDtos.PathRunDto> runs = pathRuns.loadPathRuns(job);
            List<BytecodeFactIndex.TaintPath> contrastPaths = StaticFactSnapshot.resolveContrastTaintPaths(
                    store.staticFacts(job.scanId()), scan.dto().sinks());
            ContrastLedger.Ledger current = ContrastLedger.build(
                    scan.dto().entries(), scan.dto().sinks(), scan.evidence(), runs, contrastPaths);
            if (current.roundIndex() <= 0) return "";
            // 合成上一轮 ledger：去掉 branch coverage 以模拟上一轮状态。
            List<ApiDtos.PathRunDto> priorRuns = runs.stream()
                    .map(run -> new ApiDtos.PathRunDto(
                            run.schemaVersion(), run.pathRunId(), run.scanId(), run.entrypointRef(),
                            run.track(), run.attemptId(), run.experimentPlanId(), run.method(),
                            run.contentType(), run.requestSummary(), run.outcomeClass(),
                            run.httpStatus(), run.entryHit(), run.parameterBound(),
                            run.sqlEvents(), run.stopReason(), run.verificationStatus(),
                            run.evidenceRefs(), run.identityProvenance(), run.identityPrecondition(),
                            Map.of()))
                    .toList();
            ContrastLedger.Ledger previous = ContrastLedger.build(
                    scan.dto().entries(), scan.dto().sinks(), scan.evidence(), priorRuns, contrastPaths);
            LedgerDiff.LedgerDiffResult diff = LedgerDiff.diff(previous, current);
            return LedgerDiff.formatSummary(diff, language == AiOutputLanguage.EN);
        } catch (RuntimeException ignored) {
            return "";
        }
    }
    public String contrastLedgerContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null) return "";
        if (job.role() != AgentRole.REPORT_GENERATION
                && job.role() != AgentRole.PATH_EXPLORATION
                && job.role() != AgentRole.VULNERABILITY_TRIAGE) {
            return "";
        }
        ContrastLedger.Ledger ledger = loadContrastLedger(job);
        return ContrastLedger.formatForPrompt(ledger, language == AiOutputLanguage.EN);
    }

    /**
     * PATH/TRIAGE：注入 TracePlan 期望 vs 已观测 PathTrace 缺口，用于探针优先级。
     * 增量注入 — 不替换 PathRun / CONTRAST_LEDGER 上下文。
     */
    public String tracePlanVsActualContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null) {
            return "";
        }
        if (job.role() != AgentRole.PATH_EXPLORATION
                && job.role() != AgentRole.VULNERABILITY_TRIAGE) {
            return "";
        }
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            List<BytecodeFactIndex.TaintPath> taintPaths = StaticFactSnapshot.resolveTaintPaths(
                    store.staticFacts(job.scanId()), scan.dto().sinks());
            List<TracePlan> plans = new ArrayList<>();
            for (SQLiteControlPlanePersistence.TracePlanData row : store.loadTracePlansForScan(
                    job.scanId())) {
                if (row == null || row.payloadJson() == null || row.payloadJson().isBlank()) {
                    continue;
                }
                try {
                    plans.add(TracePlan.fromMap(JsonCodec.parseObject(row.payloadJson())));
                } catch (RuntimeException ignored) {
                    // 跳过格式错误
                }
            }
            if (plans.isEmpty()) {
                for (ApiDtos.EntryDto entry : scan.dto().entries()) {
                    if (entry == null || entry.route() == null || entry.route().isBlank()) {
                        continue;
                    }
                    if (!"HTTP".equalsIgnoreCase(entry.protocol())) {
                        continue;
                    }
                    plans.add(TracePlanCompiler.compileFromStaticIr(
                            entry, scan.dto().sinks(), scan.evidence(), taintPaths, List.of()));
                    if (plans.size() >= AiPromptLimits.MAX_TRACE_PLAN_COMPILE_FOR_PROMPT) {
                        break;
                    }
                }
            }
            List<PathTrace> traces = new ArrayList<>(loadPathTracesByPathRunId(job).values());
            List<TracePlanObservationDiff.Diff> diffs = TracePlanObservationDiff.prioritizeGaps(
                    TracePlanObservationDiff.diffAll(plans, traces));
            // 行数硬顶：缺口优先后只内联少量行，避免撑爆 user text 128KiB。
            return TracePlanObservationDiff.formatForPrompt(
                    diffs, language == AiOutputLanguage.EN,
                    AiPromptLimits.MAX_TRACE_PLAN_DIFF_PROMPT_ROWS);
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    public ContrastLedger.Ledger loadContrastLedger(SQLiteControlPlanePersistence.AiJobData job) {
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            return ContrastLedger.build(
                    scan.dto().entries(),
                    scan.dto().sinks(),
                    scan.evidence(),
                    pathRuns.loadPathRuns(job),
                    StaticFactSnapshot.resolveTaintPaths(
                            store.staticFacts(job.scanId()), scan.dto().sinks()));
        } catch (RuntimeException ignored) {
            return new ContrastLedger.Ledger(List.of(), 0, false, "SCAN_UNAVAILABLE");
        }
    }
    public Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> loadPathTracesByPathRunId(
            SQLiteControlPlanePersistence.AiJobData job) {
        Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> byRun = new LinkedHashMap<>();
        if (job == null || job.scanId() == null) return byRun;
        try {
            for (SQLiteControlPlanePersistence.PathTraceData row : store.loadPathTracesForScan(
                    job.projectId(), job.artifactDigest(), job.scanId())) {
                com.aq.jvmsentinel.domain.pathdebug.PathTrace cached =
                        store.pathTraceForPathRun(row.pathRunId());
                if (cached != null) {
                    byRun.put(row.pathRunId(), cached);
                    continue;
                }
                try {
                    byRun.put(row.pathRunId(),
                            com.aq.jvmsentinel.domain.pathdebug.PathTrace.fromMap(
                                    JsonCodec.parseObject(row.payloadJson())));
                } catch (Exception ignored) {
                    // 跳过格式错误
                }
            }
        } catch (RuntimeException ignored) {
            return byRun;
        }
        return byRun;
    }
}

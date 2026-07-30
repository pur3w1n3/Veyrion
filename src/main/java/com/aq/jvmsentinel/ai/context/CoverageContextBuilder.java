package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.aq.jvmsentinel.analysis.CoverageGapProjector;
import com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import java.util.List;


/** Coverage gap 与 matrix 上下文。 */
public final class CoverageContextBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunSource pathRunSource;

    private final ContrastContextBuilder contrast;



    public CoverageContextBuilder(ControlPlaneStore store, PathRunSource pathRunSource, ContrastContextBuilder contrast) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.contrast = java.util.Objects.requireNonNull(contrast, "contrast");
    }

    public String coverageGapContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null || job.role() != AgentRole.PATH_EXPLORATION) return "";
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            ContrastLedger.Ledger ledger = contrast.loadContrastLedger(job);
            List<CoverageGapProjector.CoverageGap> gaps = CoverageGapProjector.project(
                    StaticFactSnapshot.resolveTaintPaths(
                            store.staticFacts(job.scanId()), scan.dto().sinks()),
                    ledger.rows(), scan.dto().entries());
            StringBuilder block = new StringBuilder();
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "COVERAGE_GAP_FACTS（服务端确定性；对每条 gap 生成 nextExperiment；非 VERIFIED）：\n"
                    : "COVERAGE_GAP_FACTS (deterministic; emit nextExperiment per gap; not VERIFIED):\n");
            if (gaps.isEmpty()) {
                block.append(language == AiOutputLanguage.ZH_CN ? "- （空）\n" : "- (empty)\n");
                return block.toString();
            }
            int emitted = 0;
            for (CoverageGapProjector.CoverageGap gap : gaps) {
                if (emitted >= AiPromptLimits.MAX_COVERAGE_GAP_PROMPT_ROWS) break;
                block.append("- taintPathId=").append(gap.taintPathId())
                        .append(" uncoveredStep=").append(gap.uncoveredStep())
                        .append(" branchCondition=").append(gap.branchCondition())
                        .append(" suggestedTrack=").append(gap.suggestedTrack())
                        .append(" suggestedInput=").append(gap.suggestedInput())
                        .append(" confidence=").append(gap.confidence())
                        .append('\n');
                emitted++;
            }
            if (gaps.size() > AiPromptLimits.MAX_COVERAGE_GAP_PROMPT_ROWS) {
                block.append(language == AiOutputLanguage.ZH_CN
                        ? "- …另有 " + (gaps.size() - AiPromptLimits.MAX_COVERAGE_GAP_PROMPT_ROWS) + " 条 gap 未内联。\n"
                        : "- …" + (gaps.size() - AiPromptLimits.MAX_COVERAGE_GAP_PROMPT_ROWS) + " more gaps omitted.\n");
            }
            return block.toString();
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    /** REPORT：coverage matrix gap 摘要；SUCCESS 不得描述为 safe/secure。 */
    public String coverageMatrixGapsContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null || job.role() != AgentRole.REPORT_GENERATION) return "";
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            ApiDtos.ScanDto dto = scan.dto();
            List<ApiDtos.PathRunDto> pathRuns = store.loadPathRunsForScan(
                    dto.projectId(), dto.artifactDigest(), job.scanId());
            CoverageMatrix matrix = CoverageMatrixProjector.project(
                    job.scanId(),
                    store.staticFacts(job.scanId()),
                    dto.entries(),
                    dto.dependencies(),
                    dto.sinks(),
                    store.hypotheses(job.scanId()),
                    pathRuns);
            return matrix.gapsSummaryText(language == AiOutputLanguage.ZH_CN);
        } catch (RuntimeException ignored) {
            return "";
        }
    }
}

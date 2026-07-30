#!/usr/bin/env python3
"""Generate all context builder classes."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
lines = (ROOT / "src/main/java/com/aq/jvmsentinel/ai/AiJobOrchestrator.java").read_text(encoding="utf-8").splitlines()


def s(start, end):
    return lines[start - 1 : end]


def xform(chunk, *, static_ok=False):
    text = "\n".join(chunk)
    reps = {
        "MAX_PRE_ENTRY_PROMPT_ROWS": "AiPromptLimits.MAX_PRE_ENTRY_PROMPT_ROWS",
        "MAX_PATH_RUN_PROMPT_ROWS": "AiPromptLimits.MAX_PATH_RUN_PROMPT_ROWS",
        "MAX_BYPASS_POC_PROMPT_ROWS": "AiPromptLimits.MAX_BYPASS_POC_PROMPT_ROWS",
        "MAX_CONSTRAINT_PROMPT_ROWS": "AiPromptLimits.MAX_CONSTRAINT_PROMPT_ROWS",
        "MAX_TAINT_PATH_SUMMARY_ROWS": "AiPromptLimits.MAX_TAINT_PATH_SUMMARY_ROWS",
        "MAX_FUZZ_CATEGORY_PROMPT_ROWS": "AiPromptLimits.MAX_FUZZ_CATEGORY_PROMPT_ROWS",
        "MAX_COVERAGE_GAP_PROMPT_ROWS": "AiPromptLimits.MAX_COVERAGE_GAP_PROMPT_ROWS",
        "PRIOR_ROLE_SUMMARY_CHARS": "AiPromptLimits.PRIOR_ROLE_SUMMARY_CHARS",
        "truncatePromptValue(": "AiPromptText.truncatePromptValue(",
        "limitedStrings(": "AiPromptText.limitedStrings(",
        "topCounts(": "AiPromptText.topCounts(",
        "authPreconditions(": "AiPromptText.authPreconditions(",
        "scanPromptSummary(": "AiPromptText.scanPromptSummary(",
        "entryPromptSummary(": "AiPromptText.entryPromptSummary(",
        "AiJobOrchestrator::looksAuthRelated": "AiPromptText::looksAuthRelated",
        "sanitizeSummary(": "AiPromptSanitizer.sanitizeSummary(",
        "loadPathRuns(job)": "pathRuns.loadPathRuns(job)",
        "loadPathRunsForScanSafe(scan)": "pathRuns.loadPathRunsForScanSafe(scan)",
        "loadContrastLedger(job)": "contrast.loadContrastLedger(job)",
        "loadPathTracesByPathRunId(job)": "contrast.loadPathTracesByPathRunId(job)",
        "loadAuthSurface(job)": "auth.loadAuthSurface(job)",
        "loadFeasibilityPoCs(job)": "auth.loadFeasibilityPoCs(job)",
        "latestConclusionSummary(": "history.latestConclusionSummary(",
        "latestRootCauseJson(": "history.latestRootCauseJson(",
        "isAuthBypassConfirmPass(job, runs)": "auth.isAuthBypassConfirmPass(job, runs)",
        "rankedSinkCatalogBlock(scan, language)": "preAnalysis.rankedSinkCatalogBlock(scan, language)",
    }
    for a, b in reps.items():
        text = text.replace(a, b)
    text = re.sub(r"\n    private (String|List|Map|ContrastLedger|AuthBypassFeasibility|boolean|int)",
                  r"\n    public \1", text)
    if not static_ok:
        text = text.replace("private static ", "public static ")
    return text


def emit(name, javadoc, extra_imports, body, extra_fields="", ctor_extra=""):
    imports = """
import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;
""".strip() + ("\n" + extra_imports if extra_imports else "")

    content = f"""package com.aq.jvmsentinel.ai.context;

{imports}

/** {javadoc} */
public final class {name} {{
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunSource pathRunSource;
{extra_fields}

    public {name}(ControlPlaneStore store, PathRunSource pathRunSource{ctor_extra}) {{
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");
    }}

{body}
}}
"""
    out = ROOT / f"src/main/java/com/aq/jvmsentinel/ai/context/{name}.java"
    out.write_text(content, encoding="utf-8")
    print(name, len(content.splitlines()))


emit("PathRunContextBuilder", "PathRun 事实块与加载。", "",
     xform(s(2042, 2049) + s(2519, 2527) + s(2993, 3035)))

emit("AiJobHistoryQueries", "跨角色 job 历史查询。", "",
     xform(s(1454, 1472) + s(3091, 3108)))

emit("ScanMemoryContextBuilder", "SCAN_MEMORY_INDEX 上下文。", """
import com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
""", xform(s(2946, 2991)), extra_fields="""
    private final AiJobHistoryQueries history;

""", ctor_extra=", AiJobHistoryQueries history") 
# fix ctor body - need script fix

emit("AuthContextBuilder", "鉴权面、PoC 与确认上下文。", """
import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
""", xform(s(1855, 1943) + s(2459, 2517) + s(2583, 2602) + s(2856, 2944)))

emit("CoverageContextBuilder", "Coverage gap 与 matrix 上下文。", """
import com.aq.jvmsentinel.analysis.CoverageGapProjector;
import com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import java.util.List;
""", xform(s(1505, 1567)), extra_fields="""
    private final ContrastContextBuilder contrast;

""", ctor_extra=", ContrastContextBuilder contrast")

emit("ContrastContextBuilder", "对照账本、ledger diff 与 TracePlan 对比。", """
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
""", xform(s(1474, 1503) + s(1569, 1648) + s(1825, 1850)))

emit("PreAnalysisContextBuilder", "PRE_ANALYSIS 静态事实与辅助上下文。", """
import com.aq.jvmsentinel.analysis.BranchConstraintHarvester;
import com.aq.jvmsentinel.analysis.CandidateRanker;
import com.aq.jvmsentinel.analysis.CweMapper;
import com.aq.jvmsentinel.analysis.TaintGraph;
import com.aq.jvmsentinel.analysis.TaintGraphProjector;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapter;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.analysis.fuzz.FuzzStrategyRegistry;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.ParameterSpec;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
""", xform(s(1162, 1202) + s(1204, 1452) + s(1945, 2040)), extra_fields="""
    private final PathRunContextBuilder pathRuns;

""", ctor_extra=", PathRunContextBuilder pathRuns")

emit("FindingBindingsContextBuilder", "findingBindings 事实块与服务端装配。", """
import com.aq.jvmsentinel.ai.FindingBindings;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
""", xform(s(1763, 1823)), extra_fields="""
    private final PathRunContextBuilder pathRuns;
    private final ContrastContextBuilder contrast;

""", ctor_extra=", PathRunContextBuilder pathRuns, ContrastContextBuilder contrast")

emit("PriorInferenceContextBuilder", "先前角色推断摘要。", """
import java.util.List;
""", xform(s(3056, 3089)), extra_fields="""
    private final AiJobHistoryQueries history;

""", ctor_extra=", AiJobHistoryQueries history")

print("context builders generated")

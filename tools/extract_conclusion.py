#!/usr/bin/env python3
"""Extract conclusion builders from AiJobOrchestrator."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "src/main/java/com/aq/jvmsentinel/ai/AiJobOrchestrator.java"
lines = ORCH.read_text(encoding="utf-8").splitlines()


def slice(start, end):
    return "\n".join(lines[start - 1 : end])


# --- AiAuthConclusionBuilder ---
auth_body = slice(966, 1123) + "\n\n" + slice(1278, 1306) + "\n\n" + slice(1308, 1352)
auth_body = auth_body.replace("private record AuthConclusionBuilt", "public record AuthConclusionBuilt")
auth_body = auth_body.replace("private AuthConclusionBuilt buildAuthAwareConclusion", "public AuthConclusionBuilt buildAuthAwareConclusion")
auth_body = auth_body.replace("private Set<String> allowedEntryRefs", "private Set<String> allowedEntryRefs")
auth_body = auth_body.replace("private static void collectBypassPoCFromTool", "public static void collectBypassPoCFromTool")
auth_body = auth_body.replace("private boolean authCodeQueryCountsTowardGate", "public boolean authCodeQueryCountsTowardGate")
auth_body = auth_body.replace("private boolean hasPersistedIrMethods", "private boolean hasPersistedIrMethods")
auth_body = auth_body.replace("encode(Map.of(", "AiConclusionJson.encode(Map.of(")
auth_body = auth_body.replace("JSON.readTree", "AiConclusionJson.JSON.readTree")
auth_body = auth_body.replace("JSON.createObjectNode", "AiConclusionJson.JSON.createObjectNode")
auth_body = auth_body.replace("ObjectNode conclusionNode", "com.fasterxml.jackson.databind.node.ObjectNode conclusionNode")
auth_body = auth_body.replace("ObjectNode wrapper", "com.fasterxml.jackson.databind.node.ObjectNode wrapper")

(ROOT / "src/main/java/com/aq/jvmsentinel/ai/conclusion/AiAuthConclusionBuilder.java").write_text(
    f"""package com.aq.jvmsentinel.ai.conclusion;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.ai.TriageConclusion;
import com.aq.jvmsentinel.ai.context.AuthContextBuilder;
import com.aq.jvmsentinel.ai.context.PathRunContextBuilder;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** AUTH/TRIAGE 结论构建、code_query 门禁与 tool bypassPoC 收集。 */
public final class AiAuthConclusionBuilder {{
    private final ControlPlaneStore store;
    private final AuthContextBuilder authContext;
    private final PathRunContextBuilder pathRunContext;

    public AiAuthConclusionBuilder(
            ControlPlaneStore store,
            AuthContextBuilder authContext,
            PathRunContextBuilder pathRunContext) {{
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.authContext = java.util.Objects.requireNonNull(authContext, "authContext");
        this.pathRunContext = java.util.Objects.requireNonNull(pathRunContext, "pathRunContext");
    }}

{auth_body}
}}
""",
    encoding="utf-8",
)

# --- AiDynamicProbeSupport ---
dyn_body = slice(1138, 1271)
dyn_body = dyn_body.replace("private int autoEnqueueFocusedPocProbes", "public int autoEnqueueFocusedPocProbes")
dyn_body = dyn_body.replace("private static String buildDynamicConclusion", "public static String buildDynamicConclusion")
dyn_body = dyn_body.replace("static int requiredEffectiveProbeCount", "public static int requiredEffectiveProbeCount")
dyn_body = dyn_body.replace("static boolean isEffectiveSandboxProbeAttempt", "public static boolean isEffectiveSandboxProbeAttempt")
dyn_body = dyn_body.replace("static boolean isEffectiveSandboxProbeFact", "public static boolean isEffectiveSandboxProbeFact")
dyn_body = dyn_body.replace("static ToolResult gatePathTriageProbeResult", "public static ToolResult gatePathTriageProbeResult")
dyn_body = dyn_body.replace("JSON.createObjectNode", "AiConclusionJson.JSON.createObjectNode")
dyn_body = dyn_body.replace("ObjectNode node", "com.fasterxml.jackson.databind.node.ObjectNode node")
dyn_body = dyn_body.replace("ObjectNode copy", "com.fasterxml.jackson.databind.node.ObjectNode copy")

(ROOT / "src/main/java/com/aq/jvmsentinel/ai/conclusion/AiDynamicProbeSupport.java").write_text(
    f"""package com.aq.jvmsentinel.ai.conclusion;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.DynamicProbeExecutor;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

/** DYNAMIC 结论序列化与 sandbox_probe 有效/无效探针门禁。 */
public final class AiDynamicProbeSupport {{
    private AiDynamicProbeSupport() {{
    }}

{dyn_body}
}}
""",
    encoding="utf-8",
)

# Fix autoEnqueue - needs executor field
dyn_src = (ROOT / "src/main/java/com/aq/jvmsentinel/ai/conclusion/AiDynamicProbeSupport.java").read_text(encoding="utf-8")
dyn_src = dyn_src.replace(
    "public final class AiDynamicProbeSupport {\n    private AiDynamicProbeSupport() {\n    }\n\n",
    "public final class AiDynamicProbeSupport {\n    private final DynamicProbeExecutor dynamicProbeExecutor;\n\n"
    "    public AiDynamicProbeSupport(DynamicProbeExecutor dynamicProbeExecutor) {\n"
    "        this.dynamicProbeExecutor = java.util.Objects.requireNonNull(dynamicProbeExecutor, \"dynamicProbeExecutor\");\n"
    "    }\n\n",
)
(ROOT / "src/main/java/com/aq/jvmsentinel/ai/conclusion/AiDynamicProbeSupport.java").write_text(dyn_src, encoding="utf-8")

# --- AiReportEnforcer ---
report_body = slice(699, 810)
report_body = report_body.replace("private ReportLedgerEnforced enforceReportContrastLedger", "public ReportLedgerEnforced enforceReportContrastLedger")
report_body = report_body.replace("private record ReportLedgerEnforced", "public record ReportLedgerEnforced")
report_body = report_body.replace("private record ReportBindingsEnforced", "public record ReportBindingsEnforced")
report_body = report_body.replace("private String annotateFindingBindings", "public String annotateFindingBindings")
report_body = report_body.replace("private ReportBindingsEnforced enforceReportFindingBindings", "public ReportBindingsEnforced enforceReportFindingBindings")
report_body = report_body.replace("JSON.readTree", "AiConclusionJson.JSON.readTree")
report_body = report_body.replace("JSON.createObjectNode", "AiConclusionJson.JSON.createObjectNode")
report_body = report_body.replace("ObjectNode node", "com.fasterxml.jackson.databind.node.ObjectNode node")
report_body = report_body.replace("ArrayNode ledgerNode", "com.fasterxml.jackson.databind.node.ArrayNode ledgerNode")

(ROOT / "src/main/java/com/aq/jvmsentinel/ai/conclusion/AiReportEnforcer.java").write_text(
    f"""package com.aq.jvmsentinel.ai.conclusion;

import com.aq.jvmsentinel.ai.FindingBindings;
import com.aq.jvmsentinel.ai.context.ContrastContextBuilder;
import com.aq.jvmsentinel.ai.context.FindingBindingsContextBuilder;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;

/** REPORT 阶段 findingBindings 与 contrastLedger 服务端强制。 */
public final class AiReportEnforcer {{
    private final ContrastContextBuilder contrastContext;
    private final FindingBindingsContextBuilder findingBindingsContext;

    public AiReportEnforcer(
            ContrastContextBuilder contrastContext,
            FindingBindingsContextBuilder findingBindingsContext) {{
        this.contrastContext = java.util.Objects.requireNonNull(contrastContext, "contrastContext");
        this.findingBindingsContext = java.util.Objects.requireNonNull(findingBindingsContext, "findingBindingsContext");
    }}

{report_body}
}}
""",
    encoding="utf-8",
)

# --- AiConclusionAnnotator ---
annot_body = slice(813, 964)
annot_body = annot_body.replace("private String buildConclusionJson", "public String buildConclusionJson")
annot_body = annot_body.replace("private String annotateEffectiveProbeCount", "public static String annotateEffectiveProbeCount")
annot_body = annot_body.replace("private void attachTriageFindingIfPresent", "public void attachTriageFindingIfPresent")
annot_body = annot_body.replace("private String annotateNextExperiments", "public String annotateNextExperiments")
annot_body = annot_body.replace("JSON.readTree", "AiConclusionJson.JSON.readTree")
annot_body = annot_body.replace("JSON.createObjectNode", "AiConclusionJson.JSON.createObjectNode")
annot_body = annot_body.replace("ObjectNode node", "com.fasterxml.jackson.databind.node.ObjectNode node")
annot_body = annot_body.replace("ObjectNode row", "com.fasterxml.jackson.databind.node.ObjectNode row")
annot_body = annot_body.replace("ArrayNode array", "com.fasterxml.jackson.databind.node.ArrayNode array")
annot_body = annot_body.replace("ArrayNode inputs", "com.fasterxml.jackson.databind.node.ArrayNode inputs")
annot_body = annot_body.replace("ArrayNode refs", "com.fasterxml.jackson.databind.node.ArrayNode refs")
annot_body = annot_body.replace("ArrayNode rejected", "com.fasterxml.jackson.databind.node.ArrayNode rejected")
annot_body = annot_body.replace("buildAuthAwareConclusion(job, summary, toolBypassPoCs, false)", "authConclusion.buildAuthAwareConclusion(job, summary, toolBypassPoCs, false).conclusionJson()")
# fix buildConclusionJson - it calls buildAuthAwareConclusion

(ROOT / "src/main/java/com/aq/jvmsentinel/ai/conclusion/AiConclusionAnnotator.java").write_text(
    f"""package com.aq.jvmsentinel.ai.conclusion;

import com.aq.jvmsentinel.ai.NextExperimentSteps;
import com.aq.jvmsentinel.ai.RootCauseAnalysis;
import com.aq.jvmsentinel.ai.TriageConclusion;
import com.aq.jvmsentinel.ai.context.PathRunContextBuilder;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;

/** PATH/TRIAGE 结论注解与 TRIAGE finding 挂载。 */
public final class AiConclusionAnnotator {{
    private final ControlPlaneStore store;
    private final PathRunContextBuilder pathRunContext;
    private final AiAuthConclusionBuilder authConclusion;

    public AiConclusionAnnotator(
            ControlPlaneStore store,
            PathRunContextBuilder pathRunContext,
            AiAuthConclusionBuilder authConclusion) {{
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunContext = java.util.Objects.requireNonNull(pathRunContext, "pathRunContext");
        this.authConclusion = java.util.Objects.requireNonNull(authConclusion, "authConclusion");
    }}

    /** 挂载 TRIAGE finding 时写入 job 事件（best-effort）。 */
    public void attachTriageFindingIfPresent(
            SQLiteControlPlanePersistence.AiJobData job,
            String conclusionJson,
            String actorId,
            BiConsumer<SQLiteControlPlanePersistence.AiJobData, String> triageEventAppender) {{
        // body injected below
    }}

{annot_body}
}}
""",
    encoding="utf-8",
)

print("extracted conclusion classes")

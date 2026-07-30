#!/usr/bin/env python3
"""Second pass: slim AiJobOrchestrator after conclusion extraction."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "src/main/java/com/aq/jvmsentinel/ai/AiJobOrchestrator.java"
lines = ORCH.read_text(encoding="utf-8").splitlines()

DELETE = sorted([
    (699, 1352),
], reverse=True)

out = lines[:]
for start, end in DELETE:
    out = out[: start - 1] + out[end:]

text = "\n".join(out) + "\n"

replacements = [
    ("import com.aq.jvmsentinel.ai.context.AiUserPromptBuilder;",
     "import com.aq.jvmsentinel.ai.conclusion.AiAuthConclusionBuilder;\n"
     "import com.aq.jvmsentinel.ai.conclusion.AiAuthConclusionBuilder.AuthConclusionBuilt;\n"
     "import com.aq.jvmsentinel.ai.conclusion.AiConclusionAnnotator;\n"
     "import com.aq.jvmsentinel.ai.conclusion.AiConclusionJson;\n"
     "import com.aq.jvmsentinel.ai.conclusion.AiDynamicProbeSupport;\n"
     "import com.aq.jvmsentinel.ai.conclusion.AiReportEnforcer;\n"
     "import com.aq.jvmsentinel.ai.conclusion.AiReportEnforcer.ReportBindingsEnforced;\n"
     "import com.aq.jvmsentinel.ai.conclusion.AiReportEnforcer.ReportLedgerEnforced;\n"
     "import com.aq.jvmsentinel.ai.context.AiUserPromptBuilder;"),
    ("buildAuthAwareConclusion(", "authConclusion.buildAuthAwareConclusion("),
    ("AuthConclusionBuilt built = authConclusion.buildAuthAwareConclusion(", "AuthConclusionBuilt built = authConclusion.buildAuthAwareConclusion("),
    ("authCodeQueryCountsTowardGate(", "authConclusion.authCodeQueryCountsTowardGate("),
    ("collectBypassPoCFromTool(", "AiAuthConclusionBuilder.collectBypassPoCFromTool("),
    ("gatePathTriageProbeResult(", "AiDynamicProbeSupport.gatePathTriageProbeResult("),
    ("isEffectiveSandboxProbeAttempt(", "AiDynamicProbeSupport.isEffectiveSandboxProbeAttempt("),
    ("isEffectiveSandboxProbeFact(", "AiDynamicProbeSupport.isEffectiveSandboxProbeFact("),
    ("requiredEffectiveProbeCount(", "AiDynamicProbeSupport.requiredEffectiveProbeCount("),
    ("buildDynamicConclusion(", "AiDynamicProbeSupport.buildDynamicConclusion("),
    ("autoEnqueueFocusedPocProbes(", "dynamicProbeSupport.autoEnqueueFocusedPocProbes("),
    ("annotateNextExperiments(", "conclusionAnnotator.annotateNextExperiments("),
    ("annotateEffectiveProbeCount(", "AiConclusionAnnotator.annotateEffectiveProbeCount("),
    ("annotateFindingBindings(", "reportEnforcer.annotateFindingBindings("),
    ("enforceReportFindingBindings(", "reportEnforcer.enforceReportFindingBindings("),
    ("enforceReportContrastLedger(", "reportEnforcer.enforceReportContrastLedger("),
    ("attachTriageFindingIfPresent(initial, conclusion, actorId);",
     "conclusionAnnotator.attachTriageFindingIfPresent(initial, conclusion, actorId,\n"
     "                        (job, detail) -> appendEvent(job, \"TRIAGE_FINDING_ATTACHED\", \"COMPLETED\",\n"
     "                                null, null, null, null, null, detail, null));"),
]

for old, new in replacements:
    text = text.replace(old, new)

field_block = """
    private final AiAuthConclusionBuilder authConclusion;
    private final AiDynamicProbeSupport dynamicProbeSupport;
    private final AiReportEnforcer reportEnforcer;
    private final AiConclusionAnnotator conclusionAnnotator;
"""
text = text.replace(
    "    private final FindingBindingsContextBuilder findingBindingsContext;\n",
    "    private final FindingBindingsContextBuilder findingBindingsContext;\n" + field_block,
    1,
)

init_block = """
        this.authConclusion = new AiAuthConclusionBuilder(store, this.authContext, this.pathRunContext);
        this.dynamicProbeSupport = new AiDynamicProbeSupport(dynamicProbeExecutor);
        this.reportEnforcer = new AiReportEnforcer(this.contrastContext, this.findingBindingsContext);
        this.conclusionAnnotator = new AiConclusionAnnotator(store, this.pathRunContext, this.authConclusion);
"""
text = text.replace(
    "        this.userPromptBuilder = AiUserPromptBuilder.create(store, pathRunSource);",
    "        this.userPromptBuilder = AiUserPromptBuilder.create(store, pathRunSource);" + init_block,
    1,
)

# Keep static delegators for tests on AiJobOrchestrator
delegators = """
    static int requiredEffectiveProbeCount(List<AuthBypassCandidate> feasibilityPoCs) {
        return AiDynamicProbeSupport.requiredEffectiveProbeCount(feasibilityPoCs);
    }

    static boolean isEffectiveSandboxProbeAttempt(ToolResult result) {
        return AiDynamicProbeSupport.isEffectiveSandboxProbeAttempt(result);
    }

    static boolean isEffectiveSandboxProbeFact(JsonNode value) {
        return AiDynamicProbeSupport.isEffectiveSandboxProbeFact(value);
    }

    static ToolResult gatePathTriageProbeResult(ToolResult result) {
        return AiDynamicProbeSupport.gatePathTriageProbeResult(result);
    }

"""
text = text.replace(
    "    private static String extractText(ProviderChatContracts.AssistantTurn assistant) {",
    delegators + "    private static String extractText(ProviderChatContracts.AssistantTurn assistant) {",
    1,
)

# Use AiConclusionJson.encode in orchestrator
text = text.replace("encode(", "AiConclusionJson.encode(")
text = text.replace("AiConclusionJson.encode(Map.of(", "AiConclusionJson.encode(Map.of(")  # noop

ORCH.write_text(text, encoding="utf-8")
print("slim orchestrator lines:", len(text.splitlines()))

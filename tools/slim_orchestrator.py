#!/usr/bin/env python3
"""Slim AiJobOrchestrator.java after prompt/context extraction."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/main/java/com/aq/jvmsentinel/ai/AiJobOrchestrator.java"
lines = SRC.read_text(encoding="utf-8").splitlines()

# 1-indexed inclusive ranges to delete (bottom-up)
DELETE = [
    (3146, 3158),
    (2856, 3108),
    (2785, 2820),
    (2529, 2602),
    (2459, 2517),
    (1763, 2144),
    (1162, 1648),
    (1098, 1160),
    (628, 1034),
    (110, 117),
    (87, 100),
]

out = lines[:]
for start, end in DELETE:
    out = out[: start - 1] + out[end:]

text = "\n".join(out) + "\n"

replacements = [
    ("import com.aq.jvmsentinel.ai.tool.AiToolRegistry;",
     "import com.aq.jvmsentinel.ai.context.AiUserPromptBuilder;\n"
     "import com.aq.jvmsentinel.ai.context.AuthContextBuilder;\n"
     "import com.aq.jvmsentinel.ai.context.ContrastContextBuilder;\n"
     "import com.aq.jvmsentinel.ai.context.FindingBindingsContextBuilder;\n"
     "import com.aq.jvmsentinel.ai.context.PathRunContextBuilder;\n"
     "import com.aq.jvmsentinel.ai.prompt.AiPromptLanguage;\n"
     "import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;\n"
     "import com.aq.jvmsentinel.ai.prompt.AiRepairPrompts;\n"
     "import com.aq.jvmsentinel.ai.prompt.AiSystemPrompt;\n"
     "import com.aq.jvmsentinel.ai.tool.AiToolRegistry;"),
    ("sanitizeSummary(", "AiPromptSanitizer.sanitizeSummary("),
    ("sanitizeDiagnostic(", "AiPromptSanitizer.sanitizeDiagnostic("),
    ("finalInstruction(outputLanguage)", "AiPromptLanguage.finalInstruction(outputLanguage)"),
    ("authCodeQueryRepairInstruction(", "AiRepairPrompts.authCodeQueryRepairInstruction("),
    ("authPocDiversityRepairInstruction(", "AiRepairPrompts.authPocDiversityRepairInstruction("),
    ("authBypassPocRepairInstruction(", "AiRepairPrompts.authBypassPocRepairInstruction("),
    ("dynamicPocAttemptRepairInstruction(", "AiRepairPrompts.dynamicPocAttemptRepairInstruction("),
    ("buildUserPrompt(initial, outputLanguage)", "userPromptBuilder.buildUserPrompt(initial, outputLanguage)"),
    ("loadFeasibilityPoCs(initial)", "authContext.loadFeasibilityPoCs(initial)"),
    ("loadFeasibilityPoCs(job)", "authContext.loadFeasibilityPoCs(job)"),
    ("loadPathRuns(job)", "pathRunContext.loadPathRuns(job)"),
    ("loadAuthSurface(job)", "authContext.loadAuthSurface(job)"),
    ("loadContrastLedger(job)", "contrastContext.loadContrastLedger(job)"),
    ("assembleFindingBindings(job, language)", "findingBindingsContext.assembleFindingBindings(job, language)"),
    ("loadPathFindingBindings(job, language)", "findingBindingsContext.loadPathFindingBindings(job, language)"),
    ("isAuthBypassConfirmPass(job, pathRuns)", "authContext.isAuthBypassConfirmPass(job, pathRuns)"),
    ("outputLanguage(initial)", "parseOutputLanguage(initial)"),
    ("SYSTEM_PROMPT", "AiSystemPrompt.SYSTEM_PROMPT"),
]

for old, new in replacements:
    text = text.replace(old, new)

field_block = """
    private final AiUserPromptBuilder userPromptBuilder;
    private final PathRunContextBuilder pathRunContext;
    private final AuthContextBuilder authContext;
    private final ContrastContextBuilder contrastContext;
    private final FindingBindingsContextBuilder findingBindingsContext;
"""
text = text.replace(
    "    private volatile TerminalListener terminalListener = job -> { };",
    "    private volatile TerminalListener terminalListener = job -> { };" + field_block,
    1,
)

init_block = """
        this.pathRunContext = new PathRunContextBuilder(store, pathRunSource);
        this.contrastContext = new ContrastContextBuilder(store, this.pathRunContext);
        this.authContext = new AuthContextBuilder(store, this.pathRunContext);
        this.findingBindingsContext = new FindingBindingsContextBuilder(
                store, pathRunSource, this.pathRunContext, this.contrastContext);
        this.userPromptBuilder = AiUserPromptBuilder.create(store, pathRunSource);
"""
text = text.replace("        recoverInterruptedJobs();", init_block + "        recoverInterruptedJobs();", 1)

parse_method = """
    private static AiOutputLanguage parseOutputLanguage(SQLiteControlPlanePersistence.AiJobData job) {
        try {
            return AiPromptLanguage.parseOutputLanguage(job.policySnapshotJson());
        } catch (IllegalArgumentException invalid) {
            throw new JobFailure("AI_JOB_SNAPSHOT_INVALID", "invalid output language snapshot");
        }
    }

"""
text = text.replace(
    "    private SQLiteControlPlanePersistence.AiJobData transition(",
    parse_method + "    private SQLiteControlPlanePersistence.AiJobData transition(",
    1,
)

text = text.replace(
    "/**\n * Bounded AI job state machine. Model and artifact content are data only:\n * neither can change scope, policy, tool grants, transport, or authorization.\n */",
    "/**\n * 有界 AI job 状态机。模型与制品内容仅为数据，不能改变 scope、策略、工具授权、传输或鉴权。\n */",
    1,
)
text = text.replace(
    "    /** Provider hard cap is 2 minutes; full audit reports need the upper bound under large tool context. */",
    "    /** Provider 硬上限 2 分钟；大工具上下文下的完整审计报告需要上限内完成。 */",
    1,
)

SRC.write_text(text, encoding="utf-8")
print("slim orchestrator lines:", len(text.splitlines()))

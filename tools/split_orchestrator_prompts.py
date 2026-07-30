#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/main/java/com/aq/jvmsentinel/ai/AiJobOrchestrator.java"
lines = SRC.read_text(encoding="utf-8").splitlines()


def transform_method_block(start: int, end: int) -> str:
    chunk = lines[start - 1 : end]
    out = []
    for line in chunk:
        if "private static String" in line:
            line = line.replace("private static String", "public static String", 1)
        if line.strip().startswith("private String"):
            line = line.replace("private String", "public static String", 1)
        out.append(line)
    return "\n".join(out)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({len(content.splitlines())} lines)")


# AiRolePrompts
role_body = transform_method_block(655, 1054)  # through rolePrompt end before transition
# trim after rolePrompt method - rolePrompt ends around 3054, transition at 1036
# Actually 655-1034 is roleInstruction+reportRoleInstruction, 3037-3054 is rolePrompt
role_instr = transform_method_block(655, 1034)
role_prompt = transform_method_block(3037, 3054)
write(
    ROOT / "src/main/java/com/aq/jvmsentinel/ai/prompt/AiRolePrompts.java",
    f"""package com.aq.jvmsentinel.ai.prompt;

import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** 各 AgentRole 的固定/可定制角色指令与 REPORT 专章合同。 */
public final class AiRolePrompts {{
    private static final ObjectMapper JSON = new ObjectMapper();

    private AiRolePrompts() {{
    }}

{role_instr}

{role_prompt}
}}
""",
)

# AiRepairPrompts
repair = transform_method_block(2529, 2581) + "\n\n" + transform_method_block(2785, 2820)
write(
    ROOT / "src/main/java/com/aq/jvmsentinel/ai/prompt/AiRepairPrompts.java",
    f"""package com.aq.jvmsentinel.ai.prompt;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.provider.AiOutputLanguage;

import java.util.List;

/** AUTH/DYNAMIC 补写轮次的 repair 用户指令。 */
public final class AiRepairPrompts {{
    private AiRepairPrompts() {{
    }}

{repair}
}}
""",
)

# AiPromptSanitizer
sanitizer = transform_method_block(3146, 3158)
write(
    ROOT / "src/main/java/com/aq/jvmsentinel/ai/prompt/AiPromptSanitizer.java",
    f"""package com.aq.jvmsentinel.ai.prompt;

/** Prompt/诊断文本的有界脱敏。 */
public final class AiPromptSanitizer {{
    private AiPromptSanitizer() {{
    }}

{sanitizer}
}}
""",
)

# AiPromptLimits + AiPromptText
write(
    ROOT / "src/main/java/com/aq/jvmsentinel/ai/context/AiPromptLimits.java",
    """package com.aq.jvmsentinel.ai.context;

/** 用户 prompt 各上下文块的内联行数上限。 */
public final class AiPromptLimits {
    public static final int PRIOR_ROLE_SUMMARY_CHARS = 2_048;
    public static final int MAX_PRE_ENTRY_PROMPT_ROWS = 40;
    /** 紧凑默认；可通过 scan_memory_get / facts_search 加深。 */
    public static final int MAX_PATH_RUN_PROMPT_ROWS = 12;
    public static final int MAX_BYPASS_POC_PROMPT_ROWS = 16;
    public static final int MAX_CONSTRAINT_PROMPT_ROWS = 24;
    public static final int MAX_TAINT_PATH_SUMMARY_ROWS = 8;
    public static final int MAX_FUZZ_CATEGORY_PROMPT_ROWS = 6;
    public static final int MAX_COVERAGE_GAP_PROMPT_ROWS = 20;

    private AiPromptLimits() {
    }
}
""",
)

text_utils = transform_method_block(2051, 2144)
write(
    ROOT / "src/main/java/com/aq/jvmsentinel/ai/context/AiPromptText.java",
    f"""package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Prompt 摘要 JSON 与字符串截断辅助。 */
public final class AiPromptText {{
    private AiPromptText() {{
    }}

{text_utils}
}}
""",
)

print("done")

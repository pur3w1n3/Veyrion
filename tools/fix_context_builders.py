#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
ctx = ROOT / "src/main/java/com/aq/jvmsentinel/ai/context"
for f in ctx.glob("*.java"):
    t = f.read_text(encoding="utf-8")
    t2 = re.sub(
        r"\n    private (String|List|Map|ContrastLedger|AuthBypassFeasibility|boolean|int|Optional)",
        r"\n    public \1",
        t,
    )
    if "AiJobHistoryQueries history" in t2 and "this.history =" not in t2:
        t2 = t2.replace(
            'this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");',
            'this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");\n'
            '        this.history = java.util.Objects.requireNonNull(history, "history");',
            1,
        )
    if "PathRunContextBuilder pathRuns" in t2 and "this.pathRuns =" not in t2:
        t2 = t2.replace(
            'this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");',
            'this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");\n'
            '        this.pathRuns = java.util.Objects.requireNonNull(pathRuns, "pathRuns");',
            1,
        )
    if "ContrastContextBuilder contrast" in t2 and "this.contrast =" not in t2:
        t2 = t2.replace(
            'this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");',
            'this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");\n'
            '        this.contrast = java.util.Objects.requireNonNull(contrast, "contrast");',
            1,
        )
    if t2 != t:
        f.write_text(t2, encoding="utf-8")
        print("fixed", f.name)

#!/usr/bin/env python3
"""Post-process extracted ControlPlaneRouteHandlers.java."""
from __future__ import annotations

import pathlib
import re

HANDLERS = pathlib.Path(r"e:\ai\Veyrion\src\main\java\com\aq\jvmsentinel\control\http\ControlPlaneRouteHandlers.java")

def main() -> None:
    text = HANDLERS.read_text(encoding="utf-8")
    # 移除不应在 HTTP 处理器中的 public API
    text = re.sub(
        r"\n    public void mergeRuntimeLoadedClasses\([\s\S]*?\n    \}\n",
        "\n",
        text,
        count=1,
    )
    # 修复未加 host 前缀的字段
    for token in ["clock", "workerToken", "mutationToken"]:
        text = re.sub(rf"(?<![\w\.]){token}(?=\.)", f"host.{token}", text)
        text = re.sub(rf"(?<![\w\.]){token}(?=\))", f"host.{token}", text)
    text = text.replace("host.host.", "host.")
    text = re.sub(r"\baddress\(\)\.", "host.bindAddress.", text)
    text = re.sub(r"\baddress\(\)", "host.bindAddress", text)
    # ControlPlaneWireSupport 方法引用改回 RouteHandlers（暂留同类）
    text = text.replace("ControlPlaneWireSupport::", "ControlPlaneRouteHandlers::")
    HANDLERS.write_text(text, encoding="utf-8", newline="\n")
    print("fixed handlers:", len(text.splitlines()), "lines")


if __name__ == "__main__":
    main()

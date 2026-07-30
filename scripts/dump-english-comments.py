#!/usr/bin/env python3
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("scan", Path(__file__).parent / "scan-english-comments.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
files = mod.scan_files()
Path(__file__).parent.joinpath("english-comments-dump.txt").write_text(
    "\n".join(
        f"{rel}\t{line}"
        for rel in sorted(files.keys())
        for _, line in files[rel]
    ),
    encoding="utf-8",
)
print(f"FILES {len(files)}")

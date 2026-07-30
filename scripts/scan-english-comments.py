#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
roots = [
    ROOT / "src/main/java",
    ROOT / "src/test/java",
    ROOT / "agent/src/main/java",
    ROOT / "frontend/src",
]
exclude_in_path = ("/ai/", "/control/", "/worker/", "/verification/")
eng = re.compile(r"^\s*(//|/\*|\*)\s*([A-Za-z].{7,})")
cn = re.compile(r"[\u4e00-\u9fff]")
skip_starts = (
    "http", "TODO", "FIXME", "NOTE:", "see ", "See ",
    "@param", "@return", "@throws", "@deprecated", "@link", "@code", "@see",
)

files: dict[str, list[tuple[int, str]]] = {}


def scan_files() -> dict[str, list[tuple[int, str]]]:
    out: dict[str, list[tuple[int, str]]] = {}
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.suffix not in {".java", ".ts", ".tsx"}:
                continue
            rel = p.as_posix().replace(str(ROOT.as_posix()) + "/", "")
            if any(x in "/" + rel for x in exclude_in_path):
                continue
            try:
                lines = p.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            hits = []
            for i, line in enumerate(lines, 1):
                m = eng.match(line)
                if not m:
                    continue
                body = m.group(2).strip()
                if body.startswith(skip_starts):
                    continue
                if cn.search(body[:24]):
                    continue
                if re.fullmatch(r"[A-Z0-9_./:-]+", body):
                    continue
                hits.append((i, line.strip()[:110]))
            if hits:
                out[rel] = hits
    return out


if __name__ == "__main__":
    files = scan_files()
    print(f"FILES {len(files)}")
    for rel in sorted(files.keys()):
        print(f"{len(files[rel]):3d} {rel}")

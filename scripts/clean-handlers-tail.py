#!/usr/bin/env python3
import pathlib

H = pathlib.Path(r"e:\ai\Veyrion\src\main\java\com\aq\jvmsentinel\control\http\ControlPlaneRouteHandlers.java")

def main():
    lines = H.read_text(encoding="utf-8").splitlines()
    out = []
    skip = False
    for i, ln in enumerate(lines):
        n = i + 1
        # 删除重复 HTTP 辅助块（uploadSessionMap 之后到 idempotency 之前）
        if n >= 3928 and n <= 4072:
            if "SQLiteControlPlanePersistence.IdempotencyData existingDurableIdempotency" in ln:
                skip = False
            else:
                continue
        # 删除 idempotency 之后的重复 static 直到 sendHealth
        if n >= 4103 and n <= 4191:
            continue
        # 删除末尾重复 sendJson 等
        if n >= 4197 and n <= 4222:
            continue
        if "static void ControlPlaneHttpSupport.ensureIdempotencyCapacity" in ln:
            ln = "    // ensureIdempotencyCapacity -> ControlPlaneHttpSupport"
            continue
        out.append(ln)
    text = "\n".join(out)
    text = text.replace("ensureIdempotencyCapacity(durableIdempotency,", "ensureIdempotencyCapacity(host.durableIdempotency,")
    text = text.replace("Instant.now(host.clock)", "Instant.now(host.clock)")
    H.write_text(text + "\n", encoding="utf-8")
    print("cleaned", len(out), "lines")

if __name__ == "__main__":
    main()

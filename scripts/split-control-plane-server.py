#!/usr/bin/env python3
"""Split ControlPlaneServer.java into control/http collaborators."""
from __future__ import annotations

import pathlib
import re
import textwrap

ROOT = pathlib.Path(r"e:\ai\Veyrion")
SRC = ROOT / "src/main/java/com/aq/jvmsentinel/control/ControlPlaneServer.java"
OUT = ROOT / "src/main/java/com/aq/jvmsentinel/control/http"


def read() -> str:
    return SRC.read_text(encoding="utf-8")


def write(name: str, content: str) -> int:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    n = len(content.splitlines())
    print(f"{name}: {n} lines")
    return n


HTTP_LIMITS = textwrap.dedent(
    """
    package com.aq.jvmsentinel.control.http;

    /** Control Plane HTTP 常量。 */
    public final class ControlPlaneHttpLimits {
        private ControlPlaneHttpLimits() {}

        public static final String API_PREFIX = "/api/v1";
        public static final int MAX_BODY_BYTES = 1 * 1024 * 1024;
        public static final int MAX_LIST_ITEMS = 10_000;
        public static final int MAX_IDEMPOTENCY_KEYS = 50_000;
    }
    """
).strip() + "\n"


HTTP_SUPPORT_HEADER = textwrap.dedent(
    """
    package com.aq.jvmsentinel.control.http;

    import com.aq.jvmsentinel.control.ApiDtos;
    import com.aq.jvmsentinel.control.JsonCodec;
    import com.aq.jvmsentinel.artifact.ArtifactUploadService;
    import com.sun.net.httpserver.Headers;
    import com.sun.net.httpserver.HttpExchange;

    import java.io.IOException;
    import java.net.URI;
    import java.net.URLDecoder;
    import java.nio.charset.CharacterCodingException;
    import java.nio.charset.CodingErrorAction;
    import java.nio.charset.StandardCharsets;
    import java.security.MessageDigest;
    import java.security.SecureRandom;
    import java.util.ArrayList;
    import java.util.Base64;
    import java.util.HexFormat;
    import java.util.LinkedHashMap;
    import java.util.List;
    import java.util.Locale;
    import java.util.Map;

    /** HTTP 读写、解析、CORS 与幂等键辅助。 */
    public final class ControlPlaneHttpSupport {
        private ControlPlaneHttpSupport() {}

        public static final class ApiException extends RuntimeException {
            public final int status;
            public final String code;

            public ApiException(int status, String code, String message) {
                super(message);
                this.status = status;
                this.code = code;
            }
        }

    """
).strip()


RECORDS = textwrap.dedent(
    """
    package com.aq.jvmsentinel.control.http;

    import com.aq.jvmsentinel.control.ApiDtos;
    import com.aq.jvmsentinel.control.ControlPlaneStore;
    import com.aq.jvmsentinel.control.StaticFactSnapshot;
    import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
    import com.aq.jvmsentinel.worker.TaskSnapshot;

    import java.util.List;
    import java.util.Map;

    /** 处理器间共享的私有记录类型。 */
    public final class ControlPlaneHandlerRecords {
        private ControlPlaneHandlerRecords() {}

        public record ScanBuild(ApiDtos.ScanDto scan, Map<String, ApiDtos.EvidenceDto> evidence,
                                List<ApiDtos.FindingDto> findings, List<ApiDtos.AttackChainDto> chains,
                                StaticFactSnapshot staticFacts, List<SecurityHypothesis> hypotheses) {
            public ScanBuild {
                hypotheses = List.copyOf(hypotheses == null ? List.of() : hypotheses);
            }
        }

        public record ScanStart(ControlPlaneStore.ScanRecord scan, boolean replayed) { }

        public record AuditRunReplay(String payload, String scanId, String preAnalysisJobId) { }

        public record DynamicTaskPayload(String scanId, String artifactDigest, String targetEntryId) { }

        public record DynamicTaskReplay(DynamicTaskPayload payload, TaskSnapshot snapshot) { }

        public record FindingReplay(String scanId, TaskSnapshot snapshot) { }

        public record EntryFocusProbe(String scanId, String entryId, TaskSnapshot snapshot) { }
    }
    """
).strip() + "\n"


def transform_common(body: str) -> str:
    body = body.replace("private static final class ApiException", "// moved ApiException")
    body = body.replace("ApiException", "ControlPlaneHttpSupport.ApiException")
    body = body.replace("MAX_BODY_BYTES", "ControlPlaneHttpLimits.MAX_BODY_BYTES")
    body = body.replace("MAX_LIST_ITEMS", "ControlPlaneHttpLimits.MAX_LIST_ITEMS")
    body = body.replace("MAX_IDEMPOTENCY_KEYS", "ControlPlaneHttpLimits.MAX_IDEMPOTENCY_KEYS")
    body = body.replace("API_PREFIX", "ControlPlaneHttpLimits.API_PREFIX")
    body = body.replace("ScanBuild", "ControlPlaneHandlerRecords.ScanBuild")
    body = body.replace("ScanStart", "ControlPlaneHandlerRecords.ScanStart")
    body = body.replace("AuditRunReplay", "ControlPlaneHandlerRecords.AuditRunReplay")
    body = body.replace("DynamicTaskPayload", "ControlPlaneHandlerRecords.DynamicTaskPayload")
    body = body.replace("DynamicTaskReplay", "ControlPlaneHandlerRecords.DynamicTaskReplay")
    body = body.replace("FindingReplay", "ControlPlaneHandlerRecords.FindingReplay")
    body = body.replace("EntryFocusProbe", "ControlPlaneHandlerRecords.EntryFocusProbe")
    return body


def main() -> None:
    src = read()
    write("ControlPlaneHttpLimits.java", HTTP_LIMITS)
    write("ControlPlaneHandlerRecords.java", RECORDS)

    # Extract static tail helpers into HttpSupport (manual line-based from source)
    lines = src.splitlines()
    static_chunk = []
    for i, ln in enumerate(lines):
        if i + 1 < 4531:
            continue
        if i + 1 > 4820:
            break
        if "@Override public void sendHealth" in ln:
            continue
        if "private static boolean isSseRequest" in ln:
            break
        if ln.strip().startswith("private record Scan"):
            break
        static_chunk.append(ln)

    body = "\n".join(static_chunk)
    body = re.sub(r"^\s*private static ", "    public static ", body, flags=re.M)
    body = re.sub(r"^\s*private Map<String, Object> readObject", "    public Map<String, Object> readObject", body, flags=re.M)
    body = re.sub(r"^\s*@Override public String query", "    public static String query", body, flags=re.M)
    body = body.replace("private SQLiteControlPlanePersistence.IdempotencyData existingDurableIdempotency",
                        "// instance idempotency moved to ControlPlaneIdempotencySupport")
    body = body.replace("private SQLiteControlPlanePersistence.IdempotencyData rememberDurableIdempotency",
                        "// instance idempotency moved to ControlPlaneIdempotencySupport")
    body = transform_common(body)
    http_support = HTTP_SUPPORT_HEADER + "\n" + body + "\n}\n"
    write("ControlPlaneHttpSupport.java", http_support)
    print("foundation files written; run full handler extraction separately")


if __name__ == "__main__":
    main()

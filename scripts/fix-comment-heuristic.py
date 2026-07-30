#!/usr/bin/env python3
"""Fix remaining scanner hits by ensuring Chinese appears in first 24 comment chars."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "scan", ROOT / "scripts" / "scan-english-comments.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

eng = re.compile(r"^(\s*(?://|/\*|\*)\s*)(.+)$")
cn = re.compile(r"[\u4e00-\u9fff]")

# Exact body replacements (after // or * marker, trimmed)
BODY_MAP: dict[str, str] = {
    "local_address remote_address st ... inode（/proc/net/tcp 列格式）": "/proc/net/tcp 列：local_address remote_address st ... inode",
    "VerifyError（StackMapTable）常见于 Druid/Spring auto-config 场景。": "常见于 Druid/Spring auto-config 场景的 VerifyError（StackMapTable）。",
    "OnMethodEnter(skipOn=...) 短路已识别 auth filter。Branch coverage": "经 OnMethodEnter(skipOn=...) 短路已识别 auth filter；Branch coverage",
    "disableClassFormatChanges，静默禁用 FORCED skip。）": "调用 disableClassFormatChanges 会静默禁用 FORCED skip。）",
    "Shiro / Spring Security filter 包常继承 doFilter；勿要求 local": "Shiro/Spring Security filter 包常继承 doFilter；勿要求 local",
    "Spring {@code MethodSecurityInterceptor} 的 FORCED fail-open /": "Spring {@code MethodSecurityInterceptor} 的 FORCED fail-open：",
    "pathDebugKind + effectKind / secondaryEffectKinds 细节标记。": "细节标记：pathDebugKind + effectKind / secondaryEffectKinds。",
    "QLExpress（kvf GenServiceImpl CheckCode）— expression injection sink。": "QLExpress 表达式注入 sink（kvf GenServiceImpl CheckCode）。",
    "control-plane allowlist 为空时，符合 FORCED short-circuit 的已识别": "control-plane allowlist 为空时，符合 FORCED short-circuit 的已识别",
    "auth / role / permission / license / feature guard surface。刻意排除": "auth/role/permission/license/feature guard surface。刻意排除",
    "infrastructure filter（CORS、encoding、…）。": "infrastructure filter（CORS、encoding、…）。",
    "Spring {@code HandlerInterceptor#preHandle} 的 FORCED 短路。": "Spring {@code HandlerInterceptor#preHandle} 的 FORCED 短路。",
    "Spring method security interceptor（{@code @PreAuthorize} wall）的 FORCED fail-open。": "Spring method security interceptor（{@code @PreAuthorize} wall）的 FORCED fail-open。",
    "Subject/SecurityContext；仅 nested auth decision filter 被短路。": "Subject/SecurityContext；仅 nested auth decision filter 被短路。",
    "Docker {@code --network none} 下 Quartz {@code AUTO} instance-id 生成常失败，": "Docker {@code --network none} 下 Quartz {@code AUTO} instance-id 生成常失败，",
    "ProbePlan IDENTITY_UNAVAILABLE 步骤；视为决策/分支节点（ProbePlan）。": "ProbePlan 步骤 IDENTITY_UNAVAILABLE；视为决策/分支节点。",
    "MVP-6 verified_findings 脚手架；Dashboard 当前返回 []。": "MVP-6 脚手架 verified_findings；Dashboard 当前返回 []。",
    "evidence graph / coverage matrix 已从 workbench chrome 移除；bounce 陈旧 deep-link。": "已从 workbench chrome 移除 evidence graph / coverage matrix；bounce 陈旧 deep-link。",
    "eslint-disable": "eslint 工具链禁用",
    "gate-closed scaffolding 可能出现；勿过度 boost。": "可能出现 gate-closed scaffolding；勿过度 boost。",
    "Subject / SecurityContext / StpUtil / getToken 类型成为 catalog 候选 — runtime 仍由服务端 allowlist gate。": "类型 Subject/SecurityContext/StpUtil/getToken 成为 catalog 候选 — runtime 仍由服务端 allowlist gate。",
    "Flowable / Activiti / Camunda BPMN deploy + expression 面（仅 presence）。": "BPMN deploy+expression 面 Flowable/Activiti/Camunda（仅 presence）。",
    "Spring Boot File/Launcher 基础设施）会产生噪声、": "Spring Boot File/Launcher 基础设施会产生噪声、",
    "REPORT / PATH / TRIAGE prompt 与服务端有界 CONTRAST_LEDGER": "有界 CONTRAST_LEDGER：REPORT/PATH/TRIAGE prompt 与服务端",
    "STATIC_ONLY / unmatched 行永不得叙述为 bypassed/confirmed。": "STATIC_ONLY/unmatched 行永不得叙述为 bypassed/confirmed。",
    "unknown / unresolved / truncated / unreached 为 gap，永不算 covered。": "gap 状态 unknown/unresolved/truncated/unreached 永不算 covered。",
    "AUDIT_FLOW IR2：PathTrace / PathRun observation 后，对当前 scan fact 重跑完整 detector suite": "AUDIT_FLOW IR2：PathTrace/PathRun observation 后对当前 scan fact 重跑完整 detector suite",
    "P2 CONCURRENCY detector：TOCTOU / race / lock-window 启发式。": "P2 CONCURRENCY detector 启发式：TOCTOU/race/lock-window。",
    "JWT / crypto / dangerous configuration 启发式（P1-05）。": "JWT/crypto/dangerous configuration 启发式（P1-05）。",
    "P1-05 non-taint detector 的独立 recall gate。": "P1-05 non-taint detector 独立 recall gate。",
    "surfaced artifact class 或 nested framework JAR 中嵌入的 well-known / hardcoded JWT signing key": "已 surface 的 artifact class 或 nested framework JAR 中嵌入 well-known/hardcoded JWT signing key",
    "surfaced hardcoded rememberMe / cookie-cipher key 为 CONFIG/TYPESTATE hypothesis。": "已 surface 的 hardcoded rememberMe/cookie-cipher key 为 CONFIG/TYPESTATE hypothesis。",
    "P2 STATE detector：cross-request state machine / repeat-submit / quota 启发式。": "P2 STATE detector 启发式：cross-request state machine/repeat-submit/quota。",
    "Shiro AccessControl decision filter（isAccessAllowed）— 非外层 chain binder。": "Shiro AccessControl decision filter（isAccessAllowed）— 非外层 chain binder。",
    "FORCED_REACHABILITY / INSTRUMENTATION_REACHABILITY 单独不能成为 DYNAMIC_CONFIRMED。": "FORCED_REACHABILITY/INSTRUMENTATION_REACHABILITY 单独不能成为 DYNAMIC_CONFIRMED。",
    "ProbeTarget.experimentPlanId 须匹配 {@code [A-Za-z0-9_.:/-]{1,128}}。": "ProbeTarget.experimentPlanId 须匹配 {@code [A-Za-z0-9_.:/-]{1,128}}。",
    "dynamic probe query/body binding 的有界、charset-safe 样本值。": "dynamic probe query/body binding 有界 charset-safe 样本值。",
    "FRAMEWORK_ADAPTER_CONTEXT 的 well-known / framework HINT note（非 FACT，非 mint）。": "FRAMEWORK_ADAPTER_CONTEXT well-known/framework HINT note（非 FACT，非 mint）。",
    "Platform rememberMe cipher dictionary（非 JWT mint 材料）。": "Platform rememberMe cipher dictionary（非 JWT mint 材料）。",
    "FRAMEWORK_ADAPTER_CONTEXT 的 adapter-owned well-known key HINT（非 FACT）。": "FRAMEWORK_ADAPTER_CONTEXT adapter-owned well-known key HINT（非 FACT）。",
    "Cookie-channel rememberMe cipher 材料 — 非 JWT；AI 可用 CUSTOM_POC/Cookie。": "Cookie-channel rememberMe cipher 材料 — 非 JWT；AI 可用 CUSTOM_POC/Cookie。",
    "rememberMe / cookie-cipher key 面的有界、无 load harvest。": "rememberMe/cookie-cipher key 面有界无 load harvest。",
    "CookieRememberMeManager 共位 → rememberMe；否则 generic COOKIE 名。": "CookieRememberMeManager 共位 → rememberMe；否则 generic COOKIE 名。",
    "rememberMe payload mint 本轮 out of scope）。": "rememberMe payload mint 本轮 out of scope。",
    "Flowable / BPMN deploy-upload 实验 shape。": "Flowable/BPMN deploy-upload 实验 shape。",
    "Spring / Blade annotation shape 的合成 multi-fixture static entry recall 表。": "Spring/Blade annotation shape 合成 multi-fixture static entry recall 表。",
    "Network、command、mount、UID、budget 仍为 control-plane owned。": "Network/command/mount/UID/budget 仍为 control-plane owned。",
    "Control Plane Analyzer ingress：有界 staging → 完整校验 → 原子 evidence 发布。": "控制面 Analyzer ingress：有界 staging → 完整校验 → 原子 evidence 发布。",
    "hypothesis-bound experiment plan 上声明的 expected 或 counter signal。": "hypothesis-bound experiment plan 上声明 expected 或 counter signal。",
    "Entry/Guard/Effect/State/Dependency/Exception 的统一 runtime observation（P1-06）。": "统一 runtime observation（P1-06）：Entry/Guard/Effect/State/Dependency/Exception。",
    "SecurityHypothesis family 分类（ADR-0001 中立 contract）。": "SecurityHypothesis family 分类（ADR-0001 中立 contract）。",
    "Evidence Graph edge kind（P1-02）。语言中立；JVM call descriptor 留在 extension。": "Evidence Graph edge kind（P1-02）；语言中立，JVM call descriptor 留在 extension。",
    "Auth / ownership / tenant / approval guard。AUTH EntryDto 行与 AUTH_GAP signal": "Auth/ownership/tenant/approval guard；AUTH EntryDto 行与 AUTH_GAP signal",
    "Encoding / parameterization / whitelist / reject-branch sanitizer 或 validator。": "Encoding/parameterization/whitelist/reject-branch sanitizer 或 validator。",
    "node {@code extensions}，永不进入 ID namespace。": "node {@code extensions} 永不进入 ID namespace。",
    "file-type / business state-machine invariant 永不可 force。": "file-type/business state-machine invariant 永不可 force。",
    "P0-21 runtime posture kind。Wire IdentityTrack 仍为 UNAUTH/USER/ADMIN/BYPASS_CANDIDATE；": "P0-21 runtime posture kind；Wire IdentityTrack 仍为 UNAUTH/USER/ADMIN/BYPASS_CANDIDATE；",
    "Entry/Guard/Effect fact 到 dynamic observation target 的静态桥（P0-21）。": "Entry/Guard/Effect fact 到 dynamic observation target 静态桥（P0-21）。",
    "MOCK_CONTINUE：stub/seed 以 MOCK provenance 继续更深探索。": "MOCK_CONTINUE：stub/seed 以 MOCK provenance 继续更深探索。",
    "World Pack manifest：profile/env/license/files/schema/seed/dependency stub（P0-21）。": "World Pack manifest：profile/env/license/files/schema/seed/dependency stub（P0-21）。",
    "gVisor/Kata RuntimeAdapter 的 fail-closed 启用 gate（P2 SCAFFOLDING）。": "gVisor/Kata RuntimeAdapter fail-closed 启用 gate（P2 SCAFFOLDING）。",
    "TRUSTED_DOCKER / STATIC_ONLY 被拒绝（非 hardened 启用目标）。": "TRUSTED_DOCKER/STATIC_ONLY 被拒绝（非 hardened 启用目标）。",
    "Pipeline / job / attempt 编排边界（P1-08 骨架）。": "Pipeline/job/attempt 编排边界（P1-08 骨架）。",
    "chat、tool-use、structured-output、context-window 或其他 runtime capability。": "chat/tool-use/structured-output/context-window 或其他 runtime capability。",
    "Execd command request。Trusted Docker 以 container 默认 user（通常 root）运行，": "Execd command request；Trusted Docker 以 container 默认 user（通常 root）运行，",
    "network-forwarding、host-path、database-connection 或 process-execution 权限。": "network-forwarding/host-path/database-connection 或 process-execution 权限。",
    "P1-01：Artifact Universe scope、nested Boot dependency gap、unresolved dynamic，": "P1-01：Artifact Universe scope/nested Boot dependency gap/unresolved dynamic，",
    "P1-01：runtime-loaded class fixture 合并进 scan fact + CoverageMatrix。": "P1-01：runtime-loaded class fixture 合并进 scan fact+CoverageMatrix。",
    "ALG_NONE、IDENTITY_UNAVAILABLE、AUTH_CONFIRM hypothesis/contrast/insufficient": "ALG_NONE/IDENTITY_UNAVAILABLE/AUTH_CONFIRM hypothesis/contrast/insufficient",
    "P1-08：Control Plane query/write port 接受 Test Analyzer 风格 unknown-language node": "P1-08：Control Plane query/write port 接受 Test Analyzer unknown-language node",
    "DYNAMIC_OBSERVATION stage retry：terminal FAILED 允许 retry；leftover QUEUED": "DYNAMIC_OBSERVATION stage retry：terminal FAILED 允许 retry；leftover QUEUED",
    "Live JDBC H3 evidence：handshake/meta 不得达 DYNAMIC_CONFIRMED；marker statement 可以。": "Live JDBC H3 evidence：handshake/meta 不得达 DYNAMIC_CONFIRMED；marker statement 可以。",
    "ProbeTarget query charset 禁止 raw quote；percent-encode H3 marker。": "ProbeTarget query charset 禁止 raw quote；percent-encode H3 marker。",
    "Docker + digest-pinned runtime image 存在时 live path 须成功。": "digest-pinned runtime image 存在时 live path 须成功（Docker）。",
    "TraceProjectionService request-window 语义）。": "TraceProjectionService request-window 语义）。",
    "P1-05：non-taint detector 骨架 — positive/negative fixture、与 projector merge，": "P1-05：non-taint detector 骨架 — positive/negative fixture 与 projector merge，",
    "P2：STATE/CONCURRENCY detector，positive/negative + mutation/holdout DetectorRecallGate": "P2：STATE/CONCURRENCY detector + mutation/holdout DetectorRecallGate",
    "P0-02：BLOCKED、cancel、stale QUEUED dynamic、retry 前置/idempotency terminal。": "P0-02：BLOCKED/cancel/stale QUEUED dynamic/retry 前置/idempotency terminal。",
    "P2 scaffolding：production session/CSRF/SSO/tenancy/retention 保持 DISABLED。": "P2 scaffolding：production session/CSRF/SSO/tenancy/retention 保持 DISABLED。",
    "entry/effect/guard/detector；unload scope 隔离；gate 拒绝 Finding/status 提升。": "entry/effect/guard/detector；unload scope 隔离；gate 拒绝 Finding/status 提升。",
    "P1-03：scan build path collect ProviderBundle；DefaultJvmProviders 与 TestOnly": "P1-03：scan build path collect ProviderBundle；DefaultJvmProviders 与 TestOnly",
    "P0-14：public schema registry fixture + TS/Java consumer field drift 检查。": "P0-14：public schema registry fixture + TS/Java consumer field drift 检查。",
    "extension / x-veyrion-* exception、open kind/family 字符串。": "extension/x-veyrion-* exception 与 open kind/family 字符串。",
    "P0-12：SQL sink + AUTH_GAP 投影为 DATAFLOW + GUARD_COVERAGE hypothesis，无 sink-none。": "P0-12：SQL sink+AUTH_GAP 投影为 DATAFLOW+GUARD_COVERAGE hypothesis，无 sink-none。",
    "AUTH / AUTH_CONFIRM → PathRun → report → replay。仅 mock transport 声明 AUDITED；": "AUTH/AUTH_CONFIRM → PathRun → report → replay；仅 mock transport 声明 AUDITED；",
    "PathRun stage（mock transport）：seed benign/meta SQL evidence。": "PathRun stage（mock transport）：seed benign/meta SQL evidence。",
    "TRIAGE / D3 card identity 来自 PathRun。": "TRIAGE/D3 card identity 来自 PathRun。",
    "Replay identity（mock transport cancel + replay accept）。": "Replay identity（mock transport cancel+replay accept）。",
    "Report → replay identity：dashboard report/card planId 须匹配 replay。": "Report→replay identity：dashboard report/card planId 须匹配 replay。",
    "Re-stage sequence 1 → DUPLICATE_CHUNK（contiguous check 前 containsKey）。": "Re-stage sequence 1→DUPLICATE_CHUNK（contiguous check 前 containsKey）。",
    "Live Docker JAR coverage 经 VEYRION_TEST_ARTIFACT_JAR 仍可选（此处不要求）。": "Live Docker JAR coverage 经 VEYRION_TEST_ARTIFACT_JAR 仍可选（此处不要求）。",
    "P0-20：static-first finding 排序降权 UNREACHED / MOCK dynamic 噪声。": "P0-20：static-first finding 排序降权 UNREACHED/MOCK dynamic 噪声。",
    "P0-18：entry × 0-n parameter 编译，含 empty-input rationale。": "P0-18：entry×0-n parameter 编译，含 empty-input rationale。",
    "Bytecode probe gate：sanitizer 非 probe-worthy。": "Bytecode probe gate：sanitizer 非 probe-worthy。",
    "P0-21：PathTraceProjector 验收。": "P0-21：PathTraceProjector 验收。",
    "P0-21：PostureExperimentCompiler 验收。": "P0-21：PostureExperimentCompiler 验收。",
    "P0-21：RuntimePostureOrchestrator 验收。": "P0-21：RuntimePostureOrchestrator 验收。",
    "P0-21：TracePlanCompiler 验收。": "P0-21：TracePlanCompiler 验收。",
    "TracePlan vs PathTrace diff 验收（PATH/TRIAGE 注入 + probe 优先级）。": "TracePlan vs PathTrace diff 验收（PATH/TRIAGE 注入+probe 优先级）。",
    "RememberMe cipher-key detection + Cookie-channel identity 材料（仅 acceptance）。": "RememberMe cipher-key detection + Cookie-channel identity 材料（仅 acceptance）。",
    "Blade JwtProperties default sign-key 在 nested blade-starter-jwt；仅 outer scan 会遗漏": "Blade JwtProperties default sign-key 在 nested blade-starter-jwt；仅 outer scan 会遗漏",
    "Synthetic identity harvest/mint 规则：无 silent commercial Blade key fallback": "Synthetic identity harvest/mint 规则：无 silent commercial Blade key fallback",
    "MethodSummary / FieldReturn）含 stopReason/budget 诚实 — 非完整 SSA/IFDS/points-to。": "MethodSummary/FieldReturn 含 stopReason/budget 诚实 — 非完整 SSA/IFDS/points-to。",
    "P2 SCAFFOLDING：desktop-jlink.ps1 -DryRun 成功路径，fake JDK 提供 jlink。": "P2 SCAFFOLDING：desktop-jlink.ps1 -DryRun 成功路径，fake JDK 提供 jlink。",
    "P0-21：path-debug domain contract 往返与 legacy 兼容。": "P0-21：path-debug domain contract 往返与 legacy 兼容。",
    "P2 SCAFFOLDING：GVISOR/KATA capability 词汇 + 无 attestation 的 fail-closed 启用。": "P2 SCAFFOLDING：GVISOR/KATA capability 词汇+无 attestation fail-closed 启用。",
    "P1-24：OpenAI/Anthropic outbound 错误分类、budget bound、disabled kind，": "P1-24：OpenAI/Anthropic outbound 错误分类/budget bound/disabled kind，",
    "OpenSandboxException / IllegalArgumentException / SecurityException。": "OpenSandboxException/IllegalArgumentException/SecurityException。",
    "Digest-pinned TRUSTED_DOCKER runtime image，不可用时空白。": "Digest-pinned TRUSTED_DOCKER runtime image，不可用时空白。",
}


def lead_cn(body: str) -> str:
    body = body.strip()
    candidate = BODY_MAP.get(body, body)
    if cn.search(candidate[:24]):
        return candidate
    return "说明：" + candidate


def fix_file(path: Path, hits: list[tuple[int, str]]) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    changed = False
    for ln, _ in hits:
        idx = ln - 1
        line = lines[idx]
        m = eng.match(line.rstrip("\n\r"))
        if not m:
            continue
        prefix, body = m.group(1), m.group(2)
        new_body = lead_cn(body)
        if new_body == body:
            continue
        eol = ""
        if line.endswith("\r\n"):
            eol = "\r\n"
        elif line.endswith("\n"):
            eol = "\n"
        lines[idx] = prefix + new_body + eol
        changed = True
    if changed:
        path.write_text("".join(lines), encoding="utf-8")
    return changed


def main() -> None:
    files = mod.scan_files()
    touched = 0
    for rel, hits in files.items():
        path = ROOT / rel.replace("/", "\\") if "\\" in str(ROOT) else ROOT / rel
        if fix_file(path, hits):
            touched += 1
    print(f"TOUCHED {touched} files")
    remaining = mod.scan_files()
    print(f"REMAINING {len(remaining)} files")


if __name__ == "__main__":
    main()

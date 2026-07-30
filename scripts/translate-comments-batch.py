#!/usr/bin/env python3
"""Apply Phase 2 comment translations (English -> Simplified Chinese). Logic unchanged."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Exact multi-line replacements: (relative_path, old, new)
REPLACEMENTS: list[tuple[str, str, str]] = [
    # model
    ("src/main/java/com/aq/jvmsentinel/model/PathRun.java",
     "/**\n * First-class path experiment session: scanId + entryId + track + attemptId.\n */",
     "/**\n * 一等 path 实验 session：scanId + entryId + track + attemptId。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/ArtifactDescriptor.java",
     "/** Prefer the original upload/path basename for UI labels. */",
     "/** UI 标签优先使用原始 upload/path basename。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "/**\n * AI-authored auth-bypass feasibility PoC. AUTH_ANALYSIS / triage judges and authors\n * the payload; the server validates schema/bounds; DYNAMIC_VERIFICATION executes and\n * traces outcomes. Never alone upgrades verification status.\n */",
     "/**\n * AI 撰写的 auth-bypass 可行性 PoC。AUTH_ANALYSIS / triage 评判并撰写\n * payload；服务端校验 schema/bounds；DYNAMIC_VERIFICATION 执行并\n * 追踪 outcome。单独永不升级 verification status。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "/** Token / header material for loopback probe (AI-authored; may be JWT). */",
     "/** loopback probe 的 token / header 材料（AI 撰写；可为 JWT）。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "/**\n         * Optional secondary auth-channel material (wire name {@code bladeAuthHeader} kept for\n         * compatibility; semantically {@code secondaryAuthorizationHeader}). Empty means\n         * Authorization-only unless the probe layer dual-writes from harvest hints.\n         */",
     "/**\n         * 可选次要 auth-channel 材料（wire 名 {@code bladeAuthHeader} 为\n         * 兼容保留；语义为 {@code secondaryAuthorizationHeader}）。空表示\n         * 仅 Authorization，除非 probe 层从 harvest hint 双写。\n         */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "/** True when the model supplied probe-usable auth material (not only a label). */",
     "/** 模型提供了 probe 可用的 auth 材料（不仅是 label）时为 true。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "/** Schema-gate AI auth material without constructing a full candidate. */",
     "/** schema-gate AI auth 材料，不构造完整 candidate。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "/** Probe-layer token body: strips a leading Bearer scheme if the model included it. */",
     "/** Probe 层 token body：若模型包含则剥离 leading Bearer scheme。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "/** Generic alias for {@link #bladeAuthHeader()}. */",
     "/** {@link #bladeAuthHeader()} 的通用别名。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "/** Probe-layer secondary-channel token body. */",
     "/** Probe 层次要 channel token body。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassCandidate.java",
     "        // Allow JWT / base64url / Bearer / common header token charset.",
     "        // 允许 JWT / base64url / Bearer / 常见 header token charset。"),
    ("src/main/java/com/aq/jvmsentinel/model/ExperimentPlan.java",
     "/**\n * AI-proposed, server-gated experiment plan for one entry × track.\n * Models propose; the server validates budget and safety before execution.\n */",
     "/**\n * AI 提议、服务端 gate 的单 entry × track 实验计划。\n * 模型提议；服务端在执行前校验 budget 与 safety。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/BytecodeFactIndex.java",
     "/**\n * Bounded, load-free facts decoded from classfiles. Call edges are symbolic:\n * this index does not resolve class paths or claim runtime dispatch.\n */",
     "/**\n * 从 classfile 解码的有界、无 load 事实。Call edge 为符号级：\n * 本 index 不解析 class path，也不声称 runtime dispatch。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/BytecodeFactIndex.java",
     "/** Compatibility-friendly names for consumers that treat the index as a graph/flow result. */",
     "/** 将 index 视为 graph/flow 结果的消费者的兼容友好名称。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/BytecodeFactIndex.java",
     "/**\n     * Bounded graph projection over {@link #interproceduralTaintPaths()}.\n     * Implementation lives in {@code com.aq.jvmsentinel.analysis.TaintGraphProjector}\n     * to avoid a model→analysis package cycle; this method is a stable call site.\n     */",
     "/**\n     * 对 {@link #interproceduralTaintPaths()} 的有界 graph 投影。\n     * 实现位于 {@code com.aq.jvmsentinel.analysis.TaintGraphProjector}，\n     * 避免 model→analysis package 循环；本方法为稳定 call site。\n     */"),
    ("src/main/java/com/aq/jvmsentinel/model/BytecodeFactIndex.java",
     "/** A target resolved against classes and methods present in this artifact only. */",
     "/** 仅针对本 artifact 中存在的 class 与 method 解析的 target。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/BytecodeFactIndex.java",
     "/** Static source-to-sink candidate. It is never runtime or replay verification. */",
     "/** 静态 source-to-sink 候选。永非 runtime 或 replay verification。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/StaticContrastRow.java",
     "/**\n * One ledger row: sink-perspective static projection joined (optionally) to PathRuns.\n * Engine FACT/INFERENCE only — never VERIFIED / bypass-confirmed by itself.\n */",
     "/**\n * 一条 ledger 行：sink 视角静态投影（可选）关联 PathRun。\n * 仅 Engine FACT/INFERENCE — 自身永非 VERIFIED / bypass-confirmed。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/ParameterSpec.java",
     "/**\n * Structured entry parameter. Legacy {@code List<String>} encodings remain readable via\n * {@link #fromLegacy(String)}.\n */",
     "/**\n * 结构化 entry 参数。Legacy {@code List<String>} 编码仍可通过\n * {@link #fromLegacy(String)} 读取。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/ParameterConstraint.java",
     "/** Bounded parameter constraint harvested from bytecode flow / annotations. */",
     "/** 从 bytecode flow / annotation 采集的有界 parameter constraint。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/ContrastStatus.java",
     "/**\n * Static↔dynamic contrast for a sink/entry row. Never upgrades verification:\n * MATCHED is still at most {@code DYNAMIC_SUSPECTED}.\n */",
     "/**\n * sink/entry 行的 static↔dynamic 对比。永不升级 verification：\n * MATCHED 至多仍为 {@code DYNAMIC_SUSPECTED}。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/ContrastStatus.java",
     "/** Static candidate aligns with a pass-gate PathRun on the same entry×track. */",
     "/** 静态候选与同一 entry×track 的 pass-gate PathRun 对齐。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/ContrastStatus.java",
     "/** PathRun exists for the entry×track but bind/sink touch is incomplete. */",
     "/** entry×track 存在 PathRun 但 bind/sink touch 不完整。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/ContrastStatus.java",
     "/** Static reachability/gap with no usable pass-gate PathRun (e.g. all 401). */",
     "/** 静态 reachability/gap，无可用 pass-gate PathRun（如全部 401）。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/ContrastStatus.java",
     "/** A method on the static taint path emitted at least one dynamic branch hit. */",
     "/** 静态 taint path 上的 method 至少产生一次 dynamic branch hit。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/ContrastStatus.java",
     "/** PathRun without a matching static sink row. */",
     "/** 无匹配静态 sink 行的 PathRun。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/ContrastStatus.java",
     "/** Insufficient data to classify. */",
     "/** 数据不足，无法分类。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/RunProfile.java",
     "/**\n * Declares how an artifact may be executed dynamically. Without a complete\n * profile, WAR / non-Boot / CLASS stay static-only — never host-executed.\n */",
     "/**\n * 声明 artifact 如何动态执行。无完整 profile 时，\n * WAR / non-Boot / CLASS 保持 static-only — 永不 host 执行。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/RunProfile.java",
     "                    // Boot JAR uses the default TRUSTED_DOCKER java -jar profile.",
     "                    // Boot JAR 使用默认 TRUSTED_DOCKER java -jar profile。"),
    ("src/main/java/com/aq/jvmsentinel/model/NextExperimentStep.java",
     "/**\n * Evidence-constrained next validation step produced by PATH / TRIAGE.\n * Consumable by {@code sandbox_probe}; never upgrades verification alone.\n */",
     "/**\n * PATH / TRIAGE 产生的 evidence 约束下一步验证。\n * 可由 {@code sandbox_probe} 消费；单独永不升级 verification。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/SqlExperimentCard.java",
     "/**\n * D3 replayable SQL experiment card: identity track, bounded inputs, SQL before/after,\n * and stop conditions. Default verification is at most {@link VerificationStatus#DYNAMIC_SUSPECTED};\n * only the server H3 gate may raise {@link VerificationStatus#DYNAMIC_CONFIRMED}.\n */",
     "/**\n * D3 可 replay 的 SQL 实验 card：identity track、有界 input、SQL before/after\n * 与 stop condition。默认 verification 至多 {@link VerificationStatus#DYNAMIC_SUSPECTED}；\n * 仅服务端 H3 gate 可提升为 {@link VerificationStatus#DYNAMIC_CONFIRMED}。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/AuthBypassTechnique.java",
     "/**\n * Optional known technique labels. AI may author arbitrary PoC material; these ids\n * are only fallbacks when the model names a known technique without supplying headers.\n */",
     "/**\n * 可选已知 technique label。AI 可撰写任意 PoC 材料；这些 id\n * 仅在模型命名已知 technique 但未提供 header 时作 fallback。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/PathOutcomeClassifier.java",
     "/** Maps HTTP/transport probe signals to the minimum PathOutcomeClass taxonomy. */",
     "/** 将 HTTP/transport probe 信号映射到最小 PathOutcomeClass 分类。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/SqlEvent.java",
     "/** D1 SQL observation attached to a PathRun. */",
     "/** 附加到 PathRun 的 D1 SQL observation。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/VerificationStatus.java",
     "/** Malicious SQL fragment reached the actual JDBC/mock statement without filtering. */",
     "/** 恶意 SQL 片段未经过滤到达实际 JDBC/mock statement。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/PathOutcomeClass.java",
     "/**\n * Probe/Agent outcome taxonomy. AI may only cite these codes; it cannot invent new ones.\n */",
     "/**\n * Probe/Agent outcome 分类。AI 仅能引用这些 code；不能发明新 code。\n */"),
    ("src/main/java/com/aq/jvmsentinel/model/PathOutcomeClass.java",
     "/** Identity could not be synthesized for this track. */",
     "/** 无法为本 track 合成 identity。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/PathOutcomeClass.java",
     "/** Probe received an HTTP response that is not otherwise classified. */",
     "/** Probe 收到未另行分类的 HTTP 响应。 */"),
    ("src/main/java/com/aq/jvmsentinel/model/IdentityTrack.java",
     "/** Identity track for path experiments. */",
     "/** path 实验的 identity track。 */"),
]

EXCLUDE_MAIN = {"ai", "control", "worker", "verification"}
EXCLUDE_TEST = {"ai", "control", "worker"}


def apply_replacements() -> int:
    changed = 0
    for rel, old, new in REPLACEMENTS:
        path = ROOT / rel.replace("/", "\\") if sys.platform == "win32" else ROOT / rel
        if not path.exists():
            print(f"SKIP missing: {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        if old not in text:
            print(f"SKIP no match: {rel}")
            continue
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        changed += 1
        print(f"OK: {rel}")
    return changed


if __name__ == "__main__":
    n = apply_replacements()
    print(f"Applied {n} replacements")

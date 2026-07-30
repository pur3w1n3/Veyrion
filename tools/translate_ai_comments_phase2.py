#!/usr/bin/env python3
"""Phase 2: translate English Java comments to Simplified Chinese in ai/** packages."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIRS = [
    ROOT / "src/main/java/com/aq/jvmsentinel/ai",
    ROOT / "src/test/java/com/aq/jvmsentinel/ai",
]

# Ordered multi-line block replacements (exact match after normalize_ws)
BLOCKS: list[tuple[str, str]] = [
    (
        """Parses and validates AUTH/triage AI-authored bypass PoCs.
 Accepts Authorization / secondaryAuthorizationHeader (wire: bladeAuthHeader) / JWT /
 query / body hints under hard bounds;
 rejects entry escape, oversize, control chars, and destructive unchecked payloads.
 When a scan has an auth surface (JWT / AUTH_GAP / auth-annotated entries) but AUTH
 emits no structured PoCs, the server requires a repair re-ask or seeds RULE_GENERATED
 drafts so DYNAMIC still has candidates — never elevates verification from LLM alone.""",
        """解析并校验 AUTH/triage 模型产出的 bypass PoC。
 接受 Authorization / secondaryAuthorizationHeader（wire: bladeAuthHeader）/ JWT /
 query / body 提示，受硬边界约束；
 拒绝 entry 逃逸、超长、控制字符与未校验的破坏性 payload。
 当 scan 存在鉴权面（JWT / AUTH_GAP / auth 标注 entry）但 AUTH 未产出结构化 PoC 时，
 服务端要求 repair 补问或种子 RULE_GENERATED 草稿，使 DYNAMIC 仍有候选——
 绝不仅凭 LLM 提升验证状态。""",
    ),
    (
        """Static auth surface signals that require structured bypass PoCs from AUTH.""",
        """需要 AUTH 产出结构化 bypass PoC 的静态鉴权面信号。""",
    ),
    (
        """Server evidence gate for AUTH bypass confirmation.
 Zero PathRun AUTH_CHALLENGE / pass-gate evidence → never DYNAMIC_CONTRAST;
 claiming confirmed without evidence → INSUFFICIENT_EVIDENCE.""",
        """AUTH bypass 确认的服务端证据闸门。
 零 PathRun AUTH_CHALLENGE / 过闸证据 → 不得 DYNAMIC_CONTRAST；
 无证据却声称已确认 → INSUFFICIENT_EVIDENCE。""",
    ),
    (
        """Whether AUTH_BYPASS_CONFIRM should be scheduled (AUDIT_FLOW: only after AUTH_CHALLENGE
 or pass-gate PathRun evidence). FORCED/COVERAGE 2xx with entryHit counts as 过闸 for
 <em>scheduling</em> only — confirmation status still uses {@link #isPassGate} (BYPASS/ADMIN)
 so FORCED alone cannot become DYNAMIC_CONTRAST bypass confirmation.""",
        """是否应调度 AUTH_BYPASS_CONFIRM（AUDIT_FLOW：仅在 AUTH_CHALLENGE
 或过闸 PathRun 证据之后）。FORCED/COVERAGE 2xx 且 entryHit 仅计为<em>调度</em>过闸——
 确认状态仍用 {@link #isPassGate}（BYPASS/ADMIN），
 故单独 FORCED 不能成为 DYNAMIC_CONTRAST bypass 确认。""",
    ),
    (
        """PathRuns that can support dynamic contrast: AUTH_CHALLENGE, or 2xx/3xx on
 BYPASS_CANDIDATE / ADMIN tracks for claimed entries (when claims are present).""",
        """可支撑动态对比的 PathRun：AUTH_CHALLENGE，或对已声明 entry 在
 BYPASS_CANDIDATE / ADMIN track 上的 2xx/3xx（存在 claim 时）。""",
    ),
    (
        """Surface present but fewer than {@link #AUTH_POC_MECHANISM_MIN} distinct mechanisms,
 and model did not supply enough infeasible evidence refs to explain the gap.""",
        """鉴权面存在但 distinct 机制数少于 {@link #AUTH_POC_MECHANISM_MIN}，
 且模型未提供足够 infeasible 证据 ref 解释缺口。""",
    ),
    (
        """Prefer auth-material PoCs, then diversify by entryRef/technique for DYNAMIC
 sandbox_probe attempts (prompt band and server auto-enqueue fallback).""",
        """优先含 auth material 的 PoC，再按 entryRef/technique 多样化，
 供 DYNAMIC sandbox_probe（prompt 区间与服务端自动入队回退）。""",
    ),
    (
        """Server draft candidates from static JWT/AUTH_GAP/auth-entry signals.
 Marked RULE_GENERATED; DYNAMIC may attempt them. Never upgrades verification alone.""",
        """由静态 JWT/AUTH_GAP/auth-entry 信号生成的服务端草稿候选。
 标记 RULE_GENERATED；DYNAMIC 可尝试。绝不单独提升验证状态。""",
    ),
    (
        """Server draft candidates from static JWT/AUTH_GAP/auth-entry signals.
 DEFAULT_SECRET_HS256 is seeded only when harvest found mintable sign-key material
 in the artifact (low-confidence RULE_GENERATED). Multi-header auth surface alone never
 forges a commercial default JWT. Secret-less techniques (MISSING_AUTH / EMPTY_BEARER /
 ALG_NONE) remain available without harvested keys.""",
        """由静态 JWT/AUTH_GAP/auth-entry 信号生成的服务端草稿候选。
 仅当 harvest 在制品中发现可 mint 的 sign-key material 时才种子 DEFAULT_SECRET_HS256
 （低置信 RULE_GENERATED）。多 header 鉴权面 alone 从不伪造商业默认 JWT。
 无 secret 技术（MISSING_AUTH / EMPTY_BEARER / ALG_NONE）在无 harvest key 时仍可用。""",
    ),
    (
        """Server-owned audit stage machine. Model output cannot arm, skip, or expand stages.
 Advancement requires an armed pipeline from an authorized audit-run and a CAS match on
 {@code pipelineRunId}, {@code stageAttemptId}, and the expected job/task identity.

 <p>Path-debug order: PRE → AUTH → DYNAMIC_OBSERVATION → AUTH bypass confirm (evidence only) →
 DYNAMIC_VERIFICATION → PATH ↔ OBS loops → TRIAGE ↔ OBS loops → REPORT.
 OBS feedback loops are capped ({@code VEYRION_AUDIT_OBS_LOOP_MAX} / {@code veyrion.audit.obsLoopMax},
 default 3).</p>""",
        """服务端拥有的审计阶段状态机。模型输出不能 arm、跳过或扩展阶段。
 推进需来自已授权 audit-run 的 armed pipeline，且对
 {@code pipelineRunId}、{@code stageAttemptId} 与预期 job/task 身份 CAS 匹配。

 <p>Path-debug 顺序：PRE → AUTH → DYNAMIC_OBSERVATION → AUTH bypass 确认（仅证据）→
 DYNAMIC_VERIFICATION → PATH ↔ OBS 循环 → TRIAGE ↔ OBS 循环 → REPORT。
 OBS 反馈循环有上限（{@code VEYRION_AUDIT_OBS_LOOP_MAX} / {@code veyrion.audit.obsLoopMax}，
 默认 3）。</p>""",
    ),
    (
        """CAS: advance only when scan/run/attempt and expected resource still match.
 Returns false when foreign, stale, duplicate, or late.""",
        """CAS：仅当 scan/run/attempt 与预期资源仍匹配时推进。
 外来、过期、重复或迟到时返回 false。""",
    ),
    (
        """Best-effort release of a scan-scoped retained deny-all sandbox after PATH/TRIAGE
 dynamic validation completes or the pipeline abandons a stage that may have held one.""",
        """PATH/TRIAGE 动态验证完成或 pipeline 放弃可能持有 sandbox 的阶段后，
 best-effort 释放 scan 作用域内保留的 deny-all sandbox。""",
    ),
    (
        """AUTH_BYPASS_CONFIRM only when PathRuns show AUTH_CHALLENGE or pass-gate (AUDIT_FLOW §4).
 Default true preserves unit-test fixtures that do not wire PathRuns.""",
        """仅当 PathRun 显示 AUTH_CHALLENGE 或过闸时才 AUTH_BYPASS_CONFIRM（AUDIT_FLOW §4）。
 默认 true 以保留未接入 PathRun 的单元测试 fixture。""",
    ),
    (
        """Whether PATH/TRIAGE should re-enter DYNAMIC_OBSERVATION (coverage gap / STATIC_ONLY /
 unverified hypothesis work remaining).""",
        """PATH/TRIAGE 是否应重新进入 DYNAMIC_OBSERVATION（coverage gap / STATIC_ONLY /
 未验证 hypothesis 工作仍剩）。""",
    ),
    (
        """Arms a new pipeline run that is already waiting on a caller-created AI job.
 Invalidates any prior run for the scan.""",
        """Arm 新 pipeline run，已等待调用方创建的 AI job。
 使该 scan 上任何先前 run 失效。""",
    ),
    (
        """Arms a new pipeline run that is already waiting on a caller-created dynamic task.
 Invalidates any prior run for the scan.""",
        """Arm 新 pipeline run，已等待调用方创建的 dynamic task。
 使该 scan 上任何先前 run 失效。""",
    ),
    (
        """Restores a persisted cursor exactly. Does not infer stage from scan-wide jobs/tasks.
 Reconciles already-terminal expected resources; otherwise waits without re-enqueue.""",
        """精确恢复已持久化 cursor。不从 scan 级 job/task 推断阶段。
 协调已终态的预期资源；否则等待且不重新入队。""",
    ),
    (
        """Operator pause: drop the live cursor so stage completion cannot advance, and persist
 {@link #STOP_OPERATOR_PAUSED} with the current stage identity (expected job/task cleared).
 Caller must cancel in-flight expected resources after this returns.

 @return paused snapshot, or null when the scan is not armed""",
        """操作员暂停：丢弃 live cursor 使阶段完成无法推进，并持久化
 {@link #STOP_OPERATOR_PAUSED} 与当前阶段身份（清空预期 job/task）。
 调用方须在返回后取消在途预期资源。

 @return 暂停快照；scan 未 armed 时为 null""",
    ),
    (
        """Operator cancel/stop: drop the live cursor and persist {@link #STOP_OPERATOR_CANCELLED}.

 @return true when an armed cursor was cancelled""",
        """操作员取消/停止：丢弃 live cursor 并持久化 {@link #STOP_OPERATOR_CANCELLED}。

 @return armed cursor 被取消时为 true""",
    ),
    (
        """Replace the scan cursor with a new armed run/attempt. Always succeeds for a
 well-formed write; used on arm and retry.""",
        """用新 armed run/attempt 替换 scan cursor。格式良好的写入总是成功；用于 arm 与重试。""",
    ),
    (
        """AUDIT_FLOW mermaid: PATH/TRIAGE may return to OBS (sandbox_probe / new PathRun) up to
 {@link Actions#observationLoopMax()} times, then IR2 recompute, then next stage.""",
        """AUDIT_FLOW mermaid：PATH/TRIAGE 最多可回到 OBS（sandbox_probe / 新 PathRun）
 {@link Actions#observationLoopMax()} 次，然后 IR2 重算，再进入下一阶段。""",
    ),
    (
        """Server-gated PATH → REPORT contract: per-finding API + honest PoC bindings.

 <p>Never invents VERIFIED exploits. FORCED PathRuns become
 {@code INSTRUMENTATION_REACHABILITY} experiment hints, not anonymous exploit proof.</p>""",
        """服务端闸门的 PATH → REPORT 合同：逐 finding API + 诚实 PoC 绑定。

 <p>绝不捏造 VERIFIED 利用。FORCED PathRun 变为
 {@code INSTRUMENTATION_REACHABILITY} 实验提示，非匿名 exploit 证明。</p>""",
    ),
    (
        """Default unauthenticated / AUTH_GAP endpoints with no follow-on cooperation and no
 reachable RCE-class impact are {@link #REPORT_ROLE_RISK_POINT} (report bottom).
 High-impact properties and evidenced cooperation chains stay {@link #REPORT_ROLE_PRIMARY}.""",
        """默认未鉴权 / AUTH_GAP 端点，无后续配合链且无可达 RCE 类影响时，
 为 {@link #REPORT_ROLE_RISK_POINT}（报告底部）。
 高影响属性与有证据配合链保留 {@link #REPORT_ROLE_PRIMARY}。""",
    ),
    (
        """Ensures the report Markdown leads with a locale-pure Vulnerabilities section built from bindings.""",
        """确保报告 Markdown 以 locale-pure 漏洞章节开头，由 bindings 构建。""",
    ),
    (
        """Parses and serializes VULNERABILITY_TRIAGE conclusion JSON with structured rootCause,
 top-level evidenceRefs, and counterevidence. Fail-closed to INSUFFICIENT_EVIDENCE when
 required fields are missing — never routes through AUTH bypass PoC serialization.""",
        """解析并序列化 VULNERABILITY_TRIAGE 结论 JSON，含结构化 rootCause、
 顶层 evidenceRefs 与 counterevidence。缺必填字段时 fail-closed 为 INSUFFICIENT_EVIDENCE——
 绝不走 AUTH bypass PoC 序列化路径。""",
    ),
    (
        """Builds a same-scan shared memory snapshot for AI roles and the GUI debug view.
 Server-authored only; model cannot write FACT layers.""",
        """构建同 scan 共享 memory 快照，供 AI 角色与 GUI 调试视图。
 仅服务端编写；模型不能写入 FACT 层。""",
    ),
    (
        """Read-only adapter over facts/evidence already held by Veyrion. Implementations
 must not execute artifacts, open networks, invoke a shell, or decompile code.""",
        """Veyrion 已持有 facts/evidence 的只读适配器。实现不得
 执行制品、开网络、调 shell 或反编译代码。""",
    ),
    (
        """Bounded auth/config/code fact query against the registered artifact.
 Default empty; Control Plane may scan the already-authorized JAR for
 JWT defaults, skip-url patterns and auth-related class names. Never
 executes bytecode or returns raw custom secrets.""",
        """对已注册制品的有界 auth/config/code 事实查询。
 默认空；Control Plane 可扫描已授权 JAR 中的
 JWT 默认值、skip-url 模式与 auth 相关类名。绝不
 执行字节码或返回原始自定义 secret。""",
    ),
    (
        """Versioned {@code code_query} kinds. Default ignores {@code kind} and delegates
 to {@link #queryCode(ToolExecutionContext.Scope, String, int)}.
 Known kinds: METHOD_VIEW, CALLERS, CALLEES, CFG_VIEW, DATAFLOW_SLICE,
 GUARD_QUERY, FIELD_USES, CONFIG_SEARCH, AUTH, TAINT_GRAPH.""",
        """版本化 {@code code_query} kind。默认忽略 {@code kind} 并委托
 {@link #queryCode(ToolExecutionContext.Scope, String, int)}。
 已知 kind：METHOD_VIEW、CALLERS、CALLEES、CFG_VIEW、DATAFLOW_SLICE、
 GUARD_QUERY、FIELD_USES、CONFIG_SEARCH、AUTH、TAINT_GRAPH。""",
    ),
    (
        """Same-scan shared memory slice for AI roles. Default empty; Control Plane returns INDEX/FACTS/WORK/…""",
        """同 scan 共享 memory 切片，供 AI 角色。默认空；Control Plane 返回 INDEX/FACTS/WORK/…""",
    ),
    (
        """Resolves an AI/PathRun entry alias onto a canonical {@code entry:<scanEntryId>} fact.
 Default implementation only accepts an exact evidence ref; control-plane sources may
 accept bare scan ids and unambiguous {@code entry:METHOD:route} aliases.""",
        """将 AI/PathRun entry 别名解析为规范 {@code entry:<scanEntryId>} fact。
 默认实现仅接受精确 evidence ref；control-plane 源可
 接受裸 scan id 与无歧义 {@code entry:METHOD:route} 别名。""",
    ),
    (
        """Requests a server-owned, bounded loopback probe. The model supplies an
 evidence reference, candidate input hints, and optional AI-authored auth PoC
 material; the implementation derives route, sandbox, network policy and budget
 from persisted state and validates PoC bounds.""",
        """请求服务端拥有、有界的 loopback 探针。模型提供
 evidence ref、候选输入提示与可选 AI 编写的 auth PoC
 material；实现从持久化状态推导 route、sandbox、network policy 与 budget，
 并校验 PoC 边界。""",
    ),
    (
        """Attempt-scoped sandbox probe. {@code toolCallId} (canonical ToolCall.callId) forms the
 probeAttemptId with {@code jobId}; null/blank falls back to a legacy job-level attempt.""",
        """attempt 作用域 sandbox probe。{@code toolCallId}（规范 ToolCall.callId）与
 {@code jobId} 组成 probeAttemptId；null/blank 回退到 legacy job 级 attempt。""",
    ),
    (
        """Validates model-supplied hypothesis/experiment labels against the server-owned scan
 before labels are copied into a probe fact. Implementations must fail closed.""",
        """标签复制进 probe fact 前，对照服务端拥有的 scan 校验模型提供的 hypothesis/experiment 标签。
 实现必须 fail-closed。""",
    ),
    (
        """Accepts a server-gated experiment plan from {@code plan_propose}. Default is no-op;
 Control Plane sources bind the plan for later flood/focus execution.""",
        """接受来自 {@code plan_propose} 的服务端闸门 experiment plan。默认 no-op；
 Control Plane 源绑定 plan 供后续 flood/focus 执行。""",
    ),
    (
        """Parses PATH / TRIAGE {@code nextExperiments} blocks into sandbox_probe-consumable steps.
 Rejects AUTH_GAP-only narratives without PathRun or entry references.""",
        """将 PATH / TRIAGE {@code nextExperiments} 块解析为 sandbox_probe 可消费步骤。
 拒绝无 PathRun 或 entry 引用的纯 AUTH_GAP 叙事。""",
    ),
    (
        """Code-owned registry and fail-closed dispatcher. Provider adapters may expose
 {@link #definitionsFor(AgentRole)}, but cannot register handlers or alter role grants.""",
        """代码拥有的 registry 与 fail-closed 分发器。Provider 适配器可暴露
 {@link #definitionsFor(AgentRole)}，但不能注册 handler 或改变 role 授权。""",
    ),
    (
        """Server-bound scope and budget. No value in this object is read from a model
 ToolCall, and role allowlists cannot be supplied or extended by callers.""",
        """服务端绑定的 scope 与 budget。本对象中无值来自模型
 ToolCall，调用方不能提供或扩展 role allowlist。""",
    ),
    (
        """Structured root-cause output for VULNERABILITY_TRIAGE / REPORT_GENERATION.""",
        """VULNERABILITY_TRIAGE / REPORT_GENERATION 的结构化 root-cause 输出。""",
    ),
    (
        """Versioned AI job/stage DTOs. Model output is structurally limited to INFERENCE.""",
        """版本化 AI job/stage DTO。模型输出结构上限于 INFERENCE。""",
    ),
    (
        """Workspace-scoped persistence boundary for AI data-flow state.""",
        """AI 数据流状态的 workspace 作用域持久化边界。""",
    ),
    (
        """PATH findingBindings + REPORT locale-pure Vulnerabilities section from FORCED/STATIC materials.""",
        """PATH findingBindings + 由 FORCED/STATIC 材料构建 REPORT locale-pure 漏洞章节。""",
    ),
    (
        """P0-07: VULNERABILITY_TRIAGE conclusionJson retains structured rootCause and non-empty
 evidenceRefs; AUTH PoC serialization must not empty those fields.""",
        """P0-07：VULNERABILITY_TRIAGE conclusionJson 保留结构化 rootCause 与非空
 evidenceRefs；AUTH PoC 序列化不得清空这些字段。""",
    ),
    (
        """Main-style negative acceptance checks for the canonical AI tool boundary.""",
        """规范 AI 工具边界的 main 风格负向验收检查。""",
    ),
    (
        """P0-14: sandbox_probe rejects command/image/mount/network/UID/budget overflow fields
 (schema additionalProperties=false / UNKNOWN_ARGUMENT).""",
        """P0-14：sandbox_probe 拒绝 command/image/mount/network/UID/budget 溢出字段
 （schema additionalProperties=false / UNKNOWN_ARGUMENT）。""",
    ),
    (
        """Focused acceptance checks for entry ref aliasing used by plan_propose / sandbox_probe.""",
        """plan_propose / sandbox_probe 所用 entry ref 别名的聚焦验收检查。""",
    ),
    (
        """P0-07 residual: ControlPlaneStore.attachTriageFinding keeps structured rootCause for dashboard.""",
        """P0-07 残余：ControlPlaneStore.attachTriageFinding 为 dashboard 保留结构化 rootCause。""",
    ),
    (
        """P0-05: PATH/TRIAGE sandbox_probe requires track/objective/(coverageGapRef).""",
        """P0-05：PATH/TRIAGE sandbox_probe 要求 track/objective/(coverageGapRef)。""",
    ),
    (
        """Acceptance: §2.3 six-role prompt inject sections and default roleInstruction markers.
 Captures first-round user prompts via mock ChatTransport; does not call a live LLM.""",
        """验收：§2.3 六角色 prompt 注入段与默认 roleInstruction 标记。
 经 mock ChatTransport 捕获首轮 user prompt；不调用真实 LLM。""",
    ),
    (
        """Verifies same-scan shared memory snapshot shape for AI + GUI.
 Uses in-memory store (no SQLite Jackson encode path).""",
        """验证同 scan 共享 memory 快照形状，供 AI + GUI。
 使用内存 store（无 SQLite Jackson 编码路径）。""",
    ),
    (
        """AUTH AI-authored bypass PoCs are schema-gated, persisted, injected into DYNAMIC,
 and invalid candidates are rejected. Auth-surface scans reject silent empty PoCs
 (re-ask / RULE_GENERATED seed). Non-empty feasibility forces DYNAMIC sandbox_probe
 attempt (re-ask / server auto-enqueue).""",
        """AUTH 模型编写的 bypass PoC 经 schema 闸门、持久化并注入 DYNAMIC，
 无效候选被拒绝。鉴权面 scan 拒绝静默空 PoC
 （re-ask / RULE_GENERATED 种子）。非空 feasibility 强制 DYNAMIC sandbox_probe
 尝试（re-ask / 服务端自动入队）。""",
    ),
    (
        """P0-03: independent probeAttemptId, payload-hash conflict, and effective-attempt counting.""",
        """P0-03：独立 probeAttemptId、payload-hash 冲突与有效 attempt 计数。""",
    ),
    (
        """P0-11: versioned code_query kinds with IR fail-closed and AUTH gate semantics.""",
        """P0-11：版本化 code_query kind，IR fail-closed 与 AUTH 门禁语义。""",
    ),
    (
        """P0-11: PATH_EXPLORATION sandbox_probe allowlist / prompt / schema contract unity.""",
        """P0-11：PATH_EXPLORATION sandbox_probe allowlist / prompt / schema 合同一致性。""",
    ),
    (
        """AUTH code_query harvest + DEFAULT_SECRET_HS256 seed only when key found in artifact
 (acceptance only; not VERIFIED / production).""",
        """AUTH code_query harvest + 仅当制品中发现 key 才种子 DEFAULT_SECRET_HS256
 （仅验收；非 VERIFIED / 生产）。""",
    ),
    (
        """P1-05: PATH/TRIAGE nextExperiments must be PathRun-grounded and sandbox_probe-consumable.""",
        """P1-05：PATH/TRIAGE nextExperiments 须基于 PathRun 且 sandbox_probe 可消费。""",
    ),
    (
        """P0-04: AUTH code_query / multi-PoC diversity / authPass identity gates (pure unit slice).""",
        """P0-04：AUTH code_query / 多 PoC 多样化 / authPass 身份闸门（纯单元切片）。""",
    ),
]

# Single-line // and /** ... */ inner line replacements (prefix stripped in matcher)
LINE: dict[str, str] = {
    "DYNAMIC must attempt sandbox_probe when AUTH handed non-empty PoCs.": "AUTH 移交非空 PoC 时 DYNAMIC 必须尝试 sandbox_probe。",
    "Prompt target band: attempt this many distinct PoCs before narrative-only.": "Prompt 目标区间：叙事-only 前先尝试此数量的 distinct PoC。",
    "Server auto-enqueue fallback cap (wall-clock / scan-busy aware).": "服务端自动入队回退上限（感知 wall-clock / scan-busy）。",
    "AUTH must diversify to at least this many mechanism/path keys when surface present.": "鉴权面存在时 AUTH 须多样化至少此数量的 mechanism/path key。",
    "P3: AUTH confirm must distinguish static hypothesis from PathRun dynamic contrast.": "P3：AUTH 确认须区分静态 hypothesis 与 PathRun 动态对比。",
    "Legacy flat field for dashboards that already read confirmationStatus.": "供已读 confirmationStatus 的 dashboard 使用的 legacy 扁平字段。",
    "COVERAGE / FORCED HTTP 2xx–3xx with entry hit — gate-pass signal for confirm scheduling.": "COVERAGE / FORCED HTTP 2xx–3xx 且 entry hit——确认调度的过闸信号。",
    "EntryRef formats differ (entry:<id> vs entry:METHOD:/route); fall back to scan-wide signals.": "EntryRef 格式不同（entry:<id> vs entry:METHOD:/route）；回退到 scan 级信号。",
    "Fall through to embedded object scan.": "继续扫描内嵌 object。",
    "PathRun entry refs are often entry:METHOD:/route while PoCs use entry:<id>.": "PathRun entry ref 常为 entry:METHOD:/route，PoC 用 entry:<id>。",
    "Empty PoCs are incomplete when the scan exposes an auth surface.": "scan 暴露鉴权面时空 PoC 视为不完整。",
    "Distinct entry+technique(+payload) mechanisms; used for AUTH multi-PoC band.": "distinct entry+technique(+payload) 机制；用于 AUTH 多 PoC 区间。",
    "Pass 1: one PoC per entryRef (auth-material first).": "Pass 1：每个 entryRef 一个 PoC（auth-material 优先）。",
    "Pass 2: fill remaining slots with unused technique/entry pairs.": "Pass 2：用未使用的 technique/entry 对填充剩余槽位。",
    "True when scan entries suggest an adapter that prefers a secondary auth header.": "scan entry 表明适配器偏好 secondary auth header 时为 true。",
    "Drop corrupted persisted rows fail-closed.": "丢弃损坏的持久化行，fail-closed。",
    "Fall through.": "继续向下。",
    "continue": "继续",
    "Create a QUEUED AI job; caller binds identity before submit.": "创建 QUEUED AI job；调用方在 submit 前绑定身份。",
    "Enqueue the pipeline dynamic observation task and return its taskId.": "入队 pipeline dynamic observation task 并返回 taskId。",
    "Observe current job status for restart reconciliation.": "观察当前 job 状态以供重启协调。",
    "Observe job stopReason (e.g. PROCESS_RESTARTED) for precise disarm labels.": "观察 job stopReason（如 PROCESS_RESTARTED）以精确 disarm 标签。",
    "Observe current task lifecycle name for restart reconciliation.": "观察当前 task lifecycle 名称以供重启协调。",
    "IR2: full detector recompute after PathTrace/PathRun observation (AUDIT_FLOW mermaid).": "IR2：PathTrace/PathRun 观测后全量 detector 重算（AUDIT_FLOW mermaid）。",
    "Max PATH/TRIAGE ↔ OBS feedback loops; default from env/prop or 3.": "PATH/TRIAGE ↔ OBS 反馈循环上限；默认来自 env/prop 或 3。",
    "Visible for tests: parse loop cap from env then system property.": "测试可见：先从 env 再从 system property 解析循环上限。",
    "After a PATH/TRIAGE-driven OBS loop, resume this AI stage (not AUTH_BYPASS_CONFIRM).": "PATH/TRIAGE 驱动的 OBS 循环后，恢复此 AI 阶段（非 AUTH_BYPASS_CONFIRM）。",
    "Per-scan count of PATH/TRIAGE → OBS feedback loops consumed.": "每 scan 已消耗的 PATH/TRIAGE → OBS 反馈循环次数。",
    "Persisted stopReason when an operator pauses an armed pipeline.": "操作员暂停 armed pipeline 时的持久化 stopReason。",
    "Persisted stopReason when an operator cancels/stops an armed pipeline.": "操作员取消/停止 armed pipeline 时的持久化 stopReason。",
    "AUDIT_FLOW: DYNAMIC_DISABLED keeps static narrative — do not abort the pipeline.": "AUDIT_FLOW：DYNAMIC_DISABLED 保留静态叙事——勿中止 pipeline。",
    "Worker missing / dynamic disabled: continue AI stages on static facts only.": "Worker 缺失 / dynamic 禁用：仅基于静态 fact 继续 AI 阶段。",
    "Still QUEUED/RUNNING — wait; do not re-enqueue.": "仍 QUEUED/RUNNING——等待；勿重新入队。",
    "Armed stage without expected resource: recover by enqueueing once for this attempt.": "armed 阶段无预期资源：本 attempt 入队一次以恢复。",
    "IR2 is best-effort; stage advancement must not stall.": "IR2 为 best-effort；阶段推进不得卡住。",
    "IR2 best-effort.": "IR2 best-effort。",
    "First observation after AUTH: confirm only when dynamic auth evidence exists.": "AUTH 后首次观测：仅当存在动态 auth 证据时才确认。",
    "Dynamic unavailable: skip AUTH confirm (no evidence) and continue static-capable AI stages.": "dynamic 不可用：跳过 AUTH 确认（无证据）并继续可静态 AI 阶段。",
    "A non-pipeline dynamic task is still running; keep the stage attempt and wait": "非 pipeline dynamic task 仍在运行；保持阶段 attempt 并等待",
    "until the pipeline-owned enqueue can proceed. Do not bind foreign task ids.": "直至 pipeline 拥有的入队可继续。勿绑定外来 task id。",
    "A terminal callback can arrive before expectedTaskId is bound.": "终态回调可能在 expectedTaskId 绑定前到达。",
    "Reconcile the exact task after binding so it cannot be lost.": "绑定后协调精确 task，避免丢失。",
    "Enqueued task already terminal without COMPLETED — static continue when possible.": "已入队 task 已终态且非 COMPLETED——尽可能静态继续。",
    "Sandbox/worker unavailable at enqueue: keep static AI narrative (AUDIT_FLOW).": "入队时 sandbox/worker 不可用：保留静态 AI 叙事（AUDIT_FLOW）。",
    "Bindings must not mint elevation; callers pass through only server status.": "binding 不得铸造提升；调用方仅透传服务端 status。",
    "Backward-compatible overload (defaults to PRIMARY).": "向后兼容重载（默认 PRIMARY）。",
    "Never elevate via bindings.": "binding 绝不提升。",
    "Try METHOD:route form from finding.entry": "尝试 finding.entry 的 METHOD:route 形式",
    "Replace thin section by prepending server section and keeping the rest.": "前置服务端章节并保留其余内容，替换薄弱章节。",
    "Keep content after wrong header's first line block until next ## of correct language — simple drop.": "错误标题首行块之后到下一正确语言 ## 之前的内容——简单丢弃。",
    "Merge AI-provided bindings with server assembly; server fills gaps, never elevates.": "合并 AI 提供的 binding 与服务端装配；服务端填缺口，绝不提升。",
    "Prefer server PoC when AI omitted steps; keep AI description if richer and locale-consistent.": "AI 缺步骤时优先服务端 PoC；AI 描述更丰富且 locale 一致则保留。",
    "Keep INFERENCE as a deprecated alias only when explicitly present on older payloads.": "仅当旧 payload 显式存在时保留 INFERENCE 作 deprecated 别名。",
    "Wire-safe map for FindingDto.rootCause (includes optional counterevidence).": "FindingDto.rootCause 的 wire-safe map（含可选 counterevidence）。",
    "Compact INDEX section for prompt injection.": "供 prompt 注入的紧凑 INDEX 分区。",
    "Also accept nextValidationSteps alias.": "亦接受 nextValidationSteps 别名。",
    "STATIC_ONLY contrast may inform planning but must not claim bypass/confirmed.": "STATIC_ONLY 对比可指导规划，但不得声称 bypass/confirmed。",
    "Declared schema fields (e.g. scan_memory_get.role for ROLE_SLICE) are allowed;": "已声明 schema 字段（如 scan_memory_get.role 用于 ROLE_SLICE）允许；",
    "undeclared reserved names still mean model-controlled scope/authority.": "未声明保留名仍表示模型控制的 scope/authority。",
    "Server-gate optional PathRun experiment fields only when entry:* is proposed.": "仅当提出 entry:* 时对可选 PathRun experiment 字段做服务端闸门。",
    "Validate bounds via candidate constructor without requiring a technique enum.": "经 candidate 构造器校验边界，不要求 technique enum。",
    "Prefer first non-blank among named JSON args (generic name before deprecated alias).": "命名 JSON 参数中取首个非 blank（通用名优先于 deprecated 别名）。",
    "Stable uppercase codes thrown by control-plane / candidate gates.": "control-plane / candidate 闸门抛出的稳定大写 code。",
    "Required strings must be non-blank; optional strings may be \"\" (e.g. MISSING_AUTH).": "必填字符串须非 blank；可选字符串可为 \"\"（如 MISSING_AUTH）。",
    "Optional strings may be blank (MISSING_AUTH authorizationHeader:\"\");": "可选字符串可为 blank（MISSING_AUTH authorizationHeader:\"\"）；",
    "required non-blank is enforced in ToolSchema.validate.": "必填非 blank 在 ToolSchema.validate 中强制。",
    "Legacy test sources have no hypothesis store; they cannot authorize a binding.": "Legacy 测试源无 hypothesis store；不能授权 binding。",
    "Coverage gap ids (taintPathId) for PATH_EXPLORATION sandbox_probe gating.": "PATH_EXPLORATION sandbox_probe 闸门的 coverage gap id（taintPathId）。",
    "optional": "可选",
    "Deliberately has no VERIFIED option.": "故意不提供 VERIFIED 选项。",
    "REPORT: coverage matrix gap summary; SUCCESS must not be described as safe/secure.": "REPORT：coverage matrix gap 摘要；SUCCESS 不得描述为 safe/secure。",
    "facts_search kind=PATH_TRACE rejects client policy override fields.": "facts_search kind=PATH_TRACE 拒绝客户端 policy 覆盖字段。",
    "Regression: schema field role= must not hit MODEL_CONTROLLED_SCOPE_OR_AUTHORITY.": "回归：schema 字段 role= 不得触发 MODEL_CONTROLLED_SCOPE_OR_AUTHORITY。",
    "Undeclared reserved authority field still denied.": "未声明的保留 authority 字段仍拒绝。",
    "Live bug: model passed authorizationHeader:\"\" for MISSING_AUTH → ARGUMENT_SCHEMA_MISMATCH.": "线上 bug：MISSING_AUTH 时模型传 authorizationHeader:\"\" → ARGUMENT_SCHEMA_MISMATCH。",
    "Optional bladeAuthHeader may be blank/omitted; channels stay independent.": "可选 bladeAuthHeader 可为 blank/省略；通道保持独立。",
    "JWT / AUTH_GAP surface + empty AUTH conclusion → re-ask then RULE_GENERATED drafts.": "JWT / AUTH_GAP 面 + 空 AUTH 结论 → re-ask 后 RULE_GENERATED 草稿。",
    "Satisfy AUTH_CODE_QUERY_REQUIRED once, then keep omitting bypassPoCs so seed path runs.": "满足 AUTH_CODE_QUERY_REQUIRED 一次，然后继续省略 bypassPoCs 以走种子路径。",
    "Always omit structured bypassPoCs so server must re-ask then seed.": "始终省略结构化 bypassPoCs，迫使服务端 re-ask 后种子。",
    "Surface detector with JWT finding but zero entries still reports incomplete (no silent OK).": "JWT finding 但零 entry 时 surface 检测器仍报 incomplete（无静默 OK）。",
    "Non-empty AUTH feasibility + narrative-only DYNAMIC → re-ask → sandbox_probe.": "非空 AUTH feasibility + 叙事-only DYNAMIC → re-ask → sandbox_probe。",
    "Repair turn is distinct from role-prompt mention of the same code.": "repair 轮次与 role-prompt 提及同一 code 不同。",
    "Narrative-only after re-ask → server auto-enqueues focused probes (AUTH-seed analogue).": "re-ask 后仍叙事-only → 服务端自动入队聚焦探针（AUTH-seed 类比）。",
    "Always narrative-only so re-ask then server seed/auto-enqueue fires.": "始终叙事-only 以触发 re-ask 后服务端种子/自动入队。",
    "Auto-enqueue uses synthetic toolCallId dyn-poc-N under the real AI job id.": "自动入队在真实 AI job id 下使用合成 toolCallId dyn-poc-N。",
    "P0-05: zero dynamic PathRun evidence cannot yield DYNAMIC_CONTRAST / confirmed.": "P0-05：零动态 PathRun 证据不得产生 DYNAMIC_CONTRAST / confirmed。",
    "Reflection-safe contract: without IR methods, any SUCCESS counts; with IR methods,": "反射安全合同：无 IR methods 时任一 SUCCESS 计数；有 IR methods 时，",
    "only METHOD_VIEW / GUARD_QUERY kinds count. Simulate via hasNonEmptyMethodsIr + kind check.": "仅 METHOD_VIEW / GUARD_QUERY kind 计数。经 hasNonEmptyMethodsIr + kind 检查模拟。",
    "best-effort temp cleanup": "best-effort 临时清理",
    "ignore": "忽略",
    "STATIC_ONLY contrast must not elevate to bypassed/confirmed; AUTH_GAP gate unchanged.": "STATIC_ONLY 对比不得提升为 bypassed/confirmed；AUTH_GAP 闸门不变。",
    "Touch ApiDtos schema constant so finding/report consumers stay aligned.": "触及 ApiDtos schema 常量以保持 finding/report 消费者对齐。",
    "P0-05 residual: PATH/TRIAGE only consumable projected PathRuns enter next-round conclusions.": "P0-05 残余：PATH/TRIAGE 仅可消费已投影 PathRun 进入下一轮结论。",
    "Seed TRIAGE conclusion so REPORT can inject fixSuggestion from prior rootCause.": "种子 TRIAGE 结论以便 REPORT 从先前 rootCause 注入 fixSuggestion。",
    "In-memory path: put scan directly via saveScan without artifact persistence.": "内存路径：经 saveScan 直接放入 scan，无 artifact 持久化。",
    "Some store builds require an artifact; fall back to reflection-free map build": "部分 store 构建需要 artifact；回退到无反射 map 构建",
    "by injecting via requireScan after a minimal register is unavailable in-memory.": "在内存中无法最小 register 时经 requireScan 注入。",
    "Env / system property for PATH/TRIAGE → OBS feedback loop cap (AUDIT_FLOW mermaid).": "PATH/TRIAGE → OBS 反馈循环上限的 env / system property（AUDIT_FLOW mermaid）。",
    "common typo alias": "常见拼写别名",
    "deprecated wire alias": "deprecated wire 别名",
    "??????? JSON ?????": "数据源共享 JSON 工具类。",
}

# Files may have partial Chinese already - skip lines that are mostly CJK
CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def has_substantial_cjk(text: str) -> bool:
    cjk = len(CJK_RE.findall(text))
    latin_words = len(re.findall(r"[A-Za-z]{3,}", text))
    return cjk >= 2 and cjk >= latin_words


def strip_javadoc_markers(text: str) -> str:
    lines = []
    for line in text.split("\n"):
        s = line.strip()
        if s.startswith("*"):
            s = s[1:].strip()
        if s.startswith("/"):
            continue
        lines.append(s)
    return "\n".join(lines)


def normalize_block(s: str) -> str:
    return re.sub(r"\s+", " ", strip_javadoc_markers(s).strip())


def translate_comment_body(body: str) -> str | None:
    stripped = body.strip()
    if not stripped or has_substantial_cjk(strip_javadoc_markers(stripped)):
        return None
    # block match
    norm = normalize_block(stripped)
    for eng, zh in BLOCKS:
        if normalize_block(eng) == norm:
            return zh
    # line-by-line for multi-line
    lines = stripped.split("\n")
    if len(lines) > 1:
        out_lines = []
        changed = False
        for line in lines:
            inner = line.strip()
            if inner.startswith("*"):
                inner = inner[1:].strip()
            if not inner or has_substantial_cjk(inner):
                out_lines.append(line)
                continue
            repl = LINE.get(inner)
            if repl:
                prefix = line[: len(line) - len(line.lstrip())]
                star = "* " if line.strip().startswith("*") else ""
                out_lines.append(prefix + star + repl)
                changed = True
            else:
                out_lines.append(line)
        if changed:
            return "\n".join(out_lines)
    # single line
    inner = stripped.lstrip("* ").strip()
    if inner in LINE:
        return LINE[inner]
    return None


COMMENT_PATTERNS = [
    (re.compile(r"/\*\*(.*?)\*/", re.DOTALL), "javadoc"),
    (re.compile(r"/\*(?!\*)(.*?)\*/", re.DOTALL), "block"),
    (re.compile(r"(//[^\n]*)", re.MULTILINE), "line"),
]


def format_javadoc(body: str, original: str) -> str:
    """Preserve /** ... */ structure with leading * lines."""
    lines = body.strip().split("\n")
    if "\n" not in original.strip().strip("*").strip() and len(lines) <= 1:
        return "/** " + body.strip() + " */"
    out = ["/**"]
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("*"):
            stripped = stripped[1:].strip()
        out.append(" * " + stripped if stripped else " *")
    out.append(" */")
    return "\n".join(out)


def process_file(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    original = text

    def repl_javadoc(m: re.Match) -> str:
        body = m.group(1)
        new_body = translate_comment_body(body)
        if new_body is None:
            return m.group(0)
        return format_javadoc(new_body, m.group(0))

    def repl_block(m: re.Match) -> str:
        body = m.group(1)
        new_body = translate_comment_body(body)
        if new_body is None:
            return m.group(0)
        if "\n" in new_body:
            indented = "\n * ".join(new_body.split("\n"))
            return "/*\n * " + indented + "\n */"
        return "/* " + new_body + " */"

    def repl_line(m: re.Match) -> str:
        full = m.group(0)
        content = full[2:].strip()
        if not content or has_substantial_cjk(content):
            return full
        if content in LINE:
            return "// " + LINE[content]
        return full

    text = re.sub(r"/\*\*(.*?)\*/", repl_javadoc, text, flags=re.DOTALL)
    text = re.sub(r"/\*(?!\*)(.*?)\*/", repl_block, text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", repl_line, text)

    if text != original:
        path.write_text(text, encoding="utf-8")
        return True
    return False


def main() -> int:
    touched = 0
    for d in DIRS:
        for path in sorted(d.rglob("*.java")):
            if process_file(path):
                touched += 1
                print(path.relative_to(ROOT))
    print(f"\nTouched {touched} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

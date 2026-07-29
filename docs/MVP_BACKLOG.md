# 溯脉 · Veyrion MVP Backlog

> 更新：2026-07-29（实战召回复核）。本文是唯一的实现状态与待办文档。未经根 Agent 审计的能力不得标为已验证或生产可用。产品合同见 [PRD](PRD.md)，执行合同见 [AUDIT_FLOW](AUDIT_FLOW.md)。

## 0. 根 Agent 审计

### 0.1 初审摘要

P0 主体升 `AUDITED`；明确延后 gVisor/Kata 与生产 SSO；`VERIFIED` 恒关。

### 0.2 再审计（PARTIAL 推进后，2026-07-28）

| 项 | 内容 |
|----|------|
| 命令 | `JAVA_HOME=<IntelliJ JBR>`；`mvn -q -DskipTests compile test-compile`；`java -cp "target/classes;target/test-classes;$(Get-Content target/cp.txt)" com.aq.jvmsentinel.AcceptanceTestRunner` |
| 结果 | 历史基线 **PASS** — 官方 curated gate 已通过，具体数字以运行日志为准 |
| 本轮确认 AUDITED | P0-13；P1-01…08；P1-20…24；矩阵 Universe/IR/SPI/Detector/多语言/AI Job/PathRun/GUI/`DYNAMIC_CONFIRMED`/依赖替身/动态执行（fail-closed+loopback） |
| 仍 SCAFFOLDING / 延后 | `VERIFIED`；gVisor·Kata；逃逸套件；Desktop DryRun；WAR 动态；生产 SSO；JsRuntime 无动态 cap |
| 明确延后（不变） | gVisor/Kata 真实启用；生产 session/CSRF/SSO/多租户/保留；开放 `VERIFIED` |
| 恒关闭 | `VERIFIED_GATE_NOT_OPEN`；`TRUSTED_DOCKER_NEVER_VERIFIED`；`ProductionFeatures.DISABLED`；`HARDENED_ENABLEMENT_NOT_OPEN` |
| `AUDITED` 免责 | fixture/本地合同；≠ 恶意制品隔离 / 外网 Provider / 生产隔离 / 完整 IFDS |
| Findings | 无阻断缺陷。不足见 §8。当时 ADR-0002/0003 仍 `PROPOSED` |

### 0.3 三项优化后复核（2026-07-28）

| 项 | 内容 |
|----|------|
| 命令 | 同上；完整 `AcceptanceTestRunner` |
| 结果 | **PASS** — `executed=50`，`assertions=2139`（官方 curated gate） |
| 本次环境证据 | Docker 不可用：Docker 多请求与 Postgres H3 live 分支 `SKIP`，保留 fixture 断言；`VEYRION_LIVE_PROVIDER` 未设置，仅 loopback Provider 通过 |
| 优化2 静态加深 | MethodSummary/Sanitizer 启发式；`METHOD_VIEW` 伪反编译；Boot lib 一层展开；P2 STATE/CONCURRENCY holdout+RecallGate；**ADR-0002 → `ACCEPTED`** |
| 优化3 工程 | `scripts/generate-contract-types.ps1` → `frontend/src/generated/contracts.ts`；Surefire→`AcceptanceTestGate`；更多 scan/provider 查询经 application.port |
| 仍延后 | gVisor/Kata；`VERIFIED`；生产 SSO（ADR-0003 `PROPOSED`）；进程外重型静态引擎 |
| Findings | 已修复本轮阻断缺陷；Provider ArtifactNodes/MethodSummary/DynamicProbe 主流程消费仍为 `PARTIAL`，live Agent correlation、外部 Provider 与 hardened sandbox 未复验。不足见 §8 |

拒绝路径复核：sandbox 非法字段；非 DATAFLOW 不可 `DYNAMIC_CONFIRMED`；Verified/Hardened/ProductionFeatures；DetectorRecallGate；subprocess Analyzer。

### 0.4 实战召回复核（2026-07-29）

| 项 | 内容 |
|----|------|
| 触发 | 授权制品扫描 `scan-7b619e8a65064fa9` 暴露动态路径和真实漏洞发现能力严重不足 |
| 观察 | 历史数据出现 `2036` 条 PathRun，其中 `1935` 条为 `DYNAMIC_SUSPECTED / httpStatus=-1 / outcomeClass=UNKNOWN / identityProvenance=MOCK`；最大来源任务 `task-dynamic-3c5ac1abe4994477` 产生 `1838` 条无效动态疑似 |
| 补充（2026-07-29） | `scan-28ab5e591f4d4b5a`（Blade）：266 PathRun → 184×401 `AUTH_CHALLENGE`（曾误标 `DYNAMIC_SUSPECTED`）、56×超时、25×MOCK gap、1×200；261×UNAUTH / 5×BYPASS；`parameterBound` 全空。鉴权墙 + 身份材料缺口 + 无计划洪水，仍未进入业务代码 |
| 结论 | 现有 `AUDITED` 多数只代表 fixture 合同和安全拒绝路径通过，不代表真实 JAR 漏洞召回可用；当前 MVP 的最低可靠能力仍是静态入口、调用边、sink 与部分 Security IR |
| 根因 | 动态洪水没有按 entry signature、0-n 参数空间、身份轨和下游 effect/guard/state 观测组织，导致通用 HTTP 探测替代了真实路径探索；依赖替身只让应用尽量启动，不能补齐业务状态、鉴权上下文和数据种子；PathRun/RuntimeObservation 与 detector 重算闭环薄；AI 阶段更多在解释失败结果，没有获得足够代码语义和可执行实验计划 |
| 状态调整 | 动态执行、PathRun 驱动 triage、Provider DynamicProbe 主流程、非污点 detector 的实战召回统一按 `PARTIAL` 看待；不得再用 gate PASS 描述为“基本可用漏洞挖掘”；系统性格局见 **P0-21** |
| 产品取舍 | MVP 先回到“静态事实可靠召回 + 动态用于证伪/复现/补证”的路线。动态沙箱在完成 P0-15 到 P0-21 前，不作为主发现引擎，也不应覆盖静态 sink 结果排序 |

## 1. 状态图例

| 状态 | 含义 |
|------|------|
| `AUDITED` | 代码与对应验收材料已审阅；只对声明范围有效 |
| `PARTIAL` | 主体存在，但存在未闭合路径、未复验环境或证据不足 |
| `SCAFFOLDING` | schema/API/门禁骨架存在，能力未开放 |
| `NOT STARTED` | 尚无可审计实现 |

`AUDITED` 只说明声明范围内的合同、fixture 或安全拒绝路径已通过；不能自动外推为真实项目召回率、动态可用性或漏洞确认能力。涉及“能否挖到漏洞”的判断必须同时给出基准样例、保留集、实战扫描对照和失败样本统计。

`TRUSTED_DOCKER` live 结果只证明受信本地 JAR 的开发调试，不代表恶意制品隔离。main-style acceptance 只有被显式执行且断言生效时才算测试证据；`mvn test` 通过 Surefire 运行官方 curated gate；它不是仓库全部 acceptance 类的自动枚举。官方非零门禁以 `AcceptanceTestRunner` / `scripts/ci-gates.ps1` 为准。

## 2. 当前能力矩阵

| 领域 | 状态 | 已有能力 | 诚实边界 |
|------|------|----------|----------|
| 制品导入 | `AUDITED` | JAR/WAR/CLASS 有界读取；分块上传与内容寻址副本 | 动态主路径仅 Boot JAR |
| 静态入口 | `AUDITED` | Spring mapping、参数/鉴权注解、调用点、sink | 运行时注册、反射、代理不保证 |
| 调用图/污点 | `AUDITED` | 制品内 DIRECT/CHA/UNRESOLVED；有界 TaintPath；`BytecodeFactIndex` schemaVersion=3（读 1/2）+ taint/coverage/可选 Universe 持久化；有 facts 行时 contrast 只用 persisted IR | 声明范围=持久化权威与跨方法绑定 fixture；非完整别名/IFDS；TRUNCATED；LEGACY 无行仍 stub |
| Artifact Universe | `AUDITED` | `domain.universe` + `ArtifactUniverseBuilder`：APPLICATION/THIRD_PARTY/GENERATED/UNKNOWN；Boot/`WEB-INF` lib **有界一层展开**（jar 内 class 计数上限 + 截断 CoverageGap）；CoverageGap（含 MULTI_VERSION_CLASS / runtime-only / static-not-loaded）；`StaticFactSnapshot` schemaVersion=4；`mergeRuntimeLoadedClasses` 接 CoverageMatrix；`ArtifactUniverseAcceptanceTest` | 声明范围=fixture Universe/一层展开/runtime 列表差分；二层以上嵌套与 live Agent 类列表不在范围 |
| Security IR / Evidence Graph | `AUDITED` | `domain.ir` + `EvidenceGraphProjector`；权威图写入 `StaticFactSnapshot.evidenceGraph`（schema v4）；finding↔node 双向 refs；`GET .../evidence-graph`；`EvidenceGraphAcceptanceTest` | 声明范围=扫描时持久化投影与双向 join；PathRun 增量重投影与完美 IR 不在范围 |
| Provider SPI | `PARTIAL` | 九类 Provider 接口、Registry/OutputGate、scope/schema/budget/dedupe 门禁；entry/effect/guard/detector 已进入扫描；MethodSummary/Sanitizer 有 kernel 启发式实现 | ArtifactNodes、Provider MethodSummary、DynamicProbe 尚未全部进入主扫描投影；完整插件市场与精确 sanitizer 证明不在范围 |
| 多类 Detector | `PARTIAL` | P1-05 GuardConsistency/OwnershipIdor/DangerousConfig + deser/dep/resource；P2 StateSequence/ConcurrencyResource 正负+holdout + `DetectorRecallGate`；经 `DetectorRegistry` 合并 | fixture/mutation/holdout 通过，但实战召回未达标；深度 dominance/IFDS/真实并发与生产 release 未做；非 SQL `DYNAMIC_CONFIRMED` fail-closed |
| SecurityHypothesis | `PARTIAL` | V023+V024；sink→DATAFLOW / AUTH_GAP→GUARD_COVERAGE；Finding 可选 hypothesis 字段；GUI family 列表；PathRun 成功投影可 CANDIDATE→SUPPORTED/CONTRADICTED | schema/投影存在，但 hypothesis 排序、实验规划、受影响 detector 重算和实战闭环不足；live Docker 全链路未成为可靠 triage 输入 |
| 多语言边界 | `AUDITED` | P1-07 真实子进程 Test Analyzer + 同进程 Fake；P1-08 查询端口；`TestJsLanguageAnalyzer` 非 JVM ProgramNode 复用同一 store/hypothesis/coverage/GUI 降级；`JsRuntimeAdapter` 默认无动态 capability | 声明范围=Fake+子进程合同；真实多进程 JS Analyzer/Node Worker 未接 |
| Control Plane | `AUDITED` | loopback REST/SSE、PAT、显式授权、持久化幂等；scan/evidence/coverage/hypothesis/finding/PathRun 查询经 application.port | **生产 SSO 栈延后**（`ProductionFeatures.DISABLED` / ADR-0003 PROPOSED）；大爆炸拆分未做 |
| SQLite | `AUDITED` | V001-V024；项目、扫描、AI、Worker、trace、PathRun、pipeline identity、hypotheses 等；Evidence Graph 权威投影随 `taint_graphs` StaticFactSnapshot schema v4（V024 将 hypothesis 主键限定为 scan scope） | 单节点，不是 exactly-once |
| AI Job | `AUDITED` | 六角色、Provider 适配、有界工具、双语 prompt snapshot；角色工具合同 fixture（P0-04/05/11） | 声明范围=fixture/模拟 transport；真实供应商/外网出站互操作见 P1-24 限制 |
| 动态执行 | `PARTIAL` | STATIC_ONLY、TRUSTED_DOCKER、Agent、loopback；无 Worker→`WORKER_UNAVAILABLE`/`DYNAMIC_DISABLED`；断网容器可保留给后续 probe | 安全边界和 fixture 通过，但真实 JAR 启动、业务状态、端口识别、依赖替身和多轮发包仍弱；动态不能替代静态召回；**gVisor/Kata 延后** |
| 依赖替身 | `PARTIAL` | HTTP/JDBC/Redis/MySQL 有界子集；MOCK provenance 标注测试（H3/PathRun） | 替身主要帮助启动，不等于业务依赖可用；缺表/缺数据/协议细节会导致路径不可达或假阴性 |
| PathRun | `PARTIAL` | 身份轨、超时、HTTP/Agent/SQL 摘要、请求窗 SQL、correlationId；H3/report→replay correlation fixture；成功投影可驱动 hypothesis lifecycle | fixture 通过，但实战存在无效 PathRun 洪水历史；仍需请求级 guard/effect/state 观测、失败分类和 detector 增量闭环 |
| AUTH PoC | `AUDITED` | 多轮门禁、code_query kinds、PoC 多样性（模拟 transport） | 完整反编译/SSA 与真实 Provider 多轮不在范围内 |
| 代码查询 | `AUDITED` | kind 路由 + instructionSlice/basicBlocks + PATH prompt/schema 统一 | 非完整反编译/SSA/IFDS；LEGACY 无 IR fail-closed |
| PATH/TRIAGE probe | `PARTIAL` | gap/字段闸门、预算、无效 probe→缺口；sandbox 非法字段拒绝 | 工具安全合同通过，但缺少从 hypothesis 编译可执行实验、真实业务 payload 和多轮本地发包确认；不能作为当前主发现能力 |
| GUI | `PARTIAL` | 工作区/报告/Coverage/Hypothesis/Evidence；semantics/layout 合同测试 | 合同语义可审，但最终报告结果页功能堆叠、视觉层级和动态失败降噪不足；生产隐私/保留随 SSO 延后 |
| `DYNAMIC_CONFIRMED` | `AUDITED` | SQL H3 门禁 + 同 PathRun correlation/marker 正负 fixture | 声明范围=fixture；非 live 实库 |
| `VERIFIED` | `SCAFFOLDING` | 双重重放+release 仍 `VERIFIED_GATE_NOT_OPEN` | **根审计：明确延后开放**；TRUSTED_DOCKER 永久排除 |
| 自动化测试 | `AUDITED` | Surefire→`AcceptanceTestGate`→官方 curated `GATE_CLASSES`；`ci-gates.ps1` 校验 schema/arch/migration/links/diff/安全拒绝 | 非 gate 的零星 acceptance 类未自动枚举；完整 DTO codegen 仍不足 |

## 3. P0：修复执行正确性

### P0-01 流水线 run/stage attempt 身份

- [x] 持久化 `pipelineRunId`、`stageAttemptId`、`expectedJobId` / `expectedTaskId`。
- [x] 终态回调同时匹配 run、当前 stage、attempt 和预期资源，并以 CAS 推进。
- [x] 手工 AI Job、focus probe、finding replay、实验卡 replay 和角色内 probe 不得推进主 cursor。
- [x] 迟到、重复、跨重启和旧 attempt 回调均不可改变新阶段。

验收：构造 foreign、stale、duplicate 终态事件，均不推进；正确事件只推进一次。

根审计（2026-07-28，`AUDITED`，声明范围=本地 SQLite fixture 下 pipeline/run/stage/attempt CAS）：`V022`；`AuditPipelineCoordinatorAcceptanceTest`；`ControlPlanePersistenceAcceptanceTest`；`PipelineRestartRecoveryAcceptanceTest`。限制：live 多 Worker 集群不在范围。

### P0-02 终态、取消与重试

- [x] 为无 Worker、排队超时、`BLOCKED`、投影失败、取消和进程重启定义终态。
- [x] 无 Worker 进入 `DYNAMIC_DISABLED` 或明确失败，不永久 `QUEUED`。
- [x] stage retry 使用新 attempt 和幂等键，校验上游前置，失效旧下游资源。
- [x] 取消记录操作者、原因、目标 attempt，并隔离后续迟到回调。

验收：重启、取消、重试和 BLOCKED 后不遗留 armed 流水线或永久任务。

根审计（2026-07-28，`AUDITED`，声明范围=终态/取消/重试/BLOCKED/无 Worker 本地路径）：`PipelineTerminalLifecycleAcceptanceTest` + `PipelineRestartRecoveryAcceptanceTest`；idempotency SQLITE_BUSY 重试已硬化。限制：live Docker 投影失败组合不在范围。

### P0-03 独立 probe attempt 与有效结果门禁

- [x] 使用 `jobId + canonical toolCallId` 或等价稳定身份生成 `probeAttemptId`。
- [x] attempt 绑定规范化 payload hash、technique、双鉴权通道、task；Fact 暴露 `probeAttemptId`。
- [x] 相同 attempt/相同 payload 返回原结果；相同 attempt/不同 payload 冲突。
- [x] `BUSY`、`FAILED`、`CANCELLED`、空 PathRun 或未投影结果不计为有效尝试；DYNAMIC 要求 `min(3, PoC数)` 次有效尝试。

验收：同一 AI Job 至少 3 个结构不同 PoC 可独立执行和重放，失败结果不推进 PATH/TRIAGE。

根审计（2026-07-28，`AUDITED`，声明范围=probeAttemptId/payload 冲突与有效尝试计数）：`ProbeAttemptIdentityAcceptanceTest`。限制：ExperimentPlan 见 P0-08；PATH/TRIAGE 见 P0-05。

### P0-04 AUTH 代码审阅、多 PoC 与多轮

- [x] `AUTH_ANALYSIS` 在存在鉴权面时至少成功调用一次 `code_query`（`AUTH_INITIAL`）。
- [x] 查询 Filter/Interceptor、注解、JWT/session/API key、skip URL、租户与角色分支（经 P0-11 `code_query` kinds：`METHOD_VIEW`/`CALLERS`/`CALLEES`/`CFG_VIEW`/`GUARD_QUERY`/`CONFIG_SEARCH` 等；不再仅靠字符串扫描冒充）。
- [x] PoC 按机制和过闸路径去重；目标不少于 3 个结构不同候选，或 `infeasibleEntries` 补足缺口。
- [x] 缺 `code_query` / 稀疏 PoC 时有界 re-ask；预算耗尽输出 `INSUFFICIENT_EVIDENCE` 或 RULE_GENERATED seed（永不 `SATISFIED` 于无 code_query）。
- [x] 初次 AUTH 与动态后 AUTH_CONFIRM 使用显式 `authPass`（`AUTH_INITIAL` / `AUTH_BYPASS_CONFIRM`）。

验收：未查询代码、重复 payload 变体、无 evidence refs 或错误 AUTH pass 均被拒绝或降级。

根审计（2026-07-28，`AUDITED`，声明范围=模拟 transport 下 AUTH 多轮/code_query/PoC 多样性门禁）：`AuthMultiRoundGateAcceptanceTest` + P0-11 kinds。限制：完整反编译/SSA 与真实外网 Provider 多轮不在范围。

### P0-05 PATH 与 TRIAGE 动态工具闭环

- [x] `PATH_EXPLORATION` 仅针对明确 coverage gap 调用 `sandbox_probe`，提交 entry、track、objective、inputs、expected signal 和 stop condition。
- [x] `VULNERABILITY_TRIAGE` 可用 `sandbox_probe` 复现或证伪，但只消费成功投影的证据。
- [x] 两角色的 allowlist、轮次、probe 数、deadline、payload 和结果预算由服务端固定。
- [x] 新事实写入 PathRun/evidence 后才进入下一轮；失败只形成缺口或反证。

验收：角色无法传入命令、镜像、宿主路径、网络、挂载、UID、预算或授权覆盖；无 PathRun 的结果不进入动态结论。

根审计（2026-07-28，`AUDITED`，声明范围=PATH/TRIAGE sandbox_probe 字段/allowlist/无效结果闸门）：`PathTriageProbeGateAcceptanceTest` + `PathTriageEffectiveProbeAcceptanceTest` + `PathExplorationContractAcceptanceTest` + `SandboxProbeSecurityDenialAcceptanceTest`。限制：真实多轮 Provider 编排不在范围。

### P0-06 请求级动态证据关联

- [x] 为每次 HTTP probe 建立 request/correlation id，并贯穿 Agent 与 JDBC 事件。
- [x] PathRun 只消费同请求范围事件，禁止将 task 级 SQL 复制到全部入口或身份轨。
- [x] H3 同时校验同一 PathRun、恶意片段、入口到 SQL 无过滤/参数化阻断、可重放引用。
- [x] Worker 成功、trace commit、投影和阶段成功使用原子或可补偿门禁。

验收：多入口、多请求、多 SQL 的正负场景归属准确；坏 trace 或投影失败不推进。

根审计（2026-07-28，`AUDITED`，声明范围=请求窗 SQL 按 correlation 过滤的 fixture）：`RequestWindowSqlProjectionAcceptanceTest`。限制：live Docker 多请求套件不在范围（PathRun 矩阵已升 fixture `AUDITED`，live 仍见诚实边界）。

### P0-07 TRIAGE 结论保真

- [x] 使用 TRIAGE 专用 conclusion schema，保留 `rootCause`、CWE、affected component、attack path、counterevidence、fix suggestion 和顶层 evidence refs。
- [x] AUTH 兼容序列化不得覆盖或丢弃 TRIAGE 字段。
- [x] finding、dashboard 和 REPORT 使用同一结构化来源，不从模型 Markdown 反向猜字段。

验收：TRIAGE -> finding -> REPORT 全链路字段一致；缺失必需字段时 fail-closed 或标证据不足。

根审计（2026-07-28，`AUDITED`，声明范围=TRIAGE conclusion→finding→REPORT 结构化字段保真）：`TriageConclusionFidelityAcceptanceTest` / `TriageFindingAttachAcceptanceTest`。限制：durable scan insert 全量改写与 GUI E2E 视觉不在范围。

### P0-08 ExperimentPlan 身份贯穿

- [x] `experimentPlanId` 从计划进入 probe attempt、Worker task、PathRun、实验卡和 replay。
- [x] replay 新建 attempt，但引用不可变原计划与规范化 payload。
- [x] UI 和审计可区分计划、执行 attempt 与重放。

验收：任一动态证据均可反查原计划；跨计划资源不能混用。

根审计（2026-07-28，`AUDITED`，声明范围=experimentPlanId/attemptKind 身份贯穿与 replay 绑定）：`ExperimentPlanReplayIdentityAcceptanceTest`。限制：全页 UX 视觉审计不在范围。

### P0-09 可执行测试基线

- [x] 将关键场景接入 JUnit/Surefire，或提供 CI 强制执行且在零断言时失败的统一 runner。
- [x] 覆盖阶段身份、终态/重试、同 Job 多 probe、AUTH 多轮、PATH/TRIAGE 工具、请求级 SQL、TRIAGE 保真和 ExperimentPlan。
- [x] 报告 executed tests/assertions，并在 0 时失败。

验收：`mvn test` 或唯一官方命令真实执行上述断言；不再依赖人工逐个启动 main 类判断回归。

根审计（2026-07-28，`AUDITED`，声明范围=官方非零门禁 `AcceptanceTestRunner`/`ci-gates.ps1`）：复跑官方 curated gate PASS。限制：全量 `mvn test` 与 schema 代码生成不在本项声明范围。

### P0-10 静态事实保真与跨方法绑定

- [x] 结构化持久化 taint steps + analysis coverage 到现有 `taint_graphs`（`StaticFactSnapshot` schemaVersion=1）。
- [x] 结构化持久化完整 `BytecodeFactIndex`、call graph 和 unresolved facts。
- [x] 消费侧优先 persisted taintPaths；缺失行回退 `ContrastLedger.taintPathsFromSinks` stub（coverage=`LEGACY_INCOMPLETE`）。
- [x] finding 绑定：sink 含 `taint-path`/ `classfile-taint:` 时用 `sourceOwner#sourceMethod` 匹配 entry；否则保留 sinkBindingKey。
- [x] Controller -> Service -> Repository 跨 handler 绑定需真实 fixture 端到端验收（`CrossMethodFindingBindAcceptanceTest`）。
- [x] 删除从 sink 文本重建空步骤的权威路径；PATH/contrast 全面改用 persisted IR（stub 仍仅 LEGACY 无 facts 行时回退）。

根审计（2026-07-28，`AUDITED`，声明范围=persisted IR 权威 + LEGACY 仅无 facts 行 + 跨方法绑定 fixture）：`StaticFactPersistenceAcceptanceTest` + `CrossMethodFindingBindAcceptanceTest`。限制：完整别名/IFDS 与 GUI contrast 视觉不在范围。

### P0-11 真实代码查询与角色工具合同

- [x] 将 `code_query` 拆为 `method_view`、`callers`、`callees`、`cfg_view`、`dataflow_slice`、`guard_query`、`field_uses`、`config_search` 或等价版本化接口。
- [x] 返回受限反编译/指令切片、IR/evidence ID、解析类型、coverage 和 stop reason；不能读取任意宿主文件。
- [x] AUTH 门禁要求具体 method/guard 证据，不再用字符串/类名扫描冒充代码理解。
- [x] 为 `PATH_EXPLORATION` 加入目标 `sandbox_probe` allowlist，并统一 system prompt、role prompt、schema 和审计。

验收：AUTH 能从入口查询到 guard 与敏感 operation 的先后关系；PATH 可在固定策略下执行 gap probe；越权文件/命令/网络请求均被拒绝。

根审计（2026-07-28，`AUDITED`，声明范围=code_query kind 路由/有界切片/CFG blocks + AUTH method/guard 门禁 + PATH prompt/schema 统一）：`CodeQueryKindAcceptanceTest` + `PathExplorationContractAcceptanceTest`。限制：完整反编译/SSA/IFDS 与真实 Provider 多轮不在范围。

### P0-12 通用 SecurityHypothesis 与 Finding

- [x] 建立 hypothesis schema、lifecycle、supporting/contradicting evidence、coverage gap 和 detector version。
- [x] Finding 绑定 `hypothesisId + securityProperty`，source/effect 仅对 dataflow family 必需。
- [x] 将现有 sink finding 兼容投影为 DataflowHypothesis；AUTH_GAP 迁为 GuardCoverage hypothesis，不再伪装 sink。
- [x] GUI/API/SQLite/report 支持 guard、state、typestate、config、dependency、concurrency 和 composition family（每族空态友好列表；未知 family 降级 UNKNOWN；SQLite V023 已存）。

验收：IDOR、状态绕过和危险配置 fixture 不创建伪 `sink-none`，仍可完整审计、驳回、重放和导出。

根审计（2026-07-28，`AUDITED`，声明范围=hypothesis schema/V023 + sink→DATAFLOW / AUTH_GAP→GUARD_COVERAGE 投影 + Finding 绑定 + API/GUI family 列表）：`SecurityHypothesisAcceptanceTest`。限制：GUI 手工视觉与 live detector 全量召回不在范围（P1-05/23 合同已另审）。

### P0-13 Coverage Matrix 与基准协议

- [x] 输出 Artifact Universe、入口族、调用解析、detector、动态实验和 stop reason 的 coverage matrix（`GET /api/v1/scans/{id}/coverage` + scan 嵌入 `coverage`）。
- [x] unknown/unresolved/truncated/unreached 不得计为已覆盖，扫描成功不得显示为“安全”（`honestyFlags.neverTreatSuccessAsSafe`）。
- [x] 建立基准样例、变异样例和保留规则/框架集；`CoverageBaselineMetrics` 从 baselines `groundTruth` 计算真实 TP/FP/FN（`stub=false`）；suppress/移除 detector → recall gate 失败。
- [x] source/sink + AUTH_GAP 初始基线 + mutation/holdout JSON；Universe 计数经 P1-01 接入 CoverageMatrix。

验收：相同版本基准结果可重复；移除 detector/rule 会导致对应 recall gate 失败；报告显示未覆盖范围。

根再审计（2026-07-28，`AUDITED`，声明范围=fixture CoverageMatrix + mutation/holdout 真实 TP/FP/FN + honestyFlags）：`CoverageMatrixAcceptanceTest` + `CoverageBaselineMetrics`。限制：非生产全量漏洞族召回；深层制品 Universe 见诚实边界。

### P0-14 合同优先与 AI 防偏门禁

- [x] 建立公共 schema registry，覆盖 API、事件、Security IR、Analyzer、Runtime/Worker；定义兼容矩阵、unknown kind 和 namespaced extension 规则。
- [x] TypeScript 类型/parser、Java DTO 和 fixture 由同一 schema 生成，或通过双向 consumer contract 保证一致。
- [x] 建立依赖方向/禁止 import 的架构测试；先记录当前例外基线，新增代码不得扩大 Control Plane -> 语言实现、domain -> adapter 等耦合。
- [x] CI 强制真实非零测试、schema drift、迁移 checksum/升级、Markdown link、`git diff --check` 和安全拒绝回归。
- [x] 实施任务使用 [AI 任务包](AI_TASK_TEMPLATE.md)，架构触发项引用已接受 [ADR](adr/README.md)；检查声明 Allowed paths 与实际 diff。

验收：故意引入未版本化字段、修改旧迁移、跨层 import、零测试、越权文件修改或失效文档链接时，至少一个确定性门禁失败；不能只靠 Reviewer 阅读提示词发现。

根审计（2026-07-28，`AUDITED`，声明范围=本地 `contracts/` + `ci-gates.ps1` + Schema/Architecture/CiGate/SandboxProbe 拒绝测试）：`SchemaContractAcceptanceTest`/`ArchitectureBaselineAcceptanceTest`/`CiGateAcceptanceTest`/`SandboxProbeSecurityDenialAcceptanceTest`。补充：schema→TS 字段常量生成（Finding/Hypothesis/Coverage）已落地；完整 wire DTO/parser 生成仍限。脏树需任务专用 Allowed paths。

### P0-15 实战召回基线与回归集

状态：`PARTIAL`

- [x] 建立可选开源实战样本目录（≥3）：`spring-petclinic`（Boot）、`webgoat`（Boot + multi-auth 漏洞课）、`springblade`（Blade）；记录仓库 URL、ref、buildHint、expectedEntries/sinkFamilies、knownGaps（`baselines/p0-15-practical-oss-samples.json` + `PracticalRecallSampleCatalog`）。JAR **不入库**，经 `scripts/fetch-practical-samples.ps1` 可选拉取。
- [x] 对每个样本计算 entry/sink TP/FP/FN、invalid PathRun 比例与 gate（无本地制品 → `NOT_EVALUABLE`，不得计入生产召回）。
- [x] 将 `scan-7b619e8a65064fa9` 这类历史失败归档为 regression case：`httpStatus=-1/outcomeClass=UNKNOWN` 不得产生 `DYNAMIC_SUSPECTED`，无效 PathRun 洪水必须作为失败指标（`DynamicSuspectedNoiseGateAcceptanceTest`）。
- [x] release gate：目录形状 + 噪声门禁 + 有本地 JAR 时的 sink recall / invalid ratio（`PracticalRecallBaselineAcceptanceTest` 已进 curated gate）。

验收：同一版本重复运行样本集结果稳定；报告明确列出漏报、误报、动态失败和 coverage gap。无实战 ground truth 的样本只能用于探索，不能计入召回率。

实施注记（2026-07-29）：开源可选样本目录与 metrics harness 已合入；本机未 fetch 时全部 `NOT_EVALUABLE`。完整实战 digest 对照需运行 fetch 脚本后复跑。

### P0-16 静态优先的漏洞召回主线

状态：`PARTIAL`

- [x] 静态 sink 作为主召回排序入口（`FindingRanker` + dashboard）；动态失败降权不删除静态候选。
- [x] SQL/COMMAND/FILE/SSRF/DESERIALIZATION/TEMPLATE/JWT 最小正例族合同（`baselines/p0-16-static-sink-families.json`）。
- [ ] wrapper MethodSummary / 别名加深与实战保留集对照仍待继续。
- [ ] 增强 `code_query` 对 source/effect/guard/sanitizer 的可读切片。

验收：在实战样本上，静态 finding 至少达到人工确认的最低召回基线；报告可以从 finding 回溯到入口、调用边、sink/effect、guard/sanitizer 和 unresolved gap。

### P0-17 动态沙箱启动与就绪诊断

状态：`PARTIAL`

- [x] 容器内验证真实 HTTP 服务端口；3306/6379/5432 等依赖端口不得被当成应用端口（WaitHttpReady + shell 拒绝 + `SandboxStartupDiagnostics.isDependencyPort`）。
- [x] 对启动失败建立结构化分类：`SandboxStartupDiagnostics.FailureClass`。
- [x] 动态任务失败时保留应用日志尾部与分类 stop reason；不得把失败写成疑似漏洞。
- [x] 成功启动的断网容器按 scan/artifact 保留给 PATH/TRIAGE（`RetainedSandboxSessions`）。
- [x] 启动前从 Boot `server.port` / YAML `server.port` / Start-Class 收获候选端口（`BootPortCandidateHarvester` → PreAnalysis evidence）；依赖端口写入 rejected 列表。

验收：实战样本中动态启动失败可以被归因到明确类别；依赖端口不会生成成功 PathRun；失败路径产生 `UNREACHED` 或 gap，不产生 `DYNAMIC_SUSPECTED`。

### P0-18 入口参数空间到可执行路径实验

状态：`PARTIAL`

- [x] `EntryParameterExperimentCompiler`：entry × 0-n 参数 + empty-input rationale。
- [x] `compileUnified`：合并 entry / hypothesis / DynamicProbe `ExperimentPlan` / AUTH PoC 入口提示；`ProbePlanService` 给洪水探针盖章 `experimentPlanId`。
- [x] 0 参数、空 body、空 query 合法并记录 empty-input rationale。
- [x] PATH/TRIAGE 多轮 probe 可复用保留沙箱。
- [ ] 运行时未知 effect 反向修订 hypothesis 仍待加深。

验收：至少一个 SQL dataflow、一个鉴权/IDOR、一个状态序列样本能从 entry + 0-n 参数空间自动生成可执行实验；可从下游 SQL/guard/state/effect 观测反推或修订漏洞假设，并在失败时产生可解释 counter evidence 或 coverage gap。

### P0-19 运行时观测与 IR 对齐

状态：`PARTIAL`

- [x] `ObservationKind.BRANCH`；`RuntimeObservationProjector` 映射 Entry/Guard/Effect/State/Dependency/Exception/Branch。
- [x] 内部框架 HTTP 不直接生成 PathRun；空投影/UNKNOWN/超时 → `UNREACHED`。
- [x] Probe TSV 可选第 7 列 `experimentPlanId`；LoopbackHttpProbe 写入 detail；投影优先 detail 再回退 task bind；`correlationId` 仍贯穿 attemptId/requestSummary。
- [x] PathRun 成功投影后 hypothesis lifecycle 有界更新；失败投影不推进。

验收：多请求、多 SQL、多身份轨样本中，动态证据不串线、不复制、不因 MOCK 元数据升级；GUI 能展示“观察到什么”和“仍缺什么”。

### P0-20 漏洞研判门禁与报告降噪

状态：`PARTIAL`

- [x] `FindingRanker`：静态证据优先、动态支持加权、`UNREACHED`/MOCK 动态降权。
- [x] `DYNAMIC_SUSPECTED` 仅在真实 HTTP/effect 观察时；`UNKNOWN/-1/MOCK-gap/REACHED_NO_BIND` → `UNREACHED`。
- [x] `AUTH_CHALLENGE`（401/403 鉴权墙）无 effect/SQL 信号时 → `UNREACHED`（`outcomeClass` 仍保留供对照；不得把 UNAUTH 401 洪水标成疑似漏洞）。证据：`scan-28ab5e591f4d4b5a` 184×401 曾被标 `DYNAMIC_SUSPECTED`；`DynamicSuspectedNoiseGateAcceptanceTest`。
- [x] TRIAGE classification：`SUPPORTED` / `CONTRADICTED` / `INSUFFICIENT_EVIDENCE` / `UNREACHED`（`INFERENCE` 兼容别名为 `SUPPORTED`）。
- [x] Dashboard/GUI 摘要区分 dynamicSupported / dynamicFailed；Dynamic Diagnostics 承接失败噪声。

验收：对 `scan-7b619e8a65064fa9` 类失败样本，报告应突出静态 sink 和动态不可达原因，而不是输出上千条动态疑似；真实可达漏洞必须能看到静态证据、实验计划、PathRun 和 triage 结论链。

### P0-21 动态路径调试器（三轨 Posture + World Pack + PathTrace）

状态：`PARTIAL`（domain 编译器与 V025 持久化已接线；live Sensor/Evidence Graph 增量与 ADR-0004 全量验收未闭合）

**目标**：把动态能力从“HTTP 洪水 + Agent 特例绕过”迁移为 Docker 内动态路径调试器。对每个可识别入口尽最大努力记录最深可达业务路径、参数流、sink/effect 触发和最终阻断原因；即使最终因为数据库、License、文件、业务状态或依赖不可达失败，也要保留失败前真实经过的 Controller/Service/Util/Repository/Guard/Effect 证据，并反馈给 AI。

**权威设计**：[DYNAMIC_SANDBOX_POSTURE_REDESIGN.md](DYNAMIC_SANDBOX_POSTURE_REDESIGN.md)；方向提案 [ADR-0004](adr/0004-sandbox-posture-vs-agent-bypass.md)（`PROPOSED`）。实现不得继续扩大 Agent Bypass Zoo。

**核心模型**：

```text
Artifact Universe / Security IR
  -> TracePlan(entry / params / guards / effects / expected hops)
  -> World Pack(profile / env / license / files / schema / seed / stubs)
  -> ExperimentPlan(entry x 0-n params x posture)
  -> Docker Sandbox
       -> UNAUTH
       -> COVERAGE_POSTURE
       -> FORCED_REACHABILITY (default, Docker-only)
       -> BYPASS (candidate only)
       -> Sensor Agent
  -> PathTrace(entry / param / method / guard / effect / dependency / exit)
  -> Evidence Graph delta
  -> AI PATH/TRIAGE/REPORT
```

**禁止**：

- 把“所有接口完整 2xx”作为承诺；只能承诺最深可达路径和阻断原因。
- 在宿主执行动态或强达轨。
- 让 AI/前端改变强达策略、命令、网络、挂载、UID 或预算。
- 新增每个 Filter/License/中间件一个 fail-open Agent 特例。
- 默认绕过 sanitizer、SQL 参数化、文件类型校验、金额/审批/状态机不变量。
- 把 `FORCED_REACHABILITY`、MOCK、World Pack 或扫描身份姿态单独升 `DYNAMIC_CONFIRMED` / `VERIFIED`。

**迁移与开发步骤**：

1. **合同冻结**
   - [x] 定义 `TracePlan` schema：entry、参数、预期 hops、guard refs、effect refs、unresolved points、预算。
   - [x] 定义 `PathTrace` / `TraceEvent` schema：ENTRY、PARAMETER、METHOD_HOP、GUARD、EFFECT、DEPENDENCY、EXCEPTION、EXIT。
   - [x] 定义 `WorldPack` manifest：profile、env、system properties、license/files、schema/seed、dependency stubs、missing material gaps。
   - [x] 定义 `RuntimePosture`：`UNAUTH`、`COVERAGE_POSTURE`、`FORCED_REACHABILITY`、`BYPASS`，含 `postureProvenance`、`forcedGuardRefs`。
   - [x] 旧 PathRun 兼容读取：无 trace/posture/world 字段时标 `LEGACY_DYNAMIC_INCOMPLETE`，不得回填假阳性。

2. **静态 TracePlan 编译**
   - [x] 从 EntrySurface、参数签名、DTO/config、Guard、Effect、调用边和 coverage gap 编译 TracePlan。
   - [x] 支持 0 参数入口，并记录 empty-input rationale。
   - [ ] 将旧 sink/taint path 兼容投影为 expected effect/hop。
   - [x] 反射、动态 dispatch、未解析 wrapper 写入 unresolved points。

3. **ExperimentPlan 编译**
   - [x] 编译 entry × 0-n 参数 × posture。
   - [x] 默认每入口生成 `UNAUTH`、`COVERAGE_POSTURE`、`FORCED_REACHABILITY`；`BYPASS` 只按候选生成。
   - [x] 每个计划绑定 TracePlan、WorldPack、expected/counter signal、stop condition 和预算。
   - [x] 禁止无 `experimentPlanId` 的空 GET/POST 作为主覆盖。

4. **World Pack 最小版**
   - [x] 支持 `OBSERVE_FAIL`：依赖不可达时真实失败，但保留失败前路径。
   - [x] 支持 `MOCK_CONTINUE`：替身返回空结果或 seed，继续探索更深路径，并标 MOCK。
   - [ ] 将 JDBC/Redis/MySQL 现有替身迁入 World Pack 语义。
   - [x] 统一输出 `DEPENDENCY_UNAVAILABLE`、`DEPENDENCY_DATA_GAP`、`WORLD_STATE_GAP`、`LICENSE_UNAVAILABLE`。

5. **Runtime Posture Orchestrator**
   - [x] `UNAUTH`：真实无身份撞墙，标 `authRequirement`。
   - [ ] `COVERAGE_POSTURE`：标准框架边界注入扫描身份，优先支持 Servlet Principal、Spring SecurityContext、Method Security。
   - [x] `FORCED_REACHABILITY`：默认启用但仅 Docker；只强达已识别 auth/role/permission/license/feature guard；写 `INSTRUMENTATION_REACHABILITY`。
   - [ ] `BYPASS`：仅 UNAUTH 意外过闸或 AUTH_ANALYSIS PoC 触发。
   - [x] 非 Docker Worker、STATIC_ONLY、宿主路径、用户/AI 策略字段全部拒绝。

6. **Sensor Agent 与 PathTrace 投影**
   - [ ] Agent 只做 Sensor：entry、参数绑定、方法 hop、guard decision、effect、dependency、exception、exit。
   - [ ] 每个事件贯穿 scan、task、pathRun、probeAttempt、experimentPlan、tracePlan、entry、track、posture、correlationId。
   - [x] effect 已触发但后续 DB 不可达时，PathTrace 保留 effect，并以依赖失败作为 exit。
   - [x] trace 预算截断必须记录 `TRACE_TRUNCATED`，不能静默丢路径。

7. **Evidence Graph 与 AI 反馈**
   - [x] PathTrace 投影为 RuntimeObservation：Entry、Parameter、MethodHop、Guard、Effect、Dependency、Exception、Exit。
   - [ ] Evidence Graph delta 触发 hypothesis lifecycle 有界更新。
   - [x] AI 工具可查询 path trace slice、参数流、最后业务 hop、effect 和退出原因。
   - [ ] PATH/TRIAGE 根据 PathTrace 缺口提出下一轮参数、World Pack 或 replay 建议；服务端仍负责最终编译和授权。

8. **报告与 GUI**
   - [x] 最终报告按入口展示三轨 outcome、最深可达路径、参数流、sink/effect、退出原因、World/Posture/强达限制。
   - [ ] Dynamic Diagnostics 展示 World Pack gaps、Posture gaps、forced guard refs、依赖失败。
   - [x] Findings 主列表不得把强达-only、MOCK-only、UNKNOWN/-1 作为真实漏洞支持。

**验证逻辑**：

- [ ] `GET /code?code=x` fixture：参数进入 Controller → Service → Util，触发表达式执行，随后 DB 不可达；PathTrace 必须保留表达式 effect 与 `DEPENDENCY_UNAVAILABLE` exit。
- [ ] 鉴权 fixture：UNAUTH 401 标 `authRequirement`；COVERAGE_POSTURE 进入 handler 或输出 `AUTH_POSTURE_GAP`；FORCED_REACHABILITY 越过已识别 guard 并标限制。
- [ ] DB 缺表 fixture：已观察 SQL/effect，但退出为 `DEPENDENCY_DATA_GAP`；不丢前置路径。
- [ ] License fixture：缺 license 输出 `LICENSE_UNAVAILABLE`；强达轨可探索下游但不得升验证。
- [x] 安全拒绝：非 Docker 强达、AI/前端策略覆盖、强达 sanitizer/SQL 参数化/业务状态机不变量均 fail-closed。
- [x] 旧扫描兼容：旧 PathRun 无 PathTrace 时显示 legacy incomplete，不回填 posture。
- [ ] 报告验收：AI 研判必须引用 PathTrace evidence refs，不能只引用 HTTP 500 或模型文本。

验收：对 `scan-28ab5e591f4d4b5a` 类样本，动态覆盖不再被 UNAUTH 401 洪水主导；对数据库不可达样本，系统能展示失败前真实业务路径、参数流、sink/effect 和依赖退出原因；报告不把扫描身份或强达可达写成未授权利用；静态 sink 排序不被无效 PathRun 稀释。

## 4. P1：建立开放式发现内核

### P1-01 Artifact Universe

- [x] 解析 application class、Boot 内嵌依赖、配置、资源和路径 scope，标记 application/third-party/generated/unknown。
- [x] Boot/`WEB-INF` lib **有界一层展开**（jar 内 class 计数上限）；截断与未展开写入 CoverageGap。
- [x] 反射/代理/invokedynamic、未知协议、UNRESOLVED 与 **MULTI_VERSION_CLASS** 写入 CoverageGap。
- [x] 运行时已加载 class 差分：`diffWithRuntimeLoadedClasses` / `withRuntimeDiff`；扫描侧 `mergeRuntimeLoadedClasses` 写入 StaticFactSnapshot 并进入 CoverageMatrix（fixture 已加载类列表）。

验收：含内嵌 wrapper 依赖的 fixture 可定位依赖摘要和未解析边；预算截断明确可见。

根再审计（2026-07-28，`AUDITED`，声明范围=Boot fixture Universe + 一层 lib 展开/截断 gap + 多版本 class gap + runtime 类列表差分接线 + CoverageMatrix 消费；`ArtifactUniverseAcceptanceTest`）。限制：二层以上嵌套与 live Agent 类枚举不在范围。

### P1-02 Security IR / Evidence Graph

- [x] 建立 Program、Entry、TrustBoundary、Effect、Guard、Sanitizer、State、Resource、RuntimeObservation 节点。
- [x] 建立 call/control/data/alias/guard/state/ownership/happens-before/observed 关系和稳定 ID。
- [x] 旧 Entry/Sink/Path/Contrast DTO 只作为兼容投影；权威图持久化于 `StaticFactSnapshot` schema v4（`evidenceGraph` wire + `EvidenceGraph.fromMap`）；finding↔node 双向追踪。

验收：同一静态节点、动态事件、hypothesis 和 finding 可沿 evidence refs 双向追踪。

根再审计（2026-07-28，`AUDITED`，声明范围=扫描时权威图持久化 + wire round-trip + finding↔node 双向 join；`EvidenceGraphAcceptanceTest`）。限制：完美 IR / live PathRun 全量重投影不在范围。

### P1-03 版本化 Provider SPI

状态：`PARTIAL`（接口与门禁完成，主流程消费未闭合）

- [x] 实现 Artifact、Entry、TrustBoundary、EffectModel、GuardModel、SanitizerModel、MethodSummary、Detector、DynamicProbe Provider。
- [x] 将当前 Spring 入口、固定 sink、AuthCoverage、Blade/Flowable Pack 迁为默认 Provider。
- [x] 插件输出统一经过 scope/schema/budget/dedupe，不能直接写 Finding 或验证状态。
- [x] 扫描构建路径以 `ProviderBundle`/`ProviderRegistry.collect` 为 entry/effect/guard **权威源之一**（薄合并，保留 PreAnalysis 兼容）；DefaultJvmProviders 产出进 scan。
- [ ] 将 ArtifactNodes 合并到 Artifact Universe，将 Provider MethodSummary 合并到权威 summary 投影，将 DynamicProbe 编译为 server-gated ExperimentPlan。

验收：TestOnly Provider 能新增入口、custom effect、guard 和 detector；卸载后只影响其声明范围。

根再审计（2026-07-28，`PARTIAL`，声明范围=Provider 接口、Registry/OutputGate、entry/effect/guard/detector 薄接线及拒绝路径；`ProviderSpiAcceptanceTest`）。限制：ArtifactNodes、Provider MethodSummary、DynamicProbe 尚未全部进入主扫描投影；完整插件市场与精确净化证明不在范围。

### P1-04 静态分析内核加深

状态：`PARTIAL`（轻量 `analysis.kernel` fixture 可审；实战召回仍不足，**非**完整 IFDS/SSA/points-to）

- [x] 评估并接入可序列化的 JVM CFG/SSA、points-to/call graph 与 IFDS/IDE 能力；现有 ASM 解析保留快速 fallback。
- [x] 支持字段/返回值传播与 sanitizer 标记的最小扩展（对象/容器/exception edge/callback/async/有限反射仍未做）。
- [x] bottom-up MethodSummary 让调用 primitive effect 的自研 wrapper 自动成为 custom effect。
- [x] CfgBuilder / MethodSummary / FieldReturn 正负 fixture + `stopReason`/budget（`CFG_NOT_AVAILABLE`/`CFG_BLOCK_BUDGET`/`SUMMARY_PROPAGATION_BUDGET`/`FIELD_RETURN_STEP_BUDGET`）。
- [x] MethodSummary/Sanitizer 默认对 IR 命中非空（启发式）；`METHOD_VIEW` 有界伪反编译行（bci/opcode 标签/evidence，不读宿主文件）。

验收：跨层、wrapper、字段别名、净化正负和异步 fixture 达到声明 recall；预算与解析失败可查询。

根审计（2026-07-28，fixture `AUDITED`，声明范围=轻量 kernel 正负/budget/stopReason + CFG_VIEW 消费；**非**完整 IFDS）：`StaticAnalysisKernelAcceptanceTest`。实战复核（2026-07-29）：当前静态 sink 仍是最可靠的最低可用召回层，但复杂 wrapper、别名、异步、反射和框架扩展漏报明显；P0-16 前不得宣称静态内核成熟。ADR-0002 已由根 Agent 标为 `ACCEPTED`（继续轻量 kernel + 自研加深，暂不引 Soot/WALA；完整引擎须进程外独立 ADR）。

### P1-05 非污点 Detector 第一批

状态：`PARTIAL`（fixture/mutation/holdout 可审；实战排序、覆盖和动态闭环不足）

- [x] Guard dominance 与鉴权一致性。
- [x] IDOR/BOLA 的对象所有权和租户约束。
- [x] JWT/密码学/TLS/API misuse 与危险配置。
- [x] 反序列化配置、依赖版本和资源生命周期。
- [x] mutation/holdout baseline（`p1-05-mutation-non-taint.json` / `p1-05-holdout-non-taint.json`）+ 独立 `DetectorRecallGate`（移除 detector → fail）。

验收：每个 detector 有正例、近似负例、变异样例、保留集和独立 release gate；AI 不参与基础判定。

根审计（2026-07-28，fixture `AUDITED`，声明范围=三检测器 unit/live + mutation/holdout recall；AI 不参与）：`NonTaintDetectorAcceptanceTest`（82 assertions）；baselines `p1-05-non-taint-detectors` / `p1-05-mutation-non-taint` / `p1-05-holdout-non-taint`。实战复核（2026-07-29）：非污点 detector 的输出没有稳定压中真实业务漏洞，且与动态实验闭环薄；需按 P0-15/P0-18/P0-20 重新建立实战召回和排序门禁。

### P1-06 Hypothesis 驱动实验规划

状态：`PARTIAL`（PathRun/RuntimeObservation lifecycle fixture 可审；真实实验规划与增量重算未闭合）

- [x] ExperimentPlan 支持 reachability、dataflow diff、guard diff、state sequence、typestate 和 concurrency/resource 类型。
- [x] 绑定 hypothesis/plan/probe/stage attempt，声明 expected/counter signal 和 family-specific gate。
- [x] RuntimeObservation 统一 Entry/Guard/Effect/State/Dependency/Exception，并触发受影响 detector 增量重算。
- [x] PathRun 成功投影经 `ControlPlaneStore.replacePathRunsForTask` / `applyPathRunHypothesisObservations` 驱动 CANDIDATE→SUPPORTED/CONTRADICTED；失败/空投影 no-op。

验收：一个假设可被动态支持、反证或标证据不足；失败/空投影不改变 lifecycle。

根审计（2026-07-28，fixture `AUDITED`，声明范围=store PathRun→observation→lifecycle 门禁 + incremental subjects）：`HypothesisExperimentAcceptanceTest`（38 assertions）；不升 VERIFIED/`DYNAMIC_CONFIRMED`（finding 验证状态）。实战复核（2026-07-29）：当前更多是“有 PathRun 后更新 lifecycle”，不是“从 hypothesis 自动规划并证明漏洞”；动态不可达和空投影不得推进 triage。

### P1-07 进程外 Analyzer 与 Runtime 合同

状态：`AUDITED`（声明范围=同进程 Fake + 真实子进程最小 IR 合同；非生产多进程 Worker）

- [x] 定义 capability negotiation、artifact/policy digest、scope、budget、schema range、chunk manifest、diagnostic、coverage gap、资源使用和确定终态。
- [x] IR/trace 分片先进入有界暂存区；完整校验摘要、顺序、大小和 scope 后原子发布，部分失败不进入权威 Evidence Graph。
- [x] Test Analyzer 覆盖错误 scope/digest/schema、未知 capability、缺块/重复块、超预算、取消、迟到和重放幂等。
- [x] Analyzer 无数据库、模型工具、授权和动态 Worker 权限；RuntimeAdapter 的命令、镜像、挂载、UID、网络和预算由服务端固定。
- [x] `ProcessBuilder` 启动独立 `TestAnalyzerProcessMain` 提交最小 ProgramNode/Entry/CoverageGap；保留同进程 Fake 回归。

验收：Test Analyzer 可以独立进程提交最小 ProgramNode/Entry/CoverageGap；所有越权或不完整提交 fail-closed，移除 Analyzer 不影响历史扫描读取。

根审计（2026-07-28，`AUDITED`，声明范围=Fake + 子进程 IR 合同）：`TestAnalyzerAcceptanceTest`（含 `subprocessAnalyzerPublishesMinimalIr`）。限制：生产多进程 JS Analyzer/Worker 未接。

### P1-08 Control Plane 与 GUI 解耦

状态：`AUDITED`（声明范围=查询端口解耦；非大爆炸重写）

- [x] 在当前工程内先建立 contracts/domain/application/http/persistence/orchestration 端口，逐步缩减 `ControlPlaneServer`、`ApiDtos` 和 store 的职责，不做大爆炸重写。
- [x] 旧 `/api/v1` 从中立合同兼容投影；JVM/Spring/HTTP 专属字段不进入新核心必填合同。
- [x] 前端 API 边界按 schema/domain 拆分，页面按 capability/family/protocol 展示；未知语言节点和 extension 可降级阅读。
- [x] 当前集中耦合使用 architecture baseline 固定，新功能不得增加反向依赖或新的语言/框架主流程分支。
- [x] Finding / PathRun 查询经 `FindingQueryPort` / `PathRunQueryPort`（`listScanFindings`/`sendFinding`/dashboard PathRun 投影）。
- [x] createScan HTTP 响应经 `ScanQueryPort.scanView` 投影；provider list 经 `ProviderQueryPort`。

验收：一个 Test Analyzer 输出的未知语言节点无需修改 Control Plane 主流程或页面路由即可保存、查询和显示通用证据；JVM 回归投影保持等价。

根再审计（2026-07-28，`AUDITED`，声明范围=查询端口解耦含 Finding/PathRun/Provider + createScan 投影）：`ControlPlaneDecoupleAcceptanceTest`。限制：完整职责迁出 `ControlPlaneServer` 大爆炸重写不在范围。

### P1-20 单入口人工 debug 基准

状态：`AUDITED`（声明范围=mock transport）

- [x] 选择一个授权 Boot JAR 高价值入口，保存固定制品摘要和测试策略。
- [x] 完成 AUTH 候选、身份轨对照、焦点 probe、PathRun、HTTP/Agent/JDBC 证据和 TRIAGE。
- [x] GUI 从最终报告可回到完整证据并执行同计划 replay。
- [x] AUTH_CONFIRM（`AUTH_BYPASS_CONFIRM`）与 AUTH_INITIAL 区分；report→replay 保持 `experimentPlanId`。

验收：全链路可重复，最高为 `DYNAMIC_SUSPECTED` 或满足 H3 的 `DYNAMIC_CONFIRMED`，不出现 `VERIFIED`。

根审计（2026-07-28，`AUDITED`，声明范围=mock transport）：`SingleEntryDebugBaselineAcceptanceTest` + `baselines/p1-20-single-entry-debug.json`。限制：live Docker 与 GUI 手工视觉 replay 不在范围。

### P1-21 AUTH 与身份轨 live 对照

状态：`AUDITED`（声明范围=fixture 身份轨/AUTH_CONFIRM 三态；非 live 过闸）

- [x] 对 MISSING_AUTH、空 Bearer、ALG_NONE 和框架特定 header 至少完成一组 401/过闸对照。
- [x] 身份材料不可用时标 `IDENTITY_UNAVAILABLE`，不得发送伪造空 token 冒充尝试。
- [x] 动态后 AUTH_CONFIRM 区分假设、对照证据和证据不足（HYPOTHESIS / DYNAMIC_CONTRAST / INSUFFICIENT_EVIDENCE）。

根审计（2026-07-28，`AUDITED`，声明范围=fixture AUTH_CONFIRM 三态）：`AuthIdentityTrackAcceptanceTest`。限制：live 过闸与 AUTH_CONFIRM 生产编排不在范围。

### P1-22 SQL D1-D3 与 H3

状态：`AUDITED`（声明范围=H3 fixture；非 live 实库）

- [x] live 验证语句级 SQL 不含握手/meta 污染。
- [x] 完成良性与元字符输入的 D2 差分和 D3 可重放实验卡。
- [x] 用正负 fixture 证明 H3 不会因 MOCK 元数据、错误归属或字符串巧合升级。
- [x] 同 PathRun correlationId + marker SQL 正负端到端 fixture。

根审计（2026-07-28，`AUDITED`，声明范围=fixture）：`DynamicConfirmedGateAcceptanceTest`（含 correlation 正负 + MOCK provenance）。限制：live JDBC 实库不在范围。

### P1-23 GUI 语义与隐私

状态：`AUDITED`（声明范围=合同测试；非手工视觉）

- [x] 报告默认视图、PathRun 子视图和三类下载物文案与实际内容一致。
- [x] `MODEL_THINKING` 的保存、展示、删除和保留策略完成产品/隐私审计。
- [x] 补齐无 Worker、BLOCKED、投影失败、retry/cancel 和 attempt 的可视状态。
- [x] 增加 Coverage Matrix、SecurityHypothesis 和 Evidence Graph 局部视图；非 source-sink finding 不显示伪 entry/sink。
- [x] 用桌面/窄屏和长文本检查状态、时间线、筛选与 Markdown 无重叠。
- [x] `GUI_CONTRACT_AUDIT` 显式记录合同测试范围与生产隐私随 SSO 延后。

根审计（2026-07-28，`AUDITED`，声明范围=合同测试）：`GuiSemanticsContractAcceptanceTest` + `GuiLayoutContractAcceptanceTest`。限制：手工视觉回归未做；生产隐私/保留策略随 SSO 延后（ADR-0003 PROPOSED）。2026-07-29 补充：该项只证明语义合同，不代表当前最终报告页面的信息架构和视觉质量达标；重设计见 P1-25。

### P1-24 Provider 与出站边界

状态：`AUDITED`（声明范围=loopback 出站拒绝/预算；非外网互操作）

- [x] 完成 OpenAI Chat 与 Anthropic Messages 的真实兼容矩阵、错误分类和预算验证。
- [x] 验证 HTTPS、DNS rebinding、redirect、metadata、代理、凭据擦除和审计留存。
- [x] 未验收 Provider 类型保持 disabled，不以 inventory 成功冒充工具兼容。
- [x] 验收套件明确仅 loopback fixture，不拨打外网主机。

根审计（2026-07-28，`AUDITED`，声明范围=loopback 拒绝/预算）：`ProviderOutboundBoundaryAcceptanceTest`。限制：真实外网 Provider 互操作未验收；禁止宣称 live 供应商 AUDITED。

### P1-25 最终报告结果工作台重设计

状态：`PARTIAL`

- [x] 按 `GUI_DESIGN.md` §4 将最终报告菜单重构为结果工作台：`ResultsShell`、`ScanContextBand`、`EvidenceSummaryStrip`、`ResultsSubnav`、主内容区和 `EvidenceInspector`。
- [x] 将 report、findings、entry exploration、PathRuns、evidence graph、coverage、dynamic diagnostics、experiments/replay、downloads 拆为独立 view（`frontend/src/components/results/*`），保留同一 `/api/v1` 合同；`ResultsPage.tsx` 为编排层。
- [x] Entry Parameter Exploration 子页：入口表、0-n 参数/empty-input rationale、实验 readiness（基于 entries/experimentPlans；完整矩阵待 API 加深）。
- [x] Dynamic Diagnostics 子页：UNREACHED / `-1` / UNKNOWN / MOCK 依赖从漏洞主列表分离。
- [x] Findings 默认静态优先排序；下载页区分 Markdown / HTML / JSON。
- [x] Evidence Graph 节点点击更新 EvidenceInspector（不改变服务端状态）。
- [ ] 手工窄屏/长文本视觉回归仍待补强；合同测试已覆盖新增 view id。

验收：当前功能不丢失，`npm run build` 通过；结果页可从任一 finding、PathRun、entry、coverage gap 或诊断跳转到 evidence refs；对 `scan-7b619e8a65064fa9` 类失败数据，页面突出动态失败原因和静态候选，不再把大量失败 PathRun 包装成漏洞。

## 5. P2：发布与扩展

- [x] State/Sequence detector：跨请求状态机、重复提交、额度、审批和流程不变量。
- [x] Concurrency/Resource detector：TOCTOU、race、lock/transaction 与线程/连接/内存/磁盘生命周期。
- [x] Guard/State/Typestate family-specific `DYNAMIC_CONFIRMED` 门禁；完成独立审计前保持 `DYNAMIC_SUSPECTED`。
- [x] Servlet/Filter、WebFlux、消息 Listener、定时任务、WebSocket/RPC EntryProvider。
- [x] 独立 Linux gVisor/Kata Worker 与签名 attestation。

根审计（2026-07-28，STATE/CONCURRENCY → `AUDITED`，声明范围=启发式正负 + mutation/holdout + `DetectorRecallGate`；EntryProvider 骨架仍 `PARTIAL`）：`P2DetectorEntryAcceptanceTest` + baselines `p2-state-concurrency` / `p2-mutation-state-concurrency` / `p2-holdout-state-concurrency`。限制：深度状态机求解、真实数据竞争证明、生产入口召回不在范围；family `DYNAMIC_CONFIRMED` 仍 fail-closed。

- [x] 网络/DNS/metadata/宿主挂载/非 root/只读 rootfs/capability/资源耗尽/trace 篡改/Agent 缺失/逃逸套件。
- [x] `VERIFIED` 双重重放和 release evidence gate；`TRUSTED_DOCKER` 永久排除。
- [x] `jlink + jpackage` Desktop Core 与可选 Sandbox Pack。
- [x] WAR 动态适配和第二 FrameworkAdapter，逐项通过中立事实合同。
- [x] 第二语言静态 LanguageAnalyzer 复用同一流水线、存储、Hypothesis、coverage 和 GUI；不得复制控制面。
- [x] 第二语言 RuntimeAdapter 单独通过 capability、沙箱、trace 和验证状态审计；静态支持不自动获得动态支持。
- [x] 生产 session、CSRF、SSO、多租户隔离和数据保留策略，仅在产品范围升级时启动。

根审计（2026-07-28）：
- gVisor/Kata：`SCAFFOLDING` — **明确延后开放**；`HARDENED_ENABLEMENT_NOT_OPEN` 复核通过（`HardenedRuntimeAttestationAcceptanceTest`）。非生产隔离。
- 沙箱硬化/逃逸套件：`SCAFFOLDING` — 拒绝清单门禁保留；**真实逃逸套件延后**（`SandboxHardeningAcceptanceTest`）。
- VERIFIED：`SCAFFOLDING` — **恒关闭**（`VERIFIED_GATE_NOT_OPEN`；`TRUSTED_DOCKER_NEVER_VERIFIED`）。
- Desktop jlink DryRun / WAR 动态禁用 / JsRuntime 无动态 cap：`SCAFFOLDING`，不升生产可用。
- 第二语言：合同层 `AUDITED`（Fake + 子进程 Test Analyzer）；**无**生产 Node Worker（静态 ≠ 动态）。
- 生产 session/CSRF/SSO/多租户/保留：`SCAFFOLDING` — **明确延后**；ADR-0003 仍 `PROPOSED`；`ProductionFeatures.DISABLED`（`ProductionFeaturesAcceptanceTest`）。

## 6. 明确不做 / 本阶段明确延后

- 让模型或前端直接操作 Docker、shell、宿主路径或外网；
- 在沙箱不可用时宿主执行制品；
- 把 `TRUSTED_DOCKER`、MOCK、`DYNAMIC_CONFIRMED` 或人工确认称为生产已验证；
- 为追求覆盖率跳过管理员、租户或业务状态前置条件；
- 在 P0 闭合前扩展任意语言或大规模分布式调度；
- 宣称保证发现所有非常规 source/sink 或所有业务逻辑漏洞；产品只能声明经基准验证的漏洞族覆盖合同；
- 继续维护按日期累积的迁移路线图或把实现流水账写回 `PROJECT_MEMORY.md`；
- **本阶段不开放** gVisor/Kata 真实 Worker 启用、逃逸套件 attestation 与 `VERIFIED`（骨架与 fail-closed 测试可保留）；
- **本阶段不开放** 生产 session / CSRF / SSO / 多租户隔离 / 数据保留策略（`ProductionFeatures.DISABLED`；ADR-0003 保持 `PROPOSED`）。

## 7. 维护规则

完成项必须写清证据命令、fixture、环境、断言范围和限制。代码存在不等于完成；仅有 schema 或 fail-closed gate 应标 `SCAFFOLDING`。每次根 Agent 审计后更新本文件，稳定产品决策才写入 `PROJECT_MEMORY.md`，历史细节由 Git 保留。AI 实施遵守 [开发手册](DEVELOPMENT_PLAYBOOK.md) 和 [任务包模板](AI_TASK_TEMPLATE.md)，但提示词/文档存在本身不算门禁完成。

## 8. 不足与 audited gaps（根再审计 2026-07-28）

按 [DEVELOPMENT_PLAYBOOK](DEVELOPMENT_PLAYBOOK.md) DoD / 常见写偏模式对照当前代码与门禁。下列**不是**未实现 checkbox，而是声明范围外的真实短板。

2026-07-29 实战召回复核补充：当前代码审计漏报严重，主要不是“AI 提示词不够强”，而是确定性事实、动态实验和评估基线没有闭成产品级发现系统。后续优化优先级按下表执行。

| 根因 | 当前表现 | 直接后果 | 对应任务 |
|------|----------|----------|----------|
| 缺少实战 ground truth | fixture gate 通过，但真实授权 JAR 漏报无法量化 | 无法判断改动是提升还是换噪声 | P0-15 |
| 静态内核深度不足 | 轻量 call graph / summary / sanitizer 能过正例，但复杂 wrapper、别名、异步、反射不稳 | 静态 sink 以外的真实漏洞召回弱 | P0-16、P1-04 |
| 动态入口实验过于通用 | 未围绕 entry signature、0-n 参数、三用途轨（UNAUTH/PRIVILEGED/BYPASS）和下游 effect 组织；盲 UNAUTH 洪水当覆盖 | 鉴权入口停在墙外；动态不如静态 sink 实在 | P0-18、P0-21 |
| Blade/PreAuth 鉴权墙 | 几乎只打 UNAUTH→401；JWT/Blade-Auth mint 失败无 PRIVILEGED 覆盖；`parameterBound` 全空 | 无法“进业务调试”；曾把 401 标动态疑似；缺 `IDENTITY_UNAVAILABLE` | P0-20、P0-21 |
| 沙箱启动诊断弱 | 依赖端口、启动失败、探针 JVM 失败、依赖替身缺口容易混成 UNKNOWN | `httpStatus=-1` 噪声污染 triage | P0-17 |
| 依赖替身不是业务环境 | JDBC/Redis/MySQL 替身只能帮助启动，缺表、缺数据和协议细节不能还原业务流 | 动态假阴性高，MOCK 证据不能证明真实影响 | P0-17、P0-18 |
| RuntimeObservation 与 IR 对齐薄 | Agent 事件不能稳定映射 Entry/Guard/Effect/State | PathRun 难以支持或反证 hypothesis | P0-19 |
| AI 研判吃不到足够事实 | code_query 和 evidence graph 切片有限，PATH/TRIAGE 工具结果多为失败 | AI 只能解释失败，不能可靠发现漏洞 | P0-16、P0-18、P0-20 |
| 报告排序没有惩罚动态失败 | 动态不可达可能和疑似结果混在一起 | 用户看到大量噪声，真正静态 sink 反而被稀释 | P0-20 |

### 8.1 明确延后（产品决定，保持 SCAFFOLDING）

| 缺口 | 现状 | 风险 |
|------|------|------|
| gVisor/Kata + 逃逸套件 | fail-closed 骨架 | 无强化隔离；不得宣称恶意制品沙箱 |
| `VERIFIED` | 恒 `VERIFIED_GATE_NOT_OPEN` | 最高验证态不可用（正确） |
| 生产 SSO/session/CSRF/多租户/保留 | `ProductionFeatures.DISABLED` | 仅本地 PAT；无企业会话 |

### 8.2 分析深度（fixture AUDITED，深度不足）

| 缺口 | 现状 | 风险 / 加深项 |
|------|------|----------------|
| 完整 SSA / IFDS / points-to | 轻量 `analysis.kernel`；ADR-0002 **`ACCEPTED`**（继续轻量+自研加深，暂不引 Soot/WALA） | 别名/异常/异步/反射召回不足；进程外引擎另开 ADR |
| 完整反编译切片 | `METHOD_VIEW` 有界伪反编译行（bci/opcode 标签/evidence） | 非完整反编译器；复杂控制流仍粗 |
| P2 深度状态机 / 真实并发 / 骨架 EntryProvider | STATE/CONCURRENCY 启发式已 `AUDITED`（holdout+RecallGate）；EntryProvider 仍骨架 | 深度求解与生产入口召回弱 |
| MethodSummary/Sanitizer 精度 | kernel IR/sink/guard 启发式默认非空 | 名称启发式误报/漏报；非证明级净化 |
| Boot 二层以上嵌套依赖 | Universe **一层**有界展开 + 截断 gap | 更深嵌套第三方盲区可能低估 |

### 8.3 动态与证据（fixture AUDITED + live 套件）

| 缺口 | 现状 | 风险 |
|------|------|------|
| live TRUSTED_DOCKER 多请求 | `LiveTrustedDockerMultiRequestAcceptanceTest`：fixture 相关隔离恒跑；Docker+digest runtime image 时经 Worker TRUSTED_DOCKER ≥2 HTTP probe 实跑；Docker/image 不可用时 `SKIP` 有日志且门禁仍 PASS | 仍非恶意制品隔离；需本机 sandbox-pack 镜像 |
| live JDBC 实库 H3 | `LiveJdbcH3AcceptanceTest`：握手/meta 不升 `DYNAMIC_CONFIRMED`；嵌入 SQLite 语句级正负；Docker+Postgres 镜像时 `psql` 实库 marker 正负；无 DB 容器 `SKIP` 有日志 | 非 Connector/J 进程内驱动；H3 仍仅 DATAFLOW |
| 真实多轮 Provider 编排 | `LiveProviderRoundAcceptanceTest`：loopback HttpServer 模拟 OpenAI/Anthropic tool→final；预算/错误分类/凭据不落日志；默认不打外网（`VEYRION_LIVE_PROVIDER=1` 可选） | 真实供应商流式/限流/计费未验收 |
| PathRun→detector 全量增量 | store lifecycle 接线 | 大规模重算/生产投影未审 |

Skip 约定：Docker 不可用或 runtime/DB 镜像缺失时 live 分支打 `SKIP` 日志并保留非零 fixture 断言，`AcceptanceTestRunner` 不得因此失败。`VERIFIED` / gVisor / 生产 SSO 仍关闭。

### 8.4 工程与合同

| 缺口 | 现状 | 风险 |
|------|------|------|
| schema→TS 字段常量生成 | `scripts/generate-contract-types.ps1` → `frontend/src/generated/contracts.ts`；`SchemaContractAcceptanceTest` 校验 required 集合 | 完整 DTO/parser 生成与 Java codegen 仍未做 |
| 官方 `mvn test` | Surefire → `AcceptanceTestGate` → curated `GATE_CLASSES`；零执行/零断言 fail-closed | 非 gate 的零星 `*Test` 未纳入 Surefire include，不得称全仓库自动枚举 |
| `ControlPlaneServer` 仍集中 | 查询 + createScan 投影 + provider list 经 application.port | 编排/写入大爆炸拆分未做 |
| Desktop/WAR 动态 | DryRun / DISABLED | 无安装包、无 WAR 动态路径 |

### 8.5 框架合规抽查（写偏模式）

- 未见新增语言主流程 `if language ==` 分叉；第二语言经 Analyzer 合同。
- AUTH_GAP 不以 `sink-none` 为唯一形态（GuardCoverage）。
- 前端不构造 Worker 命令/验证升级（合同测试覆盖）。
- 模型不可经 sandbox_probe 传入 command/image（拒绝测试）。
- 未改已应用迁移；schema 追加（StaticFactSnapshot v4 兼容读）。

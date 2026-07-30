# 溯脉 · Veyrion 技术架构

> 本文定义系统组件、数据、安全、持久化和执行边界，并明确区分当前实现与目标合同。产品需求见 [PRD](PRD.md)，当前系统逻辑见 [CURRENT_SYSTEM](CURRENT_SYSTEM.md)，阶段状态机 as-built 见 [AUDIT_PIPELINE_ASBUILT](AUDIT_PIPELINE_ASBUILT.md)，当前缺口见 [OPEN_GAPS](OPEN_GAPS.md) / [MVP Backlog](MVP_BACKLOG.md)。

## 1. 架构原则

1. 静态事实扩大视野，受控动态实验提供观察，AI 只解释、规划和关联。
2. FACT、运行时观察、MOCK/规则材料和 INFERENCE 分层保存。
3. 项目、制品、扫描、阶段、probe 和证据都具有不可混用的作用域身份。
4. 动态能力必须由服务端授权和固定策略控制；任何失败不得回退宿主执行。
5. 已提交证据追加写，派生视图可重建；重试创建新 attempt，不覆盖历史。
6. 制品、模型输出和前端输入不能改变工具权限、沙箱、网络或验证状态。
7. 扩展按 ArtifactPackager、LanguageAnalyzer、FrameworkAdapter、AnalysisPack、RuntimeAdapter 五条正交轴进行。
8. Control Plane 保持语言无关；新语言解析器和运行时通过版本化进程外合同接入，不复制流水线。

## 2. 当前系统

```text
React/Vite GUI
    | REST / SSE
Java 17 Control Plane
    |-- Artifact Registry / Upload
    |-- Static Fact Index
    |-- Audit Pipeline / AI Orchestrator
    |-- TracePlan / ExperimentPlan Compiler
    |-- PathRun / Finding / Dashboard Projection
    |-- SQLite Persistence
    |
    +-- Worker Adapter
          |-- STATIC_ONLY
          `-- TRUSTED_DOCKER (explicit local debug)
                 |-- executable Spring Boot JAR
                 |-- Runtime Posture Orchestrator
                 |-- World Pack
                 |-- Framework Boundary Adapter
                 `-- Sensor Agent
```

当前为单节点、loopback、本地 SQLite 语义，不是分布式 exactly-once 工作流系统。GUI 与 Control Plane 在开发模式下分别运行于 Vite 和 Java 服务；Java 托管静态前端与 Desktop Core 属于目标打包形态。

当前技术栈适合 JVM 优先的本地 MVP，但实现边界尚未完成多语言解耦：`ControlPlaneServer` 同时承担 transport、编排和大量投影，`ApiDtos`/持久化直接共享 DTO，前端 `api.ts` 集中维护大量手写类型和 parser，公共视图仍包含 JAR、HTTP、sink/taint 假设。这些是迁移基线，不是继续扩展时的推荐结构。

2026-07-29 实战复核后，MVP 的发现主线调整为：**静态事实和 sink/effect 召回优先，动态沙箱用于证伪、复现和补证**。现有动态能力能证明服务端权限边界和部分 loopback fixture，但不能稳定启动真实业务路径，也不能作为主要漏洞发现引擎。架构文档中的动态闭环均为目标合同；实现状态以 [MVP Backlog](MVP_BACKLOG.md) §0.4、P0-15 到 P0-20 为准。

## 3. 组件职责

### 3.1 Artifact Registry

- 接收 JAR/WAR/CLASS，校验扩展名、大小、ZIP 结构和 SHA-256。
- 浏览器上传使用有 TTL 和预算的顺序分块协议，校验块摘要和完整摘要。
- 完成后原子安装到授权根内的内容寻址目录，扫描只引用受控副本。
- 上传会话元数据和偏移已进入 SQLite，可在重启后校验恢复；孤立分片按内部命名规则清理。
- 旧路径登记只保留为本地兼容入口，每次使用前重新校验文件身份和摘要。

### 3.2 Static Fact Index

- 有界读取 classfile，不加载或初始化被测类。
- 提取 Spring MVC 映射、参数与鉴权注解、类层次、字段、调用点和敏感 sink。
- 制品内调用边区分 `DIRECT`、`CHA`、`UNRESOLVED`，保留 owner、descriptor、位置和限制。
- 入口参数到 sink 的跨方法污点是预算内 `STATIC_INFERRED` 候选，必须记录不完整性和停止原因。
- 反射、代理、JNI、对象别名、制品外 classpath 和运行时注册不伪装成已解析事实。

反编译视图只能由隔离分析 Worker 生成，作为派生阅读材料；它不能替代原始字节码或在 Control Plane 进程内运行不可信反编译器。

### 3.3 Audit Pipeline

Control Plane 固定编排六角色与确定性动态阶段，模型不能改变顺序。流水线只消费同一 project、artifact 和 scan 的资源；阶段输出通过 schema、证据引用和状态门禁后才能推进。

目标一致性合同要求每个组合审计有 `pipelineRunId`，每个阶段执行有 `stageAttemptId`、`expectedJobId` 或 `expectedTaskId`。终态回调只有匹配当前 run、stage、attempt 和预期资源，且通过 CAS，才能推进。当前实现尚未完整满足，属于 P0。

### 3.4 AI Orchestrator

- Job 固化项目、扫描、制品、角色、Provider、模型、提示词、语言、格式和预算快照。
- Provider 工具调用转换为 canonical ToolCall，再经过角色 allowlist、scope、JSON schema、轮次、deadline 和结果预算校验。
- `code_query`、`facts_search`、`evidence_get`、`plan_propose` 和 `sandbox_probe` 只能访问服务端允许的同作用域资源。
- AUTH 强制代码查询、多 PoC 与多轮补证；PATH/TRIAGE 的动态 probe 是目标合同，服务端门禁尚需补齐。
- 模型结论固定为 `INFERENCE`，无权修改网络、挂载、UID、命令、预算、授权或验证等级。

Provider 原始响应、凭据和完整敏感参数不进入审计事件。隐藏 chain-of-thought 不保存；Provider 显式返回的可见 reasoning/thinking 摘录当前可能经截断、脱敏后持久化为 `MODEL_THINKING`，只能作为不可信审计元数据。

### 3.5 Worker 与动态执行

后端能力显式分级：

| 能力 | 用途 | 边界 |
|------|------|------|
| `STATIC_ONLY` | 无可用 Worker | 拒绝动态任务 |
| `TRUSTED_DOCKER` | 受信本地 JAR 调试 | 普通 runc，不处理恶意制品 |
| `HARDENED_GVISOR` | 目标生产后端 | 需通过完整 release attestation |
| `HARDENED_KATA` | 目标微虚拟机后端 | 需通过完整 release attestation |

`TRUSTED_DOCKER` 只接受 artifact catalog 中的可执行 Spring Boot JAR，执行前复核摘要。runtime image、Agent、命令、挂载、capability、网络和预算由后端固定，浏览器和模型不能提供。它使用断网、只读制品挂载和资源限制，但为兼容受信应用，不等同于非 root、只读 rootfs 的强化沙箱。

JVM Agent 观察 Spring/Servlet、JDBC、HTTP client、文件、进程、Socket、DNS 和 JNDI 等事件。Agent 与被测应用同 JVM，不能作为不可篡改边界；Worker 负责 trace 预算、摘要链和提交校验。

依赖替身当前覆盖固定 loopback HTTP、JDBC、Redis RESP2/RESP3 子集和 MySQL Classic 子集。未知命令、畸形帧和预算超限 fail-closed。每个结果记录 `provenance`，替身命中不能证明真实环境影响。

目标动态执行模型：

```text
TracePlan
  -> ExperimentPlan(entry x 0-n inputs x posture)
  -> Docker Sandbox
       -> World Pack(profile/env/license/files/schema/seed/dependency stubs)
       -> Runtime Posture(UNAUTH / COVERAGE_POSTURE / FORCED_REACHABILITY / BYPASS)
       -> Framework Boundary Adapter(Servlet/Spring identity boundary)
       -> Sensor Agent(entry/parameter/method/guard/effect/dependency/exit)
  -> PathTrace
  -> PathRun summary
  -> Evidence Graph delta
```

职责边界：

- `TracePlan Compiler`：从 Security IR 生成每入口的参数、预期方法 hop、guard、effect、未知点和观测预算。
- `ExperimentPlan Compiler`：生成 entry × 0-n 参数 × posture 的可执行计划，绑定 expected/counter signal 和停止条件。
- `World Pack`：提供 profile、环境、license/文件材料、schema/seed 和依赖替身；缺材料输出 world gap。
- `Runtime Posture Orchestrator`：服务端固定启用 `UNAUTH`、`COVERAGE_POSTURE`、Docker-only `FORCED_REACHABILITY` 和按候选 `BYPASS`。
- `Framework Boundary Adapter`：只在标准框架边界注入扫描身份或记录边界，不追每个自定义 Filter 特例。
- `Sensor Agent`：只观测 entry、参数、方法 hop、guard、effect、依赖、异常和退出；不作为默认 fail-open/bypass 引擎。
- `PathTrace Projector`：把运行时事件投影为有序路径，保留失败前真实业务路径、参数流、sink/effect 和最终阻断原因。

当前动态薄弱点与新约束：

- 启动成功不等于业务路径可达；依赖替身只能降低启动阻力，不能补齐真实表结构、数据、租户、流程状态或第三方服务语义。
- 端口发现必须排除 3306/6379/5432 等依赖监听端口，只有真实 HTTP 服务端口可进入 loopback probe。
- 目标动态模型是“任意入口 × 0-n 参数组合 → 下游 guard/effect/state/dependency 观测 → 反推漏洞假设”。通用 GET/空 payload 只有在绑定 entry signature、空参数理由和观测目标时才是合法探索；盲目洪水不足以发现需要 body、session、CSRF、业务状态或多请求序列的漏洞。
- 动态失败、UNKNOWN、空 PathRun、`httpStatus=-1` 和 MOCK 前置条件不得提升为漏洞疑似；它们应生成启动诊断或 coverage gap。
- 成功启动的断网容器应在有界 TTL 内保留给 PATH/TRIAGE 复用，直到漏洞研判发包确认完成、取消或预算耗尽。
- HTTP 2xx 不是动态成功的唯一标准。若请求最终因数据库不可达、缺表、缺 license、缺文件或业务状态失败，但此前已观察到参数绑定、业务方法或 sink/effect，PathTrace 必须保留这些证据，并把依赖/世界缺口作为退出原因。
- `FORCED_REACHABILITY` 默认开启但仅限 Docker/后续 hardened sandbox，且只能强达已识别 auth/role/permission/license/feature guard。它不得绕过 sanitizer、SQL 参数化、文件类型校验、金额/审批/状态机不变量；其结果必须标 `INSTRUMENTATION_REACHABILITY`，不能单独升 `DYNAMIC_CONFIRMED` 或 `VERIFIED`。

### 3.6 PathRun 与投影

PathRun 是动态实验的核心摘要记录，绑定 scan、entry、identity track、posture、probe attempt、请求、结果、PathTrace、依赖模式、状态和停止原因。详细 schema 见 [PATH_EXPERIMENT_MODEL](PATH_EXPERIMENT_MODEL.md)。

目标顺序是：应用启动诊断 -> TracePlan 编译 -> World Pack 计划 -> 入口参数空间与实验计划编译 -> Worker 执行 -> PathTrace 校验提交 -> 请求级投影 -> PathRun/evidence 可查 -> hypothesis/detector 有界重算 -> 阶段成功。动态结果可以从下游 effect/guard/state 反推新假设，也可以增强、反证或解释静态假设；不能因为动态不可达而删除静态高危候选。

每次 `sandbox_probe` 需要独立 `probeAttemptId`，绑定 canonical tool call、规范化 payload hash、technique、posture、World Pack、计划、task 和 PathRun。`BUSY`、`FAILED`、`CANCELLED`、`UNKNOWN`、空投影或未投影结果不是有效尝试。`DYNAMIC_SUSPECTED` 只能来自真实观察到入口、参数绑定、guard/effect/state、依赖副作用或结构差分的 PathRun/PathTrace。强达轨的观察必须带限制，不能单独证明真实可利用。

## 4. 数据与持久化

SQLite 当前保存：

- 项目、制品元数据、扫描、入口、路径、finding、evidence 和 dashboard 派生数据；
- Provider、加密凭据、角色绑定、AI Job、AI 事件和本地审计；
- Worker task、租约、checkpoint、trace chunk 与摘要链；
- 上传会话、REST 幂等绑定、流水线 cursor、probe plan、PathRun 和 ExperimentPlan；
- 分支覆盖、对照快照、TaintGraph、LedgerDiff、fuzz 策略、root cause 和 VERIFIED 门禁脚手架。

数据库迁移当前注册至 V024。已记录到 `schema_migrations` 的 SQL 文件不可修改；任何 schema 变化只能追加新版本。未知版本、断档或 checksum 漂移拒绝启动。

Provider secret 使用数据库外根密钥和 AES-256-GCM，AAD 绑定 workspace、Provider、credential 与版本；HTTP DTO 不返回明文、密文、nonce 或可逆片段。

当前恢复语义是单节点有界恢复：Worker 任务与 trace 可恢复，进程重启前的 `QUEUED/RUNNING` AI Job 保留为 `FAILED/PROCESS_RESTARTED` 历史，流水线根据 cursor 创建新 Job。它不是多节点队列、分布式租约、exactly-once 或防篡改归档。

### 4.1 作用域与身份

所有 DTO、事件和证据至少绑定适用的 `projectId`、`artifactDigest`、`scanId`、`schemaVersion` 和 evidence refs。动态资源还应绑定 `taskId`、PathRun、attempt 与 policy digest。

当前最大缺口是：

- 流水线回调主要按 scan 关联，缺少完整 run/stage attempt 身份；
- ExperimentPlan 身份未完全贯穿 task -> PathRun -> replay；
- HTTP/Agent/JDBC 的请求级关联不足，任务级 SQL 可能污染多个 PathRun；
- TRIAGE 序列化可能丢失 root cause 和顶层 evidence refs。

### 4.2 事件、幂等与终态

REST 创建类操作使用作用域化 `Idempotency-Key` 和 payload hash；相同键/相同 payload 返回原资源，相同键/不同 payload 返回冲突。幂等记录跨 SQLite 重启保留，但并非所有 mutation 都已覆盖。

SSE 支持 `Last-Event-ID`，只作为增量通知。事件消费者必须校验 schema 与作用域，并在断线、窗口不足或收到终态后通过 GET 获取最终状态。

任务状态必须覆盖成功、失败、取消、阻断、无 Worker、排队超时、证据投影失败和进程重启。没有 Worker 时进入 `DYNAMIC_DISABLED` 或明确失败，不得永久停留 `QUEUED`；`BLOCKED` 不能无限冻结流水线。这些终态合同尚未全部实现。

## 5. 安全边界

- Control Plane 默认只绑定 loopback。本地 bootstrap token、操作员 PAT 和 Worker token 属于不同身份域。
- 制品、模型文本、代码注释、配置和请求响应均视为提示注入与数据注入来源。
- AI 工具使用服务端 allowlist 与结构化参数，禁止 shell、任意命令、宿主路径、Docker socket、策略覆盖和直接外网访问。
- 动态后端不可用或策略不通过时保持静态结果，禁止启动宿主 Java fallback。
- `TRUSTED_DOCKER` 永不开放 `VERIFIED`。gVisor/Kata 必须通过网络、DNS、metadata、宿主挂载、非 root、只读 rootfs、capability、资源耗尽、trace 篡改、Agent 缺失和逃逸套件 attestation。
- `DYNAMIC_CONFIRMED` 由服务端 H3 门禁产生，必须保留 MOCK 与合成身份前置条件；它不是生产数据库证明。
- 浏览器 token 仅适合本地调试；生产 session、CSRF、SSO、多租户隔离和完整 GET 鉴权仍是未来门槛。

## 6. 扩展架构

扩展使用中立事实模型，详细合同见 [EXTENSIBLE_ANALYSIS](EXTENSIBLE_ANALYSIS.md)，长期技术决定见 [ADR-0001](adr/0001-polyglot-control-plane-and-workers.md)：

- ArtifactPackager：如何识别、展开和寻址归档、资源、配置与依赖；
- LanguageAnalyzer：如何把语法/字节码、符号、调用、控制和数据语义降为 Security IR；
- FrameworkAdapter：如何组合入口、鉴权、生命周期、Effect、Guard 和 Summary Provider；
- AnalysisPack：如何定义风险域、detector、假设、实验形状与报告映射；
- RuntimeAdapter：如何在授权沙箱中启动特定运行时并输出中立 RuntimeObservation。

五者不得互相硬编码。新适配器只能补充事实、摘要、候选或实验形状，不能扩大 Worker 权限或自行升级验证状态。当前只有 JVM/Spring 的进程内基线，第二语言 Analyzer 和通用 RuntimeAdapter 协议尚未实现。

## 7. 交付形态

当前开发形态是 Java Control Plane、React/Vite GUI 和可选本地 Docker Worker。

目标交付分两层：

1. Desktop Core：通过 `jlink + jpackage` 为各平台构建自包含安装包，内置 Java runtime、Control Plane、SQLite 与前端静态资源，只绑定 loopback。
2. Sandbox Pack：可选独立 Linux Worker，使用 digest-pinned 镜像和版本化协议；未通过健康检查或 attestation 时动态能力关闭。

Tauri、企业私有化拆分、PostgreSQL/对象存储、ClickHouse、专用工作流引擎和多节点 Worker 都是规模触发后的目标架构，不是当前依赖。

## 8. 当前与目标对照

| 领域 | 当前实现 | 目标合同 |
|------|----------|----------|
| 制品 | 顶层 JAR/WAR/CLASS 有界静态读取；Boot JAR 动态 | Artifact Universe：内嵌依赖/配置/资源/scope/gap |
| 语言 | JVM ASM 索引与 Java Agent 事件 | 进程外 LanguageAnalyzer + 中立 IR；独立 RuntimeAdapter |
| 发现模型 | Spring MVC 参数 + 固定 sink + 有界 TaintPath | Security IR / Evidence Graph + 多类 detector |
| 扩展 | FrameworkAdapter HINT；AnalysisPack 实验模板 | 版本化 Provider SPI，可注册模型/摘要/detector/probe |
| 假设/发现 | Finding 强制 entrypoint/sink | SecurityHypothesis；非数据流 finding 不伪造 sink |
| 持久化 | 单节点 SQLite V021 | 可审计 attempt、完整终态与可迁移存储 |
| 动态 | `STATIC_ONLY` / `TRUSTED_DOCKER`；fixture 与少量 live 通过 | 先成为可靠补证/证伪工具，再评估强化沙箱 |
| AI | 有界 Provider/工具循环；可查询部分代码和证据 | 受限 method/CFG/dataflow/guard 查询；AI 只研判假设，不承担基础召回 |
| 证据 | PathRun、对照、finding；动态实战仍噪声高 | IR 保真持久化、请求级关联、coverage matrix、实战召回基线 |
| VERIFIED | fail-closed 脚手架 | 强化隔离与可重放 release gate |
| 测试 | main-style acceptance 较多 | `mvn test` 或统一 runner 实际执行非零断言 |

实现历史由 Git 保留。架构文档只维护当前结构、目标合同和仍影响设计的缺口。

## 9. 目标代码审计架构

当前 `entry + sink + taintPath` 保留为兼容投影，但不再作为核心数据模型。目标架构为：

```text
Artifact Universe
  │ application / nested dependencies / config / resources / generated code
  ▼
Security IR / Evidence Graph
  │ program / call / control / data / alias / guard / state / runtime
  ├── Dataflow Detectors
  ├── Guard & Ownership Detectors
  ├── State & Sequence Detectors
  ├── Typestate & API Misuse Detectors
  ├── Configuration & Dependency Detectors
  └── Concurrency & Resource Detectors
            │
            ▼
      SecurityHypothesis Pool
            │ server ranking / dedupe / budget / policy
            ▼
      Entry/Parameter Explorer + Experiment Planner
            │
            ▼
      Sandbox / PathRun / RuntimeObservation
            │ request + guard + effect + state correlation
            ▼
      Evidence Graph delta + affected-detector recompute
            │
            └──── support / contradict / refine / stop
```

六个 AI 角色位于 Hypothesis 和 Experiment 两侧，负责查询、解释、PoC 与报告，不是事实解析器、基础召回器或状态机。

### 9.1 Artifact Universe

Artifact Universe 是一次扫描可见程序世界的版本化清单，至少区分：

- application class、Boot `BOOT-INF/lib` 内嵌依赖、WAR library、配置和资源；
- generated、framework、third-party、JDK 与 unknown scope；
- 当前已解析、预算未展开、格式不支持和摘要不一致；
- 运行时加载但静态不存在、静态存在但运行时未加载的差异。

每个未展开依赖、未知协议入口、反射/代理/invokedynamic 点和制品外调用都生成 `CoverageGap`，带 scope、reason、budget 和建议 Provider。扫描完成只表示预算内工作结束，不表示 Universe 完整。

### 9.2 Security IR / Evidence Graph

核心持久化对象：

| 对象 | 作用 |
|------|------|
| `ProgramNode` | class、method、field、instruction、config、resource |
| `EntrySurface` | HTTP、Servlet、Filter、WebFlux、RPC、消息、任务、WebSocket 等入口 |
| `TrustBoundary` | 参数、Header、Cookie、Session、消息、文件、DB 二次数据、配置和环境 |
| `SensitiveEffect` | 系统能力或业务副作用，不限于固定 API sink |
| `Guard` | 鉴权、租户、对象所有权、状态、额度和审批条件 |
| `Sanitizer/Validator` | 编码、参数化、白名单、规范化和拒绝分支 |
| `StateTransition` | 业务对象和安全状态的前后关系 |
| `ResourceLifecycle` | 文件、连接、线程、锁、事务、临时对象和密钥生命周期 |
| `RuntimeObservation` | Entry、Guard、Effect、State、Dependency、Exception 运行时事件 |

关系至少包含 `CALLS`、`CONTROL_DEPENDS_ON`、`DATA_FLOWS_TO`、`ALIASES`、`GUARDED_BY`、`SANITIZED_BY`、`STATE_BEFORE/AFTER`、`OWNS`、`TENANT_SCOPED_BY`、`HAPPENS_BEFORE` 和 `OBSERVED_AS`。

所有节点/边携带稳定 ID、project/artifact/scan、来源、evidence refs、分析器版本、置信度、coverage 状态与 stop reason。完整 `BytecodeFactIndex`、taint steps、coverage 和 unresolved facts 必须结构化持久化；禁止从 `sink.source` 字符串重建空步骤路径。

### 9.3 SecurityHypothesis

所有检测器输出统一假设，而不是直接创建 Finding：

```text
hypothesisId
family / securityProperty / scope
subjects[] / relations[]
supportingEvidenceRefs[] / contradictingEvidenceRefs[]
coverageGaps[]
confidence / lifecycle
recommendedExperiments[]
detectorId / detectorVersion
```

生命周期固定为 `PROPOSED → PLANNED → OBSERVED → SUPPORTED | CONTRADICTED | INSUFFICIENT_EVIDENCE | DISMISSED`。Finding 只从通过 family-specific gate 的假设投影；非数据流假设不要求伪造 source/sink。

### 9.4 多类检测器

| 检测器 | 最小分析能力 | 示例 |
|--------|--------------|------|
| Dataflow | CFG/SSA、call graph、points-to、IFDS/IDE 或等价摘要 | 注入、SSRF、文件、反序列化 |
| Guard/Ownership | guard dominance、对象/租户关系、跨入口一致性 | IDOR/BOLA、鉴权顺序、越权 |
| State/Sequence | 状态转换、跨请求序列、不变量和差分 | 重复提交、额度、审批/流程绕过 |
| Typestate/API Misuse | API 调用协议、生命周期和配置语义 | JWT/密码学、TLS、序列化、事务 |
| Configuration/Dependency | 配置 schema、框架安全选项、SBOM/版本证据 | CORS/CSRF、弱配置、已知依赖风险 |
| Concurrency/Resource | happens-before、锁/事务边界和预算观察 | TOCTOU、竞态、连接/线程/磁盘耗尽 |
| Composition | 共享身份、对象、文件、状态或依赖关系 | 多入口攻击链 |

已知 sink 表作为 Primitive Effect Provider 保留。系统通过 bottom-up MethodSummary 将 primitive effect、guard、sanitizer 和 state effect 传播到自研 wrapper；运行时观察到未知 effect 时执行反向 slice，并产生待建模 coverage gap。AI 可提出未知 effect 候选，但必须由静态或运行时证据确认其结构。

当前产品路径遵循 ADR-0002：继续加深自研轻量 `analysis.kernel`（有界 CFG、MethodSummary、field/return/sanitizer 钩子），现有 ASM 解析器作为快速索引与 fail-safe fallback。完整 SSA/points-to/IFDS/IDE 等重型引擎只能作为进程外 LanguageAnalyzer，并须通过独立 ADR、版本化中立合同、预算与召回率基准后接入；不能把重型依赖直接塞入 Control Plane。

### 9.5 版本化 Provider SPI

扩展面拆成正交 Provider：

- `ArtifactProvider`：展开制品、依赖、资源和运行画像；
- `EntryProvider`：发现并规范化入口；
- `TrustBoundaryProvider`：定义 source/origin；
- `EffectModelProvider`：定义 primitive 与业务 effect；
- `GuardModelProvider`：定义鉴权、所有权、租户和状态 guard；
- `SanitizerModelProvider`：定义净化、编码、参数化和验证；
- `MethodSummaryProvider`：提供框架/依赖方法摘要；
- `DetectorProvider`：注册安全属性检测器；
- `DynamicProbeProvider`：把假设编译为固定策略实验。

FrameworkAdapter 只负责组合适用于某框架的 Provider，AnalysisPack 负责按风险域组合 detector、summary、probe 和 report mapping。二者都不能改变授权、Worker 能力或验证状态。

### 9.6 真实代码查询

AI 工具需要从现有鉴权字符串扫描拆分为版本化只读接口：

- `method_view`：受限反编译/指令切片与稳定位置；
- `callers` / `callees`：调用边、解析类型和 coverage；
- `cfg_view`：基本块、branch、exception edge 和 dominator；
- `dataflow_slice`：source/effect/field/argument 的前向或反向切片；
- `guard_query`：影响目标 operation 的 guard、ownership 和 sanitizer；
- `field_uses` / `config_search`：状态、配置和资源引用。

工具返回 Evidence Graph ID 和限制，不返回未经边界校验的任意文件，也不执行制品。AUTH 必须引用具体方法、guard 和调用关系；字符串/类名扫描仅作为辅助 HINT。

### 9.7 假设驱动动态闭环

Experiment Planner 不只消费已知 taint coverage gap，还支持：

- reachability/branch 实验；
- 不同身份、租户、对象的 differential guard 实验；
- 状态前置、跨请求序列、重放与回滚实验；
- metamorphic input 与 sanitizer 对照；
- typestate/API protocol 实验；
- 并发、TOCTOU 和资源预算实验。

每次实验绑定 `hypothesisId + experimentPlanId + probeAttemptId + stageAttemptId`，并记录 expected signal、counter signal、停止条件和 family-specific gate。运行时事件统一投影 Entry、Guard、Effect、State、Dependency、Exception，再以请求/序列/并发 attempt 关联回 Security IR。

### 9.8 覆盖合同

任何扫描都输出 coverage matrix：

- Artifact Universe 展开率、未读取依赖与配置；
- 入口族召回和动态注册对照；
- 调用边 DIRECT/CHA/points-to/unresolved 比例；
- source/effect/guard/sanitizer/method summary 覆盖；
- 各 detector 的执行、截断、unknown 和 stop reason；
- 各 hypothesis family 的动态实验成功率和反证率。

发布指标使用基准样例、变异样例和保留规则/框架集测量 recall/precision。不得用“扫描成功”“规则数量”或“AI 给出报告”代替覆盖证据。

## 10. 迁移约束

迁移采用平行投影，不一次替换当前 API：

1. 先保真持久化现有 BytecodeFactIndex 和 runtime correlation，旧 entry/sink/path DTO 从新图投影。
2. 再引入 SecurityHypothesis 与通用 Finding，旧 sink finding 作为 DataflowHypothesis 兼容映射。
3. 将 Spring 入口、固定 sink 表和现有 AnalysisPack 迁为默认 Provider，建立等价回归。
4. 引入新分析器和非污点 detector；每个 detector 独立版本、预算、fixture 和 release gate。
5. 最后让动态 Planner 按 Evidence Graph gap 闭环，并逐步淘汰字符串重建和特例编排。

具体优先级和验收只在 [MVP Backlog](MVP_BACKLOG.md) 维护。

## 11. 多语言技术路线与模块演进

### 11.1 技术选型结论

| 组件 | 决定 | 原因 |
|------|------|------|
| React/TypeScript/Vite GUI | 保留 | UI 只要依赖版本化中立 API，不受分析语言限制 |
| Java 17 Control Plane | 保留 | 现有授权、编排、证据和 Worker 能力可复用；改写语言不能解决合同耦合 |
| JDK HttpServer | 当前保留 | 本地 loopback 足够；先抽 transport port，生产 HTTP 需求出现后再选框架 |
| SQLite | 当前保留 | 适合个人单节点；通过 repository 隔离，达到多用户/HA 触发条件再迁移 |
| REST/SSE + JSON Schema | 保留为北向合同 | 易调试、已有基础；SSE 只通知，GET 补偿终态 |
| Analyzer/Runtime 协议 | 目标采用版本化 JSON Schema + JSONL/分块清单 | 先保证中立、摘要、scope、budget 和兼容；实测吞吐不足后再评估 gRPC/Protobuf |

前后端框架不会天然阻止多语言；公共模型和进程边界才决定扩展成本。不得以“未来多语言”为理由提前引入微服务、队列、PostgreSQL 或控制面改写。

### 11.2 目标逻辑模块

```text
frontend -> public contracts
http adapter -> application services -> domain/contracts
persistence adapter -> domain repository ports
orchestration -> application/domain/contracts
language analyzers -> Analyzer/Security IR contracts
runtime workers -> Runtime/Observation contracts
```

目标职责：

- `contracts`：API、事件、Security IR、Analyzer、Runtime schema 与兼容规则；
- `domain`：Evidence、Hypothesis、Coverage、Policy 和状态机；
- `application`：用例、事务、幂等、授权调用和投影协调；
- `adapters/http`：REST/SSE、认证入口和 DTO 映射；
- `adapters/persistence`：repository、迁移和物理存储；
- `orchestration`：pipeline/job/task/attempt、终态、恢复和预算；
- `analyzers/*`：某语言语义到 Security IR；
- `runtimes/*`：某运行时的沙箱启动和观测。

迁移先在当前仓库和进程内建立 port，不要求立即拆 Maven 仓库或服务。新功能不得继续把领域逻辑堆入 `ControlPlaneServer`、`ApiDtos`、SQLite adapter 或前端 `api.ts`；但旧逻辑迁移必须有兼容投影和回归，不能大爆炸重写。

### 11.3 公共合同中立性

- Artifact 使用 digest/mediaType/components/scope，不把 JAR/WAR/CLASS 设为永久封闭枚举。
- ProgramNode 带 `language/kind/symbol/location`；JVM descriptor、TypeScript module 等放 namespaced extension。
- EntrySurface 使用 protocol/operation/address/inputs/guards；HTTP route 只是一个协议形态。
- Finding 绑定 hypothesis/securityProperty；只有 dataflow family 才要求 origin/effect path。
- RuntimeObservation 使用 runtime/eventKind/correlation/subjects；JVM class/method 不是所有语言的必填字段。
- unknown kind 和 extension 必须可保存、转发和通用降级显示；任意 extension 不能直接控制权限或状态提升。

### 11.4 Analyzer 接入门禁

进程外 Analyzer 至少声明 analyzer/version、language/mediaType、schema/capability、预算和 deterministic fingerprint。输出通过分块 manifest 绑定 digest、scope、顺序、大小、压缩、diagnostic、coverage gap、资源使用和 stop reason。

Control Plane 对错误 scope、digest、schema、chunk、预算、迟到回调和部分失败 fail-closed。完整校验前只进入暂存区，不发布到 Evidence Graph。Analyzer 无 Control Plane 数据库、动态 Worker、模型工具、授权或验证状态权限。

### 11.5 前端中立性

前端按 capability、hypothesis family、security property、entry protocol 和通用 evidence 工作。语言/框架特有信息通过可选 renderer 显示；未知 kind 仍能展示证据和 coverage。API schema、TypeScript 类型、运行时 parser 与 Demo fixture 必须由同一合同生成或经 consumer contract 锁定，不能分别手写并长期漂移。

### 11.6 防偏治理

后续 AI 实施必须遵守 [开发与 AI 实施手册](DEVELOPMENT_PLAYBOOK.md)、[AI 任务包模板](AI_TASK_TEMPLATE.md) 和路径上的 `AGENTS.md`。框架、数据库、协议、语言运行时、权限或验证门禁变化必须先有 [ADR](adr/README.md)。提示词只是入口；最终依赖 schema compatibility、架构依赖测试、迁移测试、安全拒绝测试、coverage 基准和根 Agent diff 审计。

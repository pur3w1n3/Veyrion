# 路径实验模型（Path Experiment Model）

本文档是动态实验的**单一事实源**：SecurityHypothesis、PathRun、身份轨、实验计划、超时分类、SQL D1–D3 与状态门禁。实现与其它文档若冲突，以本文为准；变更须同步 [AUDIT_FLOW.md](AUDIT_FLOW.md)、[PRD.md](PRD.md) 与 [PROJECT_MEMORY.md](../PROJECT_MEMORY.md)。

## 1. 产品定位

溯脉对每个入口做**可对照代码的动态路径调试**（类似人工 debug）：

1. 弄清入口、参数、鉴权、预期调用链与 sink/effect；
2. 编译 TracePlan 与 entry × 0-n 参数实验计划；
3. 在 Docker 沙箱内按 UNAUTH / COVERAGE_POSTURE / FORCED_REACHABILITY / BYPASS 执行；
4. 将 HTTP、Sensor Agent、依赖替身、PathTrace 和退出原因对齐到 PathRun；
5. 即使数据库、License、文件、业务状态或依赖不可达，也保留失败前真实路径、参数流和 sink/effect 触发；
6. 再谈漏洞分级。

AI 负责编排实验与写笔记，不能改变沙箱权限、网络策略、挂载或单独升级验证状态。

实战复核后的 MVP 约束：静态 sink/effect、guard 和 SecurityHypothesis 是当前主召回来源；PathRun/PathTrace 是从入口向下游代码路径、guard、effect、state 和依赖副作用反推漏洞假设的动态材料，不是“只要发包就能发现漏洞”的替代引擎。动态覆盖依赖三轨 posture 进入或逼近业务逻辑（§3.1），而不是盲 UNAUTH 洪水；在未完成 [MVP_BACKLOG.md](MVP_BACKLOG.md) P0-15–P0-21 前，动态只能作为有界路径调试工具使用。

## 2. 验证状态全集

| 状态 | 含义 |
|------|------|
| `STATIC_INFERRED` | 仅静态图/注解/配置信号 |
| `DYNAMIC_SUSPECTED` | 运行时观测到达关键点或 SQL 差分疑似，闭环未充分 |
| `DYNAMIC_CONFIRMED` | 动态调试证明恶意片段进入实际发往 DB 的语句，且中途无过滤/参数化阻断（见 §7） |
| `VERIFIED` | 强化沙箱 + 更严可重放门禁；本阶段 SQL 命中**不**直接升此级 |
| `UNREACHED` | 预算、身份不可用、冷启动失败、World Pack 缺口或依赖不可达等原因未完成实验 |

模型输出不能单独升级上述任一状态。

`DYNAMIC_SUSPECTED` 的最低门槛是：一次成功投影的 PathRun/PathTrace 观察到入口、参数绑定、guard/effect/state、依赖副作用或结构差分之一。`httpStatus=-1`、`outcomeClass=UNKNOWN`、空 PathRun、启动失败、探针 JVM 失败、依赖端口误判和仅有 MOCK 前置条件都不能单独产生 `DYNAMIC_SUSPECTED`。

## 3. 轨与运行姿态（Track / Runtime Posture）

| 轨 | 码 | 说明 |
|----|-----|------|
| 未授权 | `UNAUTH` | 不携带合成凭据 |
| 普通用户 | `USER` | 平台合成低权限身份 |
| 管理员 | `ADMIN` | 平台合成管理员身份 |
| 绕过候选 | `BYPASS_CANDIDATE` | 针对鉴权分析点名的绕过假设做验证 |

- 身份材料可以来自平台合成、World Pack、用户授权快照、录制回放或 AI PoC，但 provenance 必须可见，报告展示前置条件。
- 合成失败 → 该轨 `IDENTITY_UNAVAILABLE`，不得假装已执行。
- Wire 码保持上表；产品用途上再分为 UNAUTH / COVERAGE_POSTURE / FORCED_REACHABILITY / BYPASS（§3.1）。不得把扫描身份、强达或管理员可达写成匿名可利用。

### 3.1 四用途姿态（撞墙、标准流通、强达、绕过）

> **重设计中**：产品要求「尽可能记录失败前真实业务路径、参数流和 sink/effect，且禁止 Agent 逐点加插桩」。目标方案见 [DYNAMIC_SANDBOX_POSTURE_REDESIGN.md](DYNAMIC_SANDBOX_POSTURE_REDESIGN.md) 与 [ADR-0004](adr/0004-sandbox-posture-vs-agent-bypass.md)（`PROPOSED`）。


产品目标是**有界动态调试全部可识别 HTTP 入口**（含默认鉴权挡住的入口），以便观测最深业务路径、参数流和 effect/sink；**不是**“保证所有接口完整 2xx”，也不是“忽略鉴权”。

| 用途 | postureKind | Wire | 默认 | 成功时记录什么 | 结论边界 |
|------|-------------|------|------|----------------|----------|
| UNAUTH | `UNAUTH` | `UNAUTH` | 是 | 墙（`AUTH_CHALLENGE`）或意外过闸；标注 `authRequirement` | 401/403 不是漏洞 |
| 标准流通 | `COVERAGE_POSTURE` | `USER` / `ADMIN` | 是 | 标准身份姿态下 entryHit、parameterBound、Guard/Effect/SQL/State | 扫描身份可达不得写成匿名利用 |
| 强达探索 | `FORCED_REACHABILITY` | `ADMIN` 或内部强达 track 投影 | **是，仅 Docker** | 被强达 guard、后续方法 hop、参数流、effect、依赖失败点 | `INSTRUMENTATION_REACHABILITY`，不能单独升 `DYNAMIC_CONFIRMED` / `VERIFIED` |
| 绕过确认 | `BYPASS` | `BYPASS_CANDIDATE` | 有候选时 | AUTH PoC 是否真实过闸 | 可与流通/强达 sink 组链 |

- 每入口应持久化 `authRequirement`（静态 PreAuth/Guard 与/或观测到的 `AUTH_CHALLENGE`）。
- **预算**：默认 = 全入口有界 UNAUTH + 全入口 COVERAGE_POSTURE + Docker 内 FORCED_REACHABILITY +（有候选时）定向 BYPASS。服务端强制总预算上限；高价值入口（上传 / deploy / token / exec / admin、静态敏感 sink、`AUTH_ANALYSIS` 标注）可加深参数空间。
- COVERAGE_POSTURE 失败：发射 `AUTH_POSTURE_GAP`、`IDENTITY_UNAVAILABLE`、`LICENSE_UNAVAILABLE` 或 `WORLD_GAP`，不得静默认定“只打 UNAUTH 即已覆盖全部 API”。
- FORCED_REACHABILITY 默认开启，但只能强达已识别 auth/role/permission/license/feature guard；不得默认强达 sanitizer、SQL 参数化、文件类型校验、金额/审批/状态机不变量。
- 所有姿态必须记录 `postureKind`、`postureProvenance`、`forcedGuardRefs`（若有）和 World Pack 状态。

### 3.2 路径存储与链式研判

Path/Entry 探索按入口存储：`authRequirement`、各姿态 outcome、标准流通/强达轨下观察到的方法 hops、参数流、effect/sink、依赖失败点和退出原因。

PATH_EXPLORATION / VULNERABILITY_TRIAGE **延迟组链**，且必须证据支持：

| 证据组合 | 允许结论 |
|----------|----------|
| `AUTH_BYPASS_CONFIRM`（或强绕过候选）**加上**相关入口 COVERAGE/强达轨 FILE_UPLOAD / SQL / 命令 / 表达式等 effect | Finding 同时引用绕过与 sink 两侧 evidence refs（例：鉴权绕过 + 管理上传 → 任意文件上传链假设） |
| 仅有 COVERAGE_POSTURE effect，无绕过证据 | **鉴权门控风险**：`STATIC_INFERRED` 或带 `SCAN_AUTH_POSTURE` 的 `DYNAMIC_SUSPECTED`；**永不**报为未授权/匿名 RCE |
| 仅有 FORCED_REACHABILITY effect | **强达路径风险材料**：用于发现下游 sink 和补充静态假设，必须标 `INSTRUMENTATION_REACHABILITY`；不能单独证明真实可利用 |
| 仅 `STATIC_INFERRED` / PreAuth 标注 | 不得单独发明漏洞 |
| `AUTH_CHALLENGE` 且无 effect/SQL | `UNREACHED` 或对照事实，不计动态支持 |

ContrastLedger 对照仍然正确：UNAUTH 证明墙或意外过闸；COVERAGE_POSTURE 提供标准姿态覆盖与 sink 观测；FORCED_REACHABILITY 提供强达探索材料；BYPASS 确认可执行绕过。差分用于研判，而不是“无 bypass 就不能覆盖”。

## 4. PathRun（一等公民）

目标键：`scanId + entryId + track + probeAttemptId`。当前实现仍存在 job 级 probe 身份冲突，修复状态见 [MVP_BACKLOG.md](MVP_BACKLOG.md)。

最小字段：

- `entrypointRef`（`entry:*`）
- `track`（§3）
- `postureKind` / `postureProvenance`
- `tracePlanId`
- `experimentPlanId`（若有）
- `worldPackId` 与 World Pack 策略（`OBSERVE_FAIL` / `MOCK_CONTINUE`）
- 请求摘要（method、content-type、参数名、身份轨；敏感值脱敏）
- `outcomeClass`（§5 超时/失败枚举）
- HTTP 状态或传输结果
- `entryHit` / `parameterBound`（布尔或 unknown）
- `pathTraceId` 与调用/Sensor Agent 事件摘要引用
- `sqlEvents[]`（§6）
- `stopReason` / 证据引用列表

GUI、动态验证、路径探索与漏洞研判围绕 PathRun 组织；`AUTH_GAP` 仅为次级静态信号，不得作为结果主列表。

### 4.1 PathTrace

`PathTrace` 是 PathRun 内的有序动态路径，负责表达“失败前真实经过了哪里”。最小事件：

| 事件 | 说明 |
|------|------|
| `ENTRY_HIT` | 命中入口、handler、route、method |
| `PARAMETER_BOUND` | query/body/header/path/form/file/session 参数绑定到 handler 参数或 DTO 字段 |
| `METHOD_HOP` | Controller、Service、Util、Repository、framework callback 等方法 hop |
| `GUARD_DECISION` | auth/role/permission/license/tenant/feature/state guard 的 allow/block/forced |
| `EFFECT_TRIGGERED` | 表达式、SQL、命令、文件、HTTP client、模板、反序列化、JNDI 等 effect |
| `DEPENDENCY_CALL` | DB/Redis/HTTP/File/Message 等依赖调用 |
| `DEPENDENCY_FAILURE` | 依赖不可达、缺表、缺种子、缺响应语义 |
| `EXCEPTION_THROWN` | 异常类型、抛出点、是否被处理 |
| `RETURN_EXIT` | 正常返回或业务退出 |
| `TRACE_TRUNCATED` | 预算截断 |

所有事件必须绑定 `pathRunId`、`probeAttemptId`、`experimentPlanId`、`tracePlanId`、`entryRef`、`track`、`postureKind`、`correlationId`、`requestSeq` 和 evidence ref。

参数流至少表达：

```text
source: query.code
boundTo: CodeController#code arg0
flows:
  CodeService#handle arg0
  ExprUtil#eval arg0
effect:
  EXPRESSION_EXECUTION at ExprUtil#eval
exit:
  JdbcTemplate#query -> DEPENDENCY_UNAVAILABLE
```

若 effect 已触发但后续数据库不可达，报告必须保留 effect 事实和依赖退出原因，不得因 HTTP 500 或 DB failure 丢弃前置路径。

### 4.2 SecurityHypothesis 与 PathRun

PathRun 是一次动态执行事实，不等同于 source-sink path。每次运行必须绑定一个或多个 `hypothesisId`，用于支持、反证或缩小 coverage gap。

假设最小字段：

- `family` 与 `securityProperty`；
- 涉及的 IR nodes/relations 与 scope；
- supporting / contradicting evidence refs；
- coverage gaps 与当前 lifecycle；
- recommended experiments 和 family-specific gate。

非数据流假设可以没有 sink。例如 IDOR 绑定 entry、object ownership guard 与身份差分；状态绕过绑定一组 StateTransition；配置/API misuse 绑定 ConfigurationFact 或调用协议。它们仍通过 PathRun 或静态证据审计，不被强行转换为假 source/sink。

## 5. 超时与失败分类（最小必选）

由探针或 Agent 打标；AI 只能引用，不得发明新码。

| 码 | 含义 |
|----|------|
| `COLD_START` | 应用尚未就绪 / 冷启动窗口内 |
| `AUTH_CHALLENGE` | 401/403/登录重定向/显式鉴权拒绝 |
| `REACHED_NO_BIND` | HTTP 进入入口，但参数未绑定或业务未继续 |
| `BUSINESS_TIMEOUT` | 进程已就绪，单次业务请求超时 |
| `ENGINE_BUSY` | 部署/工作流/引擎处理中 |
| `DEPENDENCY_MOCK_GAP` | MOCK/缺表/缺数据导致的业务失败（非注入证明） |
| `DEPENDENCY_UNAVAILABLE` | DB/Redis/HTTP/File 等外部依赖不可达，但可能已有前置 path/effect |
| `DEPENDENCY_DATA_GAP` | 依赖可达但缺 schema、seed、响应语义或业务数据 |
| `WORLD_STATE_GAP` | 缺租户、业务对象、流程状态、上传目录、模板等世界材料 |
| `LICENSE_UNAVAILABLE` | License、机器码或授权文件材料缺失 |
| `AUTH_POSTURE_GAP` | 标准扫描身份姿态仍无法越过鉴权边界 |
| `FORCED_PAST_GUARD` | 强达越过已识别 guard 后继续执行 |
| `PARAMETER_BINDING_GAP` | 参数或 DTO 未绑定，导致业务未继续 |
| `TRANSPORT_ERROR` | 连接重置、协议错误等 |
| `PROBE_BUDGET` | 预算用尽 |
| `UNKNOWN` | 无法归入以上时 |

面向 GUI / AI 的解释边界：

- `BUSINESS_TIMEOUT`：应用进程已就绪，单个业务请求在读响应阶段耗尽预算；这说明入口可能进入了业务逻辑或阻塞等待依赖，但不能单独证明漏洞或绕过。
- `COLD_START`：连接失败、拒绝或冷启动窗口内不可达；优先解释为应用未监听或尚未完成启动，不应当被写成业务入口已执行。
- `ENGINE_BUSY`：平台、工作流或应用引擎返回忙碌 / 锁定 / 限流 / 5xx 且不像依赖替身缺口；GUI 可提示稍后重试或收窄实验。
- `TRANSPORT_ERROR`：连接重置、协议错误、EOF 等传输层异常；它不同于业务读超时，也不同于冷启动拒绝。
- `AUTH_CHALLENGE`：401/403/登录跳转或明确鉴权拒绝；只有与其它身份轨形成对照时，才可用于鉴权绕过分析。
- `DEPENDENCY_UNAVAILABLE`：依赖不可达不是“路径无效”。若此前已观察到参数流、业务方法或 sink/effect，应保留这些证据并把依赖作为退出原因。
- `FORCED_PAST_GUARD`：只说明 Docker 强达轨越过了某个已识别 guard，用于探索下游；不能单独证明真实环境可利用。
- `PARAMETER_BINDING_GAP`：应反馈给 ExperimentPlan 编译器和 AI，让下一轮补参数或调整 content type，而不是标成业务安全。

任何超时或失败分类都**不能**单独触发 `DYNAMIC_CONFIRMED`；`DYNAMIC_CONFIRMED` 仍只来自 §7 的 SQL H3 服务端门禁，且模型不得单独升级。

## 6. 实验计划与鉴权绕过 PoC（AI 生成，服务端闸门）

所有权：**M** — AI 角色研判并**撰写结构化 PoC**；服务端校验 schema/预算/安全后由动态阶段执行并追踪。

每入口 × 轨建议字段：

- `method`、`contentType`
- 0-n 个参数名、来源、类型、默认值、边界值与有界取值提示；无参数入口必须显式记录 empty-input rationale
- `tracePlanId`
- `postureKind`：`UNAUTH` / `COVERAGE_POSTURE` / `FORCED_REACHABILITY` / `BYPASS`
- `worldPackId` 与依赖策略（`OBSERVE_FAIL` / `MOCK_CONTINUE`）
- `authRequired` / 建议轨 / 强达 guard refs（若有）
- 成功判据：HTTP（如 2xx）+ JSON 字段路径，和/或 Entry/Guard/Effect/State/Dependency Agent 事件类型
- 预算内最大尝试次数

鉴权绕过可行性（`bypassPoCs` / `bypassCandidates`）额外字段：

- `entryRef`（`entry:<scanEntryId>`）
- `techniqueId`（标签，可为 `ALG_NONE` / `CUSTOM_POC` 等）
- `track`、`rationale`、`evidenceRefs`、`confidence`
- **AI 撰写的** `authorizationHeader` / `bladeAuthHeader` / `query` / `bodyHint`（可含 JWT、alg-none、自定义 claims）

交接契约：`AUTH_ANALYSIS`（及研判）→ 服务端 schema 校验并写入 conclusion → `DYNAMIC_VERIFICATION` 用户提示注入 `AUTH_BYPASS_FEASIBILITY` → `sandbox_probe` 携带 AI auth 材料执行 → PathRun/Agent 观测。已知 technique 合成器仅作**无 header 时的回退**，不是唯一路径。若扫描有 JWT/AUTH_GAP/鉴权标注入口而 AUTH 仍空 `bypassPoCs`，服务端发 `AUTH_BYPASS_POC_REQUIRED` 强制补写一轮；仍空则填充标明 `RULE_GENERATED` 的草案供 DYNAMIC 尝试（不升验证级）。

服务端必须拒绝：非 `entry:*`、超长/非法字符头、破坏性 payload、试图改变 `NetworkPolicy.DENY` / 挂载 / UID / 命令。不得由模型单独升级 `DYNAMIC_CONFIRMED` / `VERIFIED`。

### 6.1 多 PoC、多轮与探针身份

`AUTH_ANALYSIS` 的工作循环固定为：`code_query` 阅读鉴权入口与执行链 → 生成不同机制的 PoC → 查询缺失代码/证据 → 修订候选。鉴权面存在时至少调用一次 `code_query`；目标生成不少于 3 个结构不同的候选或逐条给出不可行证据。同一 technique 仅替换 token 字面值不计为不同 PoC。

`PATH_EXPLORATION` 可为 coverage gap 调用 `sandbox_probe`，`VULNERABILITY_TRIAGE` 可为候选漏洞调用 `sandbox_probe` 做复现或证伪。二者都必须提交已有 `entry:*`、目标身份轨、postureKind、objective、candidate inputs、World Pack 策略、停止条件和预期信号，且只能消费服务端返回并成功投影的动态事实。

每次探针调用必须分配 `probeAttemptId`，并绑定 `pipelineRunId`（若属于主流水线）、`stageAttemptId`、`jobId`、canonical `toolCallId`、规范化 payload hash、`experimentPlanId` 和最终 `taskId/pathRunIds`。同一调用重放必须幂等，不同调用不得因共用 jobId 冲突。`BUSY`、`FAILED`、`CANCELLED`、`QUEUED`、超时未投影或空 PathRun 均不计为成功尝试。

探针计划跨重启时必须保持 technique、双鉴权通道、候选输入、停止条件和 hash 语义一致；若敏感材料无法安全恢复，应显式失败并要求重新授权，不得降级成另一套通用探针。

实验计划可以来自静态 hypothesis、AUTH PoC、Provider DynamicProbe、entry signature、参数绑定信息、配置/DTO 推断或人工 replay。目标形态是“任意入口 × 0-n 参数组合 × posture → 下游 method hop / guard / effect / state / dependency 观测 → 反推漏洞假设”。0 参数入口、空 query、空 body 都是合法参数空间；问题在于不能把没有 entry 绑定、参数来源、posture、观测目标和停止条件的盲目洪水直接升级为漏洞研判实验。

### 6.2 实验类型

| 类型 | 典型输入 | expected / counter signal |
|------|----------|---------------------------|
| `REACHABILITY` | entry、posture、0-n 参数 | entry/branch/effect hit 或未达原因 |
| `DATAFLOW_DIFF` | 良性/变异输入 | effect 结构差异、sanitizer/parameterization |
| `GUARD_DIFF` | 身份、租户、对象组合 | guard decision 与相同 effect 的差异 |
| `STATE_SEQUENCE` | 多请求前置与顺序 | state transition、不变量或重复提交 |
| `TYPESTATE_API` | 调用协议/配置变化 | misuse condition 或安全拒绝 |
| `CONCURRENCY_RESOURCE` | 并发度、时序、预算 | race、TOCTOU、lock/resource outcome |
| `FORCED_PATH_DISCOVERY` | 已识别 guard refs、Docker-only posture | 强达后最深 path/effect/dependency exit |

ExperimentPlan 必须包含 `hypothesisId`（探索型可为空但必须有 coverage gap 或 entry reason）、`experimentPlanId`、`tracePlanId`、实验类型、entry/sequence、track、postureKind、0-n inputs、input provenance、worldPackId、expected signal、counter signal、stop condition 和预算。AI 只能提议这些字段；服务端按 detector/provider schema 编译为具体 probe。

## 7. SQL 观测 D1–D3 与 DYNAMIC_CONFIRMED

| 级 | 承诺 |
|----|------|
| **D1** | JDBC/驱动或协议替身层记录 SQL 文本、参数摘要、读写类型，挂到 PathRun；最高可为观测事实 |
| **D2** | 同入口良性输入 vs 元字符探针差分；输入影响 SQL 结构 → 最高 `DYNAMIC_SUSPECTED` |
| **D3** | 可重放实验卡齐套（身份轨、输入、SQL 前后对比、停止条件）；默认仍不升 `VERIFIED` |

**H3 / `DYNAMIC_CONFIRMED` 服务端门禁**（模型不能单独升级）：

1. 存在绑定同一 PathRun 的动态调试轨迹；
2. 实际发往数据库（含 MOCK JDBC/协议替身）的语句文本中出现与探针对应的恶意片段；
3. 从入口参数到该 SQL 的路径上无过滤、无参数化阻断的证据（Agent/插桩记录）；
4. 实验可重放引用齐全。

`DYNAMIC_CONFIRMED` ≠ 生产实库已证实；报告必须标注 `MOCK` 依赖与合成身份前置条件。`VERIFIED` 仍留给强化隔离沙箱与更严门禁。

目标架构允许未来为 Guard/Ownership、State/Sequence、Typestate 等 family 增加独立 `DYNAMIC_CONFIRMED` 门禁，但每个门禁必须有确定性 schema、正负测试和可重放证据。在完成独立审计前，非 SQL family 最高为 `DYNAMIC_SUSPECTED`。

**当前实现警告：** fixture 已覆盖请求窗 SQL 归属和 H3 正负门禁，但实战动态能力仍弱。历史扫描 `scan-7b619e8a65064fa9` 曾出现大量 `DYNAMIC_SUSPECTED / httpStatus=-1 / UNKNOWN / MOCK` PathRun，说明启动诊断、探针计划、运行时观测和 triage 排序曾将失败动态污染为疑似结果。完成实战召回基线、动态启动诊断、hypothesis 实验编译和 RuntimeObservation 对齐前，不得把动态结果宣传为稳定漏洞发现能力。

## 8. 与流水线的关系

见 [AUDIT_FLOW.md](AUDIT_FLOW.md)。摘要：

```text
静态事实 → PRE_ANALYSIS → AUTH_ANALYSIS
  → DYNAMIC_OBSERVATION（按轨；非 AI）
  → AUTH_ANALYSIS 绕过确认（需动态 401/过闸证据）
  → DYNAMIC_VERIFICATION
  → PATH_EXPLORATION ↔ sandbox_probe（coverage gap）
  → VULNERABILITY_TRIAGE ↔ sandbox_probe（复现/证伪）
  → REPORT_GENERATION
```

## 9. 非目标

- LLM 单独升级任何验证状态；
- 自动攻击真实生产数据库；
- 将 `DYNAMIC_CONFIRMED` 宣传为生产已证实；
- 破坏性 payload、内存马、外带网络。

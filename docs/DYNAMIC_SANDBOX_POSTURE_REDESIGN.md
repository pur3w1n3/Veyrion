# 动态路径调试器重设计：TracePlan + 三轨 Posture + World Pack + Sensor Agent

- Status: `ACCEPTED DIRECTION`（架构方向已由 ADR-0004 接受；实现状态以 MVP_BACKLOG P0-21 为准）
- Date: 2026-07-29
- Related: [PATH_EXPERIMENT_MODEL.md](PATH_EXPERIMENT_MODEL.md)、[AUDIT_FLOW.md](AUDIT_FLOW.md)、[TECHNICAL_ARCHITECTURE.md](TECHNICAL_ARCHITECTURE.md)、[MVP_BACKLOG.md](MVP_BACKLOG.md) P0-21、[ADR-0004](adr/0004-sandbox-posture-vs-agent-bypass.md)（`ACCEPTED`）
- 实战对照样本：`scan-28ab5e591f4d4b5a`（Blade）、历史噪声样本 `scan-7b619e8a65064fa9`

本文重新定义 Veyrion 动态能力的目标：**不是让所有接口返回成功，也不是继续给 Agent 增加绕过特例；而是在授权 Docker 沙箱内，对每个可识别入口尽最大努力记录最深可达业务路径、参数流、sink/effect 触发和最终阻断原因**。即使最终因数据库、Redis、License、文件或业务状态不可达失败，也要保留失败前真实经过的 Controller、Service、Util、Repository、Guard、Effect 与依赖调用证据，并反馈给 AI 做假设修订、漏洞研判和报告生成。

## 1. 目标与非目标

### 1.1 目标效果

给定单个 JAR/WAR，在用户授权的断网 Docker 沙箱内：

1. 尽量自动启动应用，不依赖真实外部数据库、缓存、消息或第三方服务。
2. 对每个识别到的 HTTP/Servlet/Spring 入口生成 0-n 参数实验计划。
3. 默认执行三轨：
   - `UNAUTH`：真实无身份撞墙，标注鉴权要求。
   - `COVERAGE_POSTURE`：标准扫描身份姿态，尽量按框架边界进入业务逻辑。
   - `FORCED_REACHABILITY`：默认开启、仅 Docker 沙箱内，对已识别鉴权/权限/License/feature guard 做强达，最大化观察下游路径。
4. 记录入口命中、参数绑定、方法 hops、guard 决策、sink/effect 触发、依赖调用、异常和退出点。
5. 依赖不可达时仍保留此前动态路径。例如：

```text
GET /code?code=${payload}
entryHit=true
parameterBound: code
path:
  CodeController#code
  CodeService#handle
  ExprUtil#eval
effect:
  EXPRESSION_EXECUTION observed at ExprUtil#eval
dependency:
  JdbcTemplate#query -> DATABASE_UNAVAILABLE
exit:
  DEPENDENCY_UNAVAILABLE
conclusion:
  code 参数到达表达式执行点，中途未退出；后续数据库不可达导致业务未完整返回。
```

### 1.2 不能承诺的事

即使强达轨默认开启，也不能承诺“所有接口完整跑通”：

| 阻断类型 | 能否由强达解决 | 正确输出 |
|----------|----------------|----------|
| Spring Security / Filter / `@PreAuthorize` | 多数可逼近，取决于边界识别 | `COVERAGE_POSTURE` 或 `FORCED_REACHABILITY` 进入业务；保留鉴权前置 |
| License / 机器码 / 授权文件 | 部分可强达，部分需 World Pack 材料 | `LICENSE_UNAVAILABLE` 或 `FORCED_REACHABILITY` provenance |
| 参数缺失 / DTO 绑定失败 | 不能靠强达 | `PARAMETER_BINDING_GAP` + 参数计划建议 |
| 业务状态 / 租户 / 数据不存在 | 不能靠强达 | `WORLD_STATE_GAP` / `DEPENDENCY_DATA_GAP` |
| 数据库缺表 / 不可达 | 可用替身继续或诚实失败 | `DEPENDENCY_UNAVAILABLE`，保留失败前路径 |
| 异步任务 / 消息 / 定时任务 | 需 EntryProvider/RuntimeAdapter | `ENTRY_CAPABILITY_GAP` |
| 文件/模板/license 材料缺失 | 需 World Pack | `WORLD_MATERIAL_GAP` |
| 反射/插件/动态路由 | 不保证 | `UNRESOLVED_RUNTIME_DISPATCH` |

产品文案必须使用“最深可达路径、触发过的 sink/effect、最终阻断原因”，不能写“保证完整跑通所有接口”。

## 2. 核心架构

```text
Artifact Universe / Security IR
        |
        v
TracePlan Compiler
  - entries
  - parameters
  - expected methods / effects / guards
  - unknown points to observe
        |
        v
Experiment Compiler
  - entry x 0-n parameters
  - track/posture
  - expected/counter signal
  - stop condition
        |
        v
Runtime Posture Orchestrator
  - UNAUTH
  - COVERAGE_POSTURE
  - FORCED_REACHABILITY
        |
        v
Docker Sandbox Runtime
  - World Pack
  - Framework Boundary Adapter
  - Sensor Agent
        |
        v
PathTrace / RuntimeObservation / PathRun
        |
        v
Evidence Graph delta -> AI roles -> Hypothesis / Triage / Report
```

### 2.1 TracePlan

`TracePlan` 是静态事实到动态观测的桥。它不直接执行请求，而是告诉运行时“该看哪里”：

- entry：route、method、handler、content type、参数签名。
- parameter sources：query、path、header、cookie、body、form、file、session。
- expected hops：Controller、Service、Util、Repository、framework callback。
- expected effects：SQL、表达式执行、命令、文件、HTTP client、模板、反序列化、JNDI、脚本。
- expected guards：auth、role、permission、tenant、license、feature flag、state guard。
- unresolved points：反射、动态 dispatch、未知 wrapper、预算截断点。
- observation budget：每入口最大 hop、最大事件、最大响应时间、最大序列长度。

TracePlan 的目的不是证明漏洞，而是减少全量插桩噪声，并确保“失败前走过哪里”能被稳定还原。

### 2.2 ExperimentPlan

`ExperimentPlan` 绑定一次具体动态尝试：

```text
experimentPlanId
entryRef
tracePlanId
track: UNAUTH | USER | ADMIN | BYPASS_CANDIDATE
postureKind: UNAUTH | COVERAGE_POSTURE | FORCED_REACHABILITY | BYPASS
inputs: 0-n parameters
inputProvenance: STATIC_SIGNATURE | DTO_INFERENCE | AI_PROPOSED | REPLAY | RULE_GENERATED
emptyInputRationale
expectedSignal
counterSignal
stopCondition
worldPackId
budget
```

0 参数、空 query、空 body 是合法输入，但必须记录 `emptyInputRationale`。没有 entry、参数来源、posture、观测目标和停止条件的请求只是诊断噪声，不是路径实验。

### 2.3 Runtime Posture

三轨默认策略：

| 用途 | postureKind | 默认 | 目的 | 结论边界 |
|------|-------------|------|------|----------|
| 撞墙 | `UNAUTH` | 开启 | 无身份证明鉴权墙或意外过闸 | `AUTH_CHALLENGE` 不是漏洞；意外过闸才进入绕过候选 |
| 标准流通 | `COVERAGE_POSTURE` | 开启 | 在标准框架边界注入扫描身份，尽量进入业务逻辑 | 标注 `SCAN_AUTH_POSTURE`，不得写成匿名可利用 |
| 强达探索 | `FORCED_REACHABILITY` | **开启** | Docker 内对已识别 guard/auth/license/feature 边界强达，最大化看到下游路径 | 标注 `INSTRUMENTATION_REACHABILITY`，不能单独升 `DYNAMIC_CONFIRMED` / `VERIFIED` |
| 绕过确认 | `BYPASS` | 有候选时开启 | 执行 AUTH PoC | 成功后可与流通/强达 sink 组链 |

强达默认开启的硬边界：

- 只能在 Docker/后续 hardened sandbox 内执行，绝不在宿主执行。
- 只能由服务端固定策略启用，AI/前端不能改变命令、网络、挂载、UID、预算。
- 只能强达已识别的 auth/permission/role/license/feature guard；不得默认绕过 sanitizer、SQL 参数化、文件类型校验、金额/审批/状态机不变量。
- 所有事件必须带 `postureKind`、`postureProvenance`、`forcedGuardRefs`。
- 强达结果只能用于路径探索、未知 effect 发现、AI 研判和报告限制；不能单独证明真实可利用。

### 2.4 World Pack

`World Pack` 负责“业务世界”，而不是让 Agent 到处 fail-open：

- application profile、环境变量、系统属性；
- 临时目录、上传目录、模板/配置/license 材料；
- JDBC/Redis/MySQL/Postgres 替身或协议 stub；
- schema/seed、租户、用户、角色、业务对象和状态种子；
- 录制回放或用户授权快照；
- 缺失材料、不可合成材料和预算截断的 coverage gap。

依赖策略分两种：

| 策略 | 作用 | 结果语义 |
|------|------|----------|
| `OBSERVE_FAIL` | 依赖不可达时让真实调用失败，但记录失败前路径 | 最诚实，适合确认“sink 已触发但 DB 不可达” |
| `MOCK_CONTINUE` | 替身返回空结果或种子数据，让业务继续走更深 | 适合路径探索，必须标 `MOCK` / `RULE_GENERATED` |

默认执行顺序建议：先用 `MOCK_CONTINUE` 扩大路径探索，再对关键 finding 用 `OBSERVE_FAIL` 复核退出点。

### 2.5 Sensor Agent

Agent 保留，但职责收敛为传感器：

允许：

- HTTP entry、Filter/Interceptor/Controller 命中；
- 参数绑定、DTO 字段绑定、body 解析摘要；
- 方法 hop、调用深度、类/方法位置；
- guard/auth/license/feature/state decision；
- expression/script/template/deserialize/command/file/http-client/sql effect；
- JDBC/Redis/HTTP/file 等依赖调用；
- exception、return、timeout、branch、state transition；
- correlationId、probeAttemptId、experimentPlanId、tracePlanId。

禁止作为默认主线：

- 每个自定义 Filter 一个 Advice 去 return true；
- 每个 LicenseChecker 一个 fail-open；
- 新中间件启动失败就加 Agent 特例；
- 修改 sanitizer、参数化、防注入、文件类型校验、业务金额/审批状态；
- 根据模型输出改变插桩点、命令、网络、挂载或预算。

如果确实需要强达，必须归入 `FORCED_REACHABILITY`，由 Runtime Posture Orchestrator 根据已识别 guard refs 启用，不能散落在 Agent 特例里。

## 3. PathTrace：失败前路径的权威动态记录

`PathRun` 是一次请求/序列尝试，`PathTrace` 是该尝试内的有序动态路径。

### 3.1 最小事件模型

| 事件 | 必需字段 |
|------|----------|
| `ENTRY_HIT` | entryRef、handler、route、method、postureKind |
| `PARAMETER_BOUND` | name、source、target parameter/field、value shape、taint marker |
| `METHOD_HOP` | class、method、bci/line、caller、depth、reason |
| `GUARD_DECISION` | guardRef、kind、decision、forced、postureKind |
| `EFFECT_TRIGGERED` | effectKind、method、argument shape、taint refs、sanitizer refs |
| `DEPENDENCY_CALL` | dependencyKind、operation、target summary、mode、result |
| `DEPENDENCY_FAILURE` | dependencyKind、failure class、missing material、last business hop |
| `EXCEPTION_THROWN` | type、message summary、throw site、handled |
| `RETURN_EXIT` | status、return shape、last hop |
| `TRACE_TRUNCATED` | budget type、last event、reason |

所有事件必须带：

```text
projectId / artifactDigest / scanId
taskId / pathRunId / probeAttemptId / experimentPlanId / tracePlanId
entryRef / track / postureKind / postureProvenance
correlationId / requestSeq
provenance / evidenceRef
```

### 3.2 参数流表达

参数流不是只看 HTTP 参数名，至少要表达：

```text
source: query.code
boundTo:
  CodeController#code(String code) arg0
flows:
  CodeService#handle arg0
  ExprUtil#eval arg0
effect:
  EXPRESSION_EXECUTION at ExprUtil#eval
sanitizer:
  none observed | sanitizer refs
exit:
  JdbcTemplate#query DATABASE_UNAVAILABLE
```

若静态已预测路径但动态未命中，需要记录：

- `PREDICTED_NOT_OBSERVED`
- 未命中原因：参数未绑定、guard 阻断、world gap、反射未解析、预算截断、线程异步未关联。

### 3.3 退出原因

每条 PathTrace 必须有一个终止解释：

| 类别 | 含义 |
|------|------|
| `COMPLETED` | 请求正常返回 |
| `AUTH_CHALLENGE` | 未授权轨撞墙 |
| `GUARD_BLOCKED` | 非鉴权 guard 阻断 |
| `FORCED_PAST_GUARD` | 强达越过 guard 后继续 |
| `PARAMETER_BINDING_GAP` | 参数/DTO 未绑定 |
| `WORLD_STATE_GAP` | 租户、业务对象、流程状态缺失 |
| `DEPENDENCY_UNAVAILABLE` | DB/Redis/HTTP/File 等不可达 |
| `DEPENDENCY_DATA_GAP` | 缺表、缺 seed、缺响应语义 |
| `LICENSE_UNAVAILABLE` | license/机器码材料缺失 |
| `BUSINESS_TIMEOUT` | 业务执行超时 |
| `TRACE_TRUNCATED` | 预算截断 |
| `RUNTIME_CRASH` | JVM 或应用崩溃 |

这些退出原因可以作为 AI 的分析材料，但不能单独升级漏洞验证状态。

## 4. AI 反馈闭环

动态路径调试不是让 AI 直接操作沙箱，而是把结构化动态事实反馈给 AI：

```text
PathTrace / RuntimeObservation
  -> Evidence Graph delta
  -> Hypothesis lifecycle update
  -> AI role context
```

### 4.1 PRE_ANALYSIS

消费静态 TracePlan 候选，输出业务对象、入口优先级、参数空间建议和高价值 World Pack 材料需求。不能补写 FACT。

### 4.2 AUTH_ANALYSIS

消费：

- 静态 guard/auth/license facts；
- `UNAUTH` 轨 `AUTH_CHALLENGE`；
- `COVERAGE_POSTURE` / `FORCED_REACHABILITY` 的 guard decision；
- 被强达的 guard refs。

输出：

- 鉴权要求说明；
- 绕过 PoC；
- “仅扫描姿态可达”与“可能真实绕过”的区分；
- 缺少身份/license/world 材料的 gap。

### 4.3 PATH_EXPLORATION

消费 PathTrace，寻找：

- 参数已到达但后续依赖失败；
- 静态预测 sink 未动态命中；
- 动态发现未知 effect；
- 参数绑定缺口；
- World Pack 缺口。

输出下一轮 ExperimentPlan 建议，但仍由服务端编译和授权。

### 4.4 VULNERABILITY_TRIAGE

消费完整链：

```text
entry -> parameter flow -> guard/posture -> effect -> dependency/exit
```

研判规则：

- 真实轨或标准姿态观察到 sink，可作为强动态支持。
- 强达轨观察到 sink，只能说明“若越过该 guard，则下游存在 effect”，不能单独证明真实可利用。
- 数据库不可达不抹掉之前已经真实发生的表达式执行、命令构造、文件写入尝试或 SQL 构造。
- 依赖替身结果必须标 MOCK；缺 schema/seed 要作为限制写入报告。

### 4.5 REPORT_GENERATION

最终报告必须按入口展示：

- 鉴权要求；
- 三轨 outcome；
- 最深动态路径；
- 参数流；
- sink/effect 触发；
- 退出原因；
- World Pack / Posture / 强达限制；
- AI 研判与反证。

## 5. 新执行流程

```text
1. Artifact Universe
   -> class/config/resource/dependency/license material inventory

2. Static Analysis
   -> EntrySurface / Guard / Parameter / Effect / Dependency / preliminary call path

3. TracePlan Compile
   -> per entry expected hops/effects/guards/unresolved points

4. World Pack Plan
   -> profile/env/license/files/schema/seed/dependency stubs
   -> missing material gaps

5. ExperimentPlan Compile
   -> entry x 0-n inputs x tracks/postures

6. Sandbox Startup
   -> Docker only for dynamic
   -> fixed command/mount/network/UID/budget
   -> app port readiness, dependency port rejection

7. Dynamic Run
   -> UNAUTH
   -> COVERAGE_POSTURE
   -> FORCED_REACHABILITY (default Docker-only)
   -> BYPASS if candidate

8. Trace Projection
   -> PathTrace events
   -> PathRun summary
   -> RuntimeObservation
   -> dependency/world/posture gaps

9. Evidence Graph Delta
   -> support/contradict/refine hypothesis
   -> AI context update

10. PATH/TRIAGE rounds
   -> targeted replay / parameter expansion / world pack refinement

11. Report
   -> final findings + limitations + per-entry path debug evidence
```

## 6. 迁移路线

### Phase 0：冻结语义和降噪

- 接受 ADR-0004 或保持 `PROPOSED` 但按本文作为目标设计。
- 文档统一 `UNAUTH / COVERAGE_POSTURE / FORCED_REACHABILITY / BYPASS`。
- 明确 `UNKNOWN/-1/MOCK-only` 不进入主漏洞疑似。
- 禁止新增 Agent Bypass Zoo 特例。

验收：文档、Backlog、GUI 文案、报告语义一致。

### Phase 1：TracePlan 合同

- 定义 TracePlan schema。
- 从静态 Entry、参数、Guard、Effect、调用路径生成 TracePlan。
- 旧 taint path / sink path 兼容投影到 TracePlan。
- Coverage gap 记录 unresolved hops。

验收：给定 fixture，TracePlan 能列出入口、参数、预期 Controller/Service/Effect 和未知点。

### Phase 2：PathTrace 事件模型

- 定义 PathTrace / TraceEvent schema。
- Sensor Agent 事件映射为 ENTRY、PARAMETER、METHOD、GUARD、EFFECT、DEPENDENCY、EXCEPTION、EXIT。
- PathRun 汇总引用 PathTrace，而不是只保存 HTTP/SQL 摘要。
- 添加 trace budget、truncation 和 integrity summary。

验收：即使请求最终 500，也能看到失败前最后业务 hop 和 effect。

### Phase 3：World Pack 最小版

- WorldPack manifest：profile/env/system properties/files/license/dependency stubs/schema/seed。
- 支持 `OBSERVE_FAIL` 与 `MOCK_CONTINUE`。
- JDBC/Redis/MySQL 现有替身迁入 World Pack 语义。
- 缺表、缺种子、缺 license、缺文件统一输出 world gap。

验收：数据库不可达样本保留表达式/SQL 构造前路径，并标 `DEPENDENCY_UNAVAILABLE`。

### Phase 4：Runtime Posture Orchestrator

- 定义 postureKind/postureProvenance/forcedGuardRefs。
- 实现 UNAUTH 与 COVERAGE_POSTURE 合同。
- 标准框架边界优先：Servlet Principal、Spring SecurityContext、Method Security。
- JWT/Blade mint 降为 IdentityMaterial 来源。

验收：Blade/PreAuth 类样本在 COVERAGE_POSTURE 至少进入 handler 或明确 `AUTH_POSTURE_GAP`。

### Phase 5：FORCED_REACHABILITY 默认 Docker 轨

- 仅 Docker sandbox 可启用。
- 只对已识别 auth/role/permission/license/feature guard refs 强达。
- 强达事件写入 PathTrace，且每个被越过 guard 有 evidenceRef。
- 禁止强达 sanitizer、参数化、文件类型校验、金额/审批/状态机不变量。

验收：无标准身份材料时，强达轨能越过已识别鉴权边界并记录下游路径；报告明确 `INSTRUMENTATION_REACHABILITY`，不升 `VERIFIED`。

### Phase 6：AI 反馈与多轮探索

- Evidence Graph delta 暴露给 AI 工具。
- PATH 根据 PathTrace 缺口生成下一轮参数/World Pack 建议。
- TRIAGE 根据 posture 和 evidence refs 分类：supported、contradicted、insufficient、unreached。
- REPORT 输出 per-entry path debug section。

验收：AI 能引用具体 Controller/Util/Service/sink/依赖失败点，而不是只解释 HTTP 500。

### Phase 7：GUI 与报告

- Dynamic Diagnostics 显示 World/Posture/Forced gaps。
- PathRun 页面展示 PathTrace 时间线。
- Findings 详情展示参数流和退出原因。
- 最终报告按入口列最深可达路径。

验收：用户能从报告点击到 PathTrace 事件、代码位置和 AI 研判。

## 7. 开发任务拆分

### T1 合同与迁移

Allowed paths:

- contracts/schema（或现有 DTO 合同位置）
- `docs/*`
- 新增迁移（只追加）
- contract tests

工作：

- TracePlan schema。
- PathTrace schema。
- WorldPack manifest schema。
- RuntimePosture schema。
- 旧 PathRun 兼容读取。

测试：

- schema round trip；
- unknown enum 降级；
- old scan no posture fields 兼容；
- migration empty DB / old DB upgrade。

### T2 静态 TracePlan 编译

工作：

- Entry + parameter + static call path + effect -> TracePlan。
- Guard / auth / license facts -> guard refs。
- unresolved calls -> trace coverage gap。

测试：

- Controller -> Service -> Util -> sink fixture；
- 0 参数入口；
- DTO body 参数；
- unresolved reflection gap。

### T3 Sensor Agent 事件映射

工作：

- 统一事件 envelope。
- HTTP/parameter/method/effect/dependency/exception/exit 映射。
- correlationId 贯穿。
- trace budget。

测试：

- 请求成功；
- 请求 500；
- DB 不可达；
- effect 先触发后失败；
- trace truncation。

### T4 World Pack

工作：

- WorldPack manifest。
- OBSERVE_FAIL。
- MOCK_CONTINUE。
- JDBC/Redis/MySQL 现有替身迁移语义。
- world gaps。

测试：

- DB 不可达但路径保留；
- 缺表；
- mock seed 继续；
- license file missing。

### T5 Posture Orchestrator

工作：

- 三轨编排。
- standard coverage posture。
- forced reachability Docker-only。
- forced guard refs。

测试：

- UNAUTH 401 标 authRequirement；
- COVERAGE_POSTURE 进入 handler；
- FORCED_REACHABILITY 越过已识别 guard；
- 非 Docker 禁止 forced；
- AI/前端无法启用策略字段。

### T6 PathTrace 投影与 AI 查询

工作：

- PathTrace -> RuntimeObservation。
- Evidence Graph delta。
- AI tool 可查询 path trace slice。
- Hypothesis lifecycle 更新。

测试：

- effect observed -> hypothesis supported；
- guard blocked -> unreached/counter evidence；
- forced-only effect -> limited support；
- dependency failure -> not drop prior effect。

### T7 GUI/报告

工作：

- PathTrace timeline。
- Parameter flow view。
- World/Posture diagnostics。
- Report per-entry path debug。

测试：

- `npm run build`；
- empty/error/unknown；
- forced evidence not rendered as verified；
- long trace responsive。

## 8. 验证逻辑

### 8.1 最小验收样本

至少建立以下 fixture/实战样本：

1. `GET /code?code=x`：参数进入表达式执行，再访问 DB，DB 不可达。
2. `POST /upload`：需要鉴权，强达后触发文件写入尝试。
3. `GET /admin/list`：UNAUTH 401，COVERAGE_POSTURE 进入 handler，DB 缺表。
4. `POST /state/approve`：缺业务状态，输出 WORLD_STATE_GAP。
5. License guard 样本：COVERAGE_POSTURE 失败，FORCED_REACHABILITY 越过 license guard，标限制。

### 8.2 判定门槛

动态路径调试成功不等于 HTTP 2xx。成功分级：

| 级别 | 判定 |
|------|------|
| `ENTRY_REACHED` | entryHit=true |
| `PARAMETER_BOUND` | 至少一个计划参数绑定到 handler/DTO |
| `BUSINESS_HOP_OBSERVED` | 进入 Controller/Service/Util 等业务方法 |
| `EFFECT_OBSERVED` | sink/effect 触发 |
| `DEPENDENCY_EXIT_EXPLAINED` | 依赖失败点明确，且保留失败前路径 |
| `COMPLETE_RESPONSE` | 请求完整返回 |

MVP 应优先追求 `EFFECT_OBSERVED` 和 `DEPENDENCY_EXIT_EXPLAINED`，而不是只追求 2xx。

### 8.3 状态门禁

- `UNAUTH` 401：`UNREACHED/AUTH_CHALLENGE`，不是漏洞。
- `COVERAGE_POSTURE` sink：可支持“鉴权门控路径存在”，不得写匿名利用。
- `FORCED_REACHABILITY` sink：只支持“强达路径下存在下游 effect”，必须标限制。
- `OBSERVE_FAIL` 中 effect 已触发但 DB 不可达：保留 effect，可进入 triage，但限制写入报告。
- `MOCK_CONTINUE` 中 effect：标 MOCK，不得升 `VERIFIED`。
- SQL H3 仍需独立门禁；强达或 MOCK 不能绕过门禁。

### 8.4 回归指标

每次发布至少记录：

- entry count；
- entries with TracePlan；
- entries with UNAUTH outcome；
- entries with COVERAGE_POSTURE path；
- entries with FORCED_REACHABILITY path；
- entries with parameterBound；
- entries with effect observed；
- dependency/world gaps；
- forced guard count；
- dynamic suspected noise count；
- AI triage references with PathTrace evidence。

## 9. 风险与控制

| 风险 | 控制 |
|------|------|
| 强达导致假阳性 | provenance 强制可见；不能单独升高验证；报告必须写限制 |
| Agent 再次膨胀 | 禁止新增 fail-open 特例；强达只通过 Posture Orchestrator |
| MOCK 被误解成真实环境 | World Pack provenance + report limitation |
| 路径 trace 过大 | TracePlan + budget + truncation |
| 异步/多线程关联错 | correlationId + requestSeq + happens-before gap |
| AI 编造路径 | AI 只能引用 PathTrace evidence refs；不能补写 FACT |
| 沙箱逃逸风险 | 动态仅 Docker/后续 hardened；无宿主 fallback；固定命令/网络/挂载/UID |

## 10. 一句话决策

Veyrion 动态能力应从“HTTP 探针 + Agent 特例绕过”升级为“**Docker 内动态路径调试器**”：静态 TracePlan 指路，World Pack 提供业务世界，Runtime Posture 三轨执行，Sensor Agent 只观测，PathTrace 保留失败前真实路径，AI 基于结构化证据做研判。

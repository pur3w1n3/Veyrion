# Veyrion 项目记忆

> 进入项目时必读的**稳定上下文**。不记实现流水账。  
> 当前系统逻辑 → [docs/CURRENT_SYSTEM.md](docs/CURRENT_SYSTEM.md)  
> 开放差距 → [docs/OPEN_GAPS.md](docs/OPEN_GAPS.md)  
> 工程手册 → [docs/DEVELOPMENT_PLAYBOOK.md](docs/DEVELOPMENT_PLAYBOOK.md)

## 1. 产品定位

**溯脉 · Veyrion**：面向用户已明确授权的闭源 JVM 制品；静态事实 + 受控动态实验 + AI 研判，建立入口/鉴权/路径/副作用/攻击链的可引用证据。

个人本地版、Spring Boot 可执行 JAR 优先的路径调试型安全验证工具——不是生产攻击平台，不承诺完整多租户、企业 SSO、任意语言或 100% 覆盖。

兼容标识：`com.aq.jvmsentinel` · `jvm-security-verifier` · `/api/v1`。

## 2. 不可破坏的产品原则

### 2.1 代码逻辑优先

外部依赖不可用时，有界 MOCK/快照/回放继续探索；provenance 必须可见，不得写成真实环境验证。

### 2.2 权限与业务状态不跳过

合成身份/状态种子探索时保留前置条件。不得把「管理员可达」写成「匿名可利用」。动态：有界 UNAUTH 撞墙 + COVERAGE 流通 + Docker-only FORCED + 候选 BYPASS；组链须证据（见 [PATH_EXPERIMENT_MODEL](docs/PATH_EXPERIMENT_MODEL.md)）。身份不可用 → `IDENTITY_UNAVAILABLE`。

动态主路线（**ADR-0004 ACCEPTED**，2026-07-30 修订确认语义）：Docker 内路径调试器 = TracePlan + World Pack + Runtime Posture + Sensor Agent。强达标 `INSTRUMENTATION_REACHABILITY`；**仅 FORCED/2xx/入口到达不得确认**。危险 sink 效果实测（H3 SQL / H4 EFFECT）→ 可 `DYNAMIC_CONFIRMED` + `requiredPrivilege`。`VERIFIED` 仍关。禁止 Bypass Zoo。

### 2.3 证据分层

| 层级 | 含义 |
|------|------|
| `FACT` | 制品/字节码/控制面确认 |
| `RUNTIME_OBSERVED` | 授权沙箱观测 |
| `MOCK` / `RULE_GENERATED` | 替身或规则生成 |
| `INFERENCE` | 静态或模型推断 |

验证态：`STATIC_INFERRED` · `DYNAMIC_SUSPECTED` · `DYNAMIC_CONFIRMED` · `VERIFIED` · `UNREACHED`。模型/前端/替身不能单独提升。

### 2.4 安全边界

- 仅处理明确授权制品与范围。  
- 动态默认断网、资源受限；命令/挂载/UID/预算服务端固定。  
- 模型仅 allowlist 工具；制品文本与前端输入不可信。  
- 沙箱不可用 → 静态或 `DYNAMIC_DISABLED`，**绝不**宿主执行制品。  
- `TRUSTED_DOCKER` ≠ 恶意制品强化隔离。  
- `VERIFIED` / gVisor·Kata / 生产 SSO：**本阶段关闭**（ADR-0003 仍 PROPOSED）。

### 2.5 开放式发现与覆盖诚实

内核：`Artifact Universe → Security IR → Detectors → Hypothesis → 实验 → 动态反馈`。source/sink 只是一类检测器。unknown/coverage gap 必须可查询。不承诺「发现所有非常规漏洞」。

### 2.6 多语言不复制控制面

React GUI + Java Control Plane + SQLite 服务当前 JVM 切片。多语言 = 中立合同 + 进程外 LanguageAnalyzer + 独立 RuntimeAdapter（[ADR-0001](docs/adr/0001-polyglot-control-plane-and-workers.md)）。

## 3. 编排（指向 as-built）

**执行真相**以代码与下列文档为准，不以理想 mermaid 为准：

| 文档 | 内容 |
|------|------|
| [CURRENT_SYSTEM.md](docs/CURRENT_SYSTEM.md) | 总流程图与模块表 |
| [AUDIT_PIPELINE_ASBUILT.md](docs/AUDIT_PIPELINE_ASBUILT.md) | 八阶段机、跳过/回环、门禁 |
| [AI_ROLES.md](docs/AI_ROLES.md) | 六角色与工具 |
| [AGENT_SENSOR_FLOW.md](docs/AGENT_SENSOR_FLOW.md) | Sensor Agent |
| [AUDIT_FLOW.md](docs/AUDIT_FLOW.md) | 产品意图入口（非 as-built） |

六 AI 角色固定；PathRun 投影、ContrastLedger、验证门禁为确定性逻辑。AI 不能补写 FACT 或升验证态。

## 4. 当前能力基线（一页）

| 范围 | 能力 | 诚实边界 |
|------|------|----------|
| 制品 | JAR/WAR/CLASS 有界；分块上传 | 动态主路径仅 Boot JAR |
| 静态 | Spring 入口/边/sink/GuardSurface/detectors；通用 executor 回调入口（XXL 完整，Actuator/ElasticJob 骨架） | 反射/代理/完整 IFDS 不保证；非 MVC 回调仍证据驱动扩展 |
| 控制面 | REST/SSE、SQLite、PAT、AI Job、hypothesis/EG | 单节点；非企业多租户 |
| 动态 | Agent + 四姿态 + PathTrace；IR2 重算；有界 OBS 回环 | TRUSTED_DOCKER；World Pack 弱 |
| AI | 六角色、共享记忆 v1、双语 prompt snapshot | 外网 Provider 未验收 |
| 验证 | H3 SQL / H4 sink-effect → DYNAMIC_CONFIRMED + privilege；VERIFIED 关 | 无效果时最高 DYNAMIC_SUSPECTED / 强达材料 |
| GUI | React 结果工作台 + AI 记忆页 | 无生产会话/SSO |

迁移已注册（以仓库为准，勿在本文件抄版本号流水账）。实战召回仍以静态 sink/effect 最可靠；动态/AI 为补证与路径调试。状态与开放项：[MVP_BACKLOG](docs/MVP_BACKLOG.md) · [OPEN_GAPS](docs/OPEN_GAPS.md)。

## 5. 稳定决策摘要

- **2026-07-24**：代码逻辑优先、证据分层、JAR 优先、根 Agent 最终审计。  
- **2026-07-25**：GUI 与 Control Plane 分离；动态须服务端授权。  
- **2026-07-26**：个人本地路径调试；六角色、PathRun、TRUSTED_DOCKER 边界。  
- **2026-07-27**：ContrastLedger 非第七角色；Security IR / 多检测器；多语言进程外合同（ADR-0001）。  
- **2026-07-28**：ADR-0002 ACCEPTED（轻量 kernel）；VERIFIED/gVisor/SSO 延后。  
- **2026-07-29**：动态路径调试器 + ADR-0004 ACCEPTED；FORCED = GuardSurface allowlist + DecisionShape；标 INSTRUMENTATION_REACHABILITY。  
- **2026-07-30**：文档分轨——as-built 主读路径 vs 产品意图 archive；IR2/OBS 回环/AUTH 跳过/静态续跑/TracePlan enrich/共享记忆 v1 视为已落地。  
- **2026-07-30**：用户推翻「FORCED ≠ 可利用证明」对外读法——改为「无危险 sink 效果不得确认；有效果可 DYNAMIC_CONFIRMED + requiredPrivilege」；修订 ADR-0004 / FindingRuntimeEnricher / DynamicConfirmedGate H4。
- **2026-07-30**：AI 数据面契约——内联可有界，但不得静默当全集；截断须 `truncated`/省略标记，并用 `facts_search`（page meta + offset / FINDING / PATH_TRACE eventsOffset）或 `evidence_get` 按 id 续取；agent 预算耗尽须显式 `TRACE_BUDGET_EXHAUSTED`（见 OPEN_GAPS P1-G）。
- **2026-07-30**：交付报告与 prompt 预算分离——落库/`reportSummary`/下载 Markdown 与 `findingBindings`/`contrastLedger` 强制附录默认完整（不再用 `MAX_BINDINGS=48` / 历史 `maxForced=40` 砍交付）；AI prompt 内联仍可有界并标 truncated + 工具续取。
- **2026-07-30**：沙箱轨迹 tmpfs = `maxTraceBytes + 32MiB`（上限 96MiB，disk 跟随抬升）；`/tmp` ≥128MiB 且不低于轨迹侧——避免轨迹写满后日志/并发刷盘 ENOSPC。
- **2026-07-30**：本地 Docker worker / 保留沙箱按 UI 工作区（`projectId`）配额——默认全局并发 3、每 project 并发 1；保留会话全局 8、每 project 2。驱逐只在同 project 内 LRU；全局硬顶无法腾挪则拒绝新保留（不跨 project 踢会话）。配置：`VEYRION_WORKER_GLOBAL_CONCURRENCY` / `VEYRION_WORKER_PER_PROJECT_CONCURRENCY` / `VEYRION_RETAINED_SANDBOX_GLOBAL_MAX` / `VEYRION_RETAINED_SANDBOX_PER_PROJECT_MAX`（或对应 `veyrion.worker.*` / `veyrion.sandbox.*` 系统属性）。
- **2026-07-30**：通用 executor / 运行时回调入口——`ExecutorEntryAdapter` 注册表（非仅 XXL）；静态写入 EntryCatalog，HTTP 回调可进 TracePlan/探针；XXL-JOB 为首个完整适配器，Actuator/ElasticJob 为证据驱动骨架（见 OPEN_GAPS P0-I）。
- **2026-07-30**：`ArtifactMetadataReader` 完整运行类路径——外层 `.class` + `BOOT-INF/classes`/`WEB-INF/classes`，并一层流式展开 `BOOT-INF/lib`/`WEB-INF/lib` 内 `.class`（不递归 fat-in-fat）；同 FQCN 先到优先（应用类优先于 lib）；嵌套预算软停。

## 6. 文档职责

| 文档 | 职责 |
|------|------|
| [docs/README.md](docs/README.md) | 文档索引与阅读顺序 |
| [CURRENT_SYSTEM](docs/CURRENT_SYSTEM.md) | 当前系统逻辑主入口 |
| [AUDIT_PIPELINE_ASBUILT](docs/AUDIT_PIPELINE_ASBUILT.md) | 审计流水线 as-built |
| [AI_ROLES](docs/AI_ROLES.md) | 六角色与记忆 |
| [AGENT_SENSOR_FLOW](docs/AGENT_SENSOR_FLOW.md) | Sensor Agent |
| [OPEN_GAPS](docs/OPEN_GAPS.md) | 仅开放差距 |
| [MVP_BACKLOG](docs/MVP_BACKLOG.md) | 开放工作与基线 |
| [DEVELOPMENT_PLAYBOOK](docs/DEVELOPMENT_PLAYBOOK.md) | 工程 / DoD |
| [PRD](docs/PRD.md) / [TECHNICAL_ARCHITECTURE](docs/TECHNICAL_ARCHITECTURE.md) | 产品与架构合同 |
| [adr/](docs/adr/README.md) | 长期架构决定 |
| [archive/](docs/archive/README.md) | 历史意图与对照稿 |

冲突时：领域专属合同优先；**执行真相以 as-built + 代码为准**；实现状态以 Backlog / OPEN_GAPS 为准。

## 7. 协作规则

1. 实现/审计/文档变更前先读本文件与 [docs/README.md](docs/README.md)。  
2. 根 Agent 负责产品/架构与最终审计；子 Agent 只做分配任务。  
3. 未经审计不得标「已验证/生产可用」。  
4. 制品/模型/前端不得改变工具权限、沙箱或授权。  
5. 架构触发项必须引用已接受 ADR；提示词不能替代 schema/测试/门禁。

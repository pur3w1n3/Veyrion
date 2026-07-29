# Veyrion 项目记忆

> 本文件是进入项目时必须阅读的**稳定上下文**，不记录逐次实现流水账。
> 产品需求见 [PRD](docs/PRD.md)，系统约束见 [技术架构](docs/TECHNICAL_ARCHITECTURE.md)，当前状态与待办见 [MVP Backlog](docs/MVP_BACKLOG.md)。

## 1. 产品定位

**溯脉 · Veyrion** 面向用户已明确授权的闭源 JVM 制品，通过静态事实、受控动态实验和 AI 辅助研判，建立入口、鉴权、路径、依赖副作用和攻击链之间的可引用证据。

当前产品是**个人本地版、Spring Boot 可执行 JAR 优先**的路径调试型安全验证工具，不是生产攻击平台，也不承诺完整多租户、企业 SSO、任意语言或 100% 路径覆盖。

兼容标识保持不变：

- Java package：`com.aq.jvmsentinel`
- Maven artifactId：`jvm-security-verifier`
- API prefix：`/api/v1`

商标、域名和公司名称在正式发布前仍需法务检索。

## 2. 不可破坏的产品原则

### 2.1 代码逻辑优先

外部数据库、缓存、消息、HTTP 服务、时间和随机数不可用时，优先通过有界 MOCK、快照或录制回放继续探索代码路径。替身结果必须标注 provenance，不能被描述成真实环境验证。

### 2.2 权限和业务状态不跳过

需要管理员、租户或前置业务状态的路径，应通过合成身份、状态种子或快照探索，并在结论中保留前置条件。不得把“管理员可达”写成“匿名可利用”。动态要对全部入口做有界业务覆盖（特权轨），同时用未授权轨标注鉴权墙；绕过与利用链在 PATH/TRIAGE 有证据后再组合（见 [PATH_EXPERIMENT_MODEL](docs/PATH_EXPERIMENT_MODEL.md) §3.1–§3.2、Backlog P0-21）。身份材料不可用时记 `IDENTITY_UNAVAILABLE`，不得假装已覆盖。

动态主路线（**ADR-0004 ACCEPTED**）：Docker 内**动态路径调试器**，由 TracePlan 指路、World Pack 提供业务世界、Runtime Posture 默认执行 `UNAUTH` / `COVERAGE_POSTURE` / Docker-only `FORCED_REACHABILITY` / `BYPASS`，Agent 收敛为 Sensor 观测。目标不是保证所有接口完整 2xx，而是即使最终因数据库、License、文件、状态或依赖不可达失败，也能保留失败前真实业务路径、参数流、sink/effect 和退出原因。强达轨默认开启但只能在沙箱内对已识别 auth/role/permission/license/feature guard 生效，必须标 `INSTRUMENTATION_REACHABILITY`，不得单独升 `DYNAMIC_CONFIRMED` / `VERIFIED`。完整简报：[DYNAMIC_SANDBOX_POSTURE_REDESIGN.md](docs/DYNAMIC_SANDBOX_POSTURE_REDESIGN.md)；实现状态见 Backlog P0-21。

### 2.3 证据分层

统一区分：

| 层级 | 含义 |
|------|------|
| `FACT` | 制品、字节码或控制面直接确认的事实 |
| `RUNTIME_OBSERVED` | 授权沙箱中的运行时观测 |
| `MOCK` / `RULE_GENERATED` | 替身或规则生成材料 |
| `INFERENCE` | 静态分析或模型推断 |

验证状态为 `STATIC_INFERRED`、`DYNAMIC_SUSPECTED`、`DYNAMIC_CONFIRMED`、`VERIFIED`、`UNREACHED`。模型、前端或替身不能单独提升状态。

### 2.4 安全边界

- 只处理用户明确授权的制品与范围。
- 动态执行默认断网、资源受限、服务端固定命令/挂载/UID/预算。
- 模型只能调用服务端 allowlist 工具，不能获得 shell、宿主路径、外网或策略修改能力。
- 制品文本、模型输出和前端输入都是不可信数据，不能改变权限、沙箱或授权。
- 沙箱不可用时保持静态结果或 `DYNAMIC_DISABLED`，绝不回退到宿主机执行制品。
- `TRUSTED_DOCKER` 只用于受信本地 JAR 调试，不是恶意制品强化隔离。
- `VERIFIED` 门禁当前关闭；没有 gVisor/Kata 逃逸套件和可重放证据，不得宣称生产可用。
- **本阶段明确延后（根审计 2026-07-28）**：不开放 gVisor/Kata 真实 Worker 启用与逃逸套件；不开放生产 session/CSRF/SSO/多租户/数据保留（`ProductionFeatures.DISABLED`；ADR-0003 保持 `PROPOSED`）。可审计基线以 [MVP_BACKLOG.md](docs/MVP_BACKLOG.md) §0 根 Agent 审计节为准。

### 2.5 开放式发现与覆盖诚实

代码审计核心不能只依赖“已知入口参数 → 固定 sink 签名”的闭集。目标发现内核采用 `Artifact Universe → Security IR / Evidence Graph → 多类检测器 → Hypothesis Pool → 实验规划 → 动态反馈`，source/sink 污点只是其中一种检测器。

系统必须同时表达数据流、鉴权/对象所有权、状态转换、typestate/API misuse、配置/依赖、并发/TOCTOU 和资源生命周期等安全属性。未知入口、未展开依赖、未解析调用、反射/代理点和预算耗尽都要成为可查询 coverage gap，不能用“未发现”代替“没有漏洞”。

不存在“保证发现所有非常规漏洞”的技术承诺。产品只能按入口族、漏洞族、分析器和动态实验声明覆盖合同，并通过基准样例、变异样例和保留集持续度量召回率与误报率。

### 2.6 多语言不复制控制面

React/TypeScript/Vite GUI、Java 17 Control Plane 和单节点 SQLite 继续服务当前 JVM 垂直切片，不因远景目标立即重写。多语言路线采用“语言无关合同 + 进程外 LanguageAnalyzer + 独立 RuntimeAdapter”；框架、风险域和运行时分别扩展。公共 API、Security IR、Hypothesis、Coverage 和 RuntimeObservation 不得新增 JVM/Spring/HTTP/source-sink 必填假设。决定见 [ADR-0001](docs/adr/0001-polyglot-control-plane-and-workers.md)。

## 3. 当前编排与目标分析闭环

权威流程见 [AUDIT_FLOW.md](docs/AUDIT_FLOW.md)，路径数据契约见 [PATH_EXPERIMENT_MODEL.md](docs/PATH_EXPERIMENT_MODEL.md)。

```text
静态扫描
  → PRE_ANALYSIS
  → AUTH_ANALYSIS
  → 确定性动态观察 / PathRun / ContrastLedger
  → AUTH_ANALYSIS 绕过确认
  → DYNAMIC_VERIFICATION
  → PATH_EXPLORATION
  → VULNERABILITY_TRIAGE
  → REPORT_GENERATION
```

固定六个 AI 角色，模型不能增删、跳过或重排阶段。PathRun 洪水、trace 投影、ContrastLedger 和验证状态门禁属于确定性服务端逻辑，不是额外 AI 角色。

六角色仍是研判与报告职责，不再承担基础召回。目标确定性发现闭环为：

```text
Artifact Universe
  → Security IR / Evidence Graph
  → Dataflow / Guard / State / Typestate / Config / Dependency / Concurrency Detectors
  → Hypothesis Pool
  → 服务端实验规划
  → PathRun / Runtime Observation
  → 请求级投影与差分
  → 受影响子图重算、假设修订或证伪
```

AI 只能查询受控代码切片和 Evidence Graph、提出结构化假设与实验，不能补写 FACT、注册权限或直接升级状态。

工程迁移采用小步兼容：先固化 schema/consumer contract 和依赖方向，再在当前工程内抽出 contracts/domain/application/adapter 端口，随后迁移 JVM producer，最后接第二语言。不得为新语言复制流水线、存储、权限或 GUI，也不得在 Control Plane 进程内堆入所有语言工具链。

### 3.1 角色契约

- `PRE_ANALYSIS`：解释静态入口、依赖和 sink；补充候选只能标 `MODEL_SUPPLEMENT`。
- `AUTH_ANALYSIS`：必须使用 `code_query` 阅读真实鉴权实现，按“查代码 → 草拟 PoC → 补证 → 修订”有界多轮执行；鉴权面存在时目标不少于 3 个结构不同候选或逐条不可行证据。
- `DYNAMIC_VERIFICATION`：在服务端固定策略下用 `sandbox_probe` 验证 AUTH PoC。
- `PATH_EXPLORATION`：允许为明确 coverage gap 调用 `sandbox_probe`，新事实必须回写 PathRun。
- `VULNERABILITY_TRIAGE`：允许用 `sandbox_probe` 复现或证伪；只消费成功投影的证据，输出结构化 root cause。
- `REPORT_GENERATION`：汇总证据边界、路径、对照账本、限制和修复建议，不提升验证状态。

提示词可按项目编辑中英文版本，但自定义文本不能改变工具白名单、安全策略、预算或验证等级。

## 4. 当前实现基线

| 范围 | 当前能力 | 诚实边界 |
|------|----------|----------|
| 制品 | JAR/WAR/CLASS 有界读取；浏览器分块上传后进入内容寻址目录 | 动态主路径仅 Spring Boot 可执行 JAR |
| 静态分析 | Spring MVC/鉴权注解、调用边、TaintPath、sink、TaintGraph/coverage 脚手架 | 反射、代理、JNI、制品外 classpath 和完整别名分析不保证 |
| 控制面 | Loopback REST/SSE、SQLite V001-V024、本地 PAT、Provider/角色/AI Job、Hypothesis/Coverage/Evidence Graph 查询端口；StaticFactSnapshot schemaVersion=4（Universe + 权威 Evidence Graph wire） | 单节点语义，不是分布式 exactly-once 或企业多租户；`VERIFIED` 与生产 session/SSO 仍关闭 |
| 动态执行 | JVM Agent、loopback HTTP、JDBC/Redis/MySQL 有界替身、PathRun | `TRUSTED_DOCKER` 仅受信开发调试 |
| AI | OpenAI Chat/Anthropic Messages 有界工具循环、六角色、双语提示快照 | Provider 生产互操作、成本与流式协议未验收 |
| 结果 | PathRun、ContrastLedger、finding、Hypothesis、Coverage、Markdown report、VERIFIED 脚手架 | 常用最高 `DYNAMIC_SUSPECTED`；SQL H3 可 `DYNAMIC_CONFIRMED`（fixture）；`VERIFIED` 关闭 |
| GUI | React/TypeScript/Vite，真实 API 与显式 Demo 模式 | 浏览器 token 仅适合本地调试；无生产会话/SSO |

数据库迁移已注册至 **V024**。已应用迁移文件不可改写，schema 变化只能追加新迁移。

2026-07-29 实战复核：当前代码审计的产品可用性不能按 fixture gate 乐观外推。静态 sink/effect 与字节码事实仍是 MVP 最可靠的主召回层；动态沙箱、PathRun 驱动研判、非污点 detector 和 AI 多轮闭环在真实 JAR 上仍为 `PARTIAL`。动态失败、`UNKNOWN/-1/MOCK` 和空投影不得进入疑似漏洞主列表。后续 MVP 开发按 [MVP_BACKLOG.md](docs/MVP_BACKLOG.md) P0-15 到 P0-20 优先补实战召回基线、静态优先排序、动态启动诊断、实验计划编译、RuntimeObservation 对齐和报告降噪。

## 5. 当前风险与审计基线

2026-07-28 根复核：官方 `AcceptanceTestRunner` curated gate 已通过；执行数、断言数和跳过项以每次运行日志为准，不在全局记忆复制。P0/P1 只在各 Backlog 条目的声明范围内标为 `AUDITED`；[ADR-0002](docs/adr/0002-jvm-static-analysis-kernel.md) 已 `ACCEPTED`（轻量 kernel + 自研加深）。gVisor/Kata、`VERIFIED`、生产 SSO 仍为 `SCAFFOLDING`。唯一实现状态来源见 [MVP_BACKLOG.md](docs/MVP_BACKLOG.md)。

残余重点（声明范围外）：

1. 外网真实 Provider（需 `VEYRION_LIVE_PROVIDER=1`）与流式/限流/计费未验收；live Agent PathRun 仍可能缺 `correlationId`。
2. 完整 SSA/IFDS/别名、Boot 二层以上展开、P2 深度状态/并发求解未做（进程外引擎须新 ADR）。
3. `VERIFIED` / gVisor·Kata / 生产 SSO **明确延后**，骨架仅 fail-closed。
4. Provider 的 ArtifactNodes、MethodSummary、DynamicProbe 输出已有 SPI 与 OutputGate，但尚未全部进入主扫描投影；不得宣称九类 Provider 已完整消费。
5. 完整 DTO codegen、`ControlPlaneServer` 大拆分仍不足。

不得把 fixture/`TRUSTED_DOCKER` live 说成恶意制品隔离或生产可用。

## 6. 近期实施顺序

1. 手工验收 GUI/API 主路径（本机 `Start-Veyrion.ps1 -WithDockerRuntime`）。
2. 按 §8 继续加深召回与工程拆分；不开放 gVisor/SSO/`VERIFIED`。
3. 在动态沙箱完成实战启动诊断、可执行实验计划和 PathRun→hypothesis 闭环前，不把动态作为主发现引擎；动态只用于补证、证伪和复现。
4. 仅在产品范围升级且新 ADR 接受后，再启动强化沙箱、进程外重型引擎或生产会话栈。

## 7. 文档职责

| 文档 | 唯一职责 |
|------|----------|
| [README](README.md) | 安装、启动、开发入口和能力摘要 |
| [PRD](docs/PRD.md) | 产品目标、用户流程、功能与验收契约 |
| [TECHNICAL_ARCHITECTURE](docs/TECHNICAL_ARCHITECTURE.md) | 组件、数据、安全、持久化和执行架构 |
| [AUDIT_FLOW](docs/AUDIT_FLOW.md) | 阶段状态机、角色职责和当前流程缺陷 |
| [PATH_EXPERIMENT_MODEL](docs/PATH_EXPERIMENT_MODEL.md) | PathRun、身份轨、探针、SQL 与状态门禁 |
| [MVP_BACKLOG](docs/MVP_BACKLOG.md) | 当前能力等级、未完成工作和优先级 |
| [GUI_DESIGN](docs/GUI_DESIGN.md) | 页面、交互、状态展示与前端安全 |
| [EXTENSIBLE_ANALYSIS](docs/EXTENSIBLE_ANALYSIS.md) | Artifact / Language / Framework / Analysis / Runtime 扩展契约 |
| [DEVELOPMENT_PLAYBOOK](docs/DEVELOPMENT_PLAYBOOK.md) | 技术路线、模块边界、实施门禁与 Definition of Done |
| [AI_TASK_TEMPLATE](docs/AI_TASK_TEMPLATE.md) | 可直接交给实施 AI 的有界任务包 |
| [ADR](docs/adr/README.md) | 跨模块长期架构决定 |
| [frontend/README](frontend/README.md) | 前端开发和环境变量 |

文档冲突时按“领域专属文档优先”处理；状态判断始终以 Backlog 和实际审计为准。实现过程、一次性测试日志和过期迁移草稿不写入本文件，Git 历史承担归档。

## 8. 协作与审计规则

1. 开始任何实现、审计或文档变更前先读本文件。
2. 根 Agent 负责产品/架构决策、任务拆分、集成和最终审计。
3. 子 Agent 只处理明确分配的文件/任务，并报告假设、改动、验证和限制。
4. 可安全拆分且文件边界明确的任务默认并行；共享文件由根 Agent 统一修改。
5. 未经审计的能力只能标为实验性或待验证，不能标“已完成”“已验证”或“生产可用”。
6. 被测制品、模型输出和前端输入不得改变工具权限、沙箱策略或授权范围。
7. 重要稳定决策更新本文件；实现状态更新 Backlog；架构细节更新对应领域文档。
8. 实现任务先形成 Task ID、允许路径、禁止项、验收和测试；架构触发项必须引用已接受 ADR。提示词不能替代 schema、测试和服务端门禁。

## 9. 稳定决策摘要

- **2026-07-24**：确立代码逻辑优先、证据分层、JAR 优先和根 Agent 最终审计。
- **2026-07-25**：GUI 与 Java Control Plane 分离；React/Vite 作为唯一前端；动态能力必须服务端授权。
- **2026-07-26**：产品收敛为个人本地路径调试；确立六角色、PathRun、身份轨、AUTH PoC 交接和 `TRUSTED_DOCKER` 边界。
- **2026-07-27**：确立 ContrastLedger 不新增第七角色、适配器泛化、`VERIFIED` fail-closed；要求 AUTH 查代码与多 PoC，PATH/TRIAGE 可在服务端闸门下做定向动态验证。
- **2026-07-27**：代码审计核心调整为 Security IR / Evidence Graph 与多检测器假设闭环；source/sink 不再是唯一漏洞模型，六角色降为受控研判层，覆盖能力必须可量化且显式暴露 unknown。
- **2026-07-27**：保留 Java Control Plane 与 React GUI；多语言采用进程外 LanguageAnalyzer、独立 RuntimeAdapter 和中立合同，配套作用域 Agent 指令、任务包、ADR 与确定性 CI/架构门禁防止 AI 实施偏离。
- **2026-07-29**：实战召回复核后，MVP 路线调整为静态事实和 sink/effect 主召回、动态沙箱补证/证伪；动态路径和 AI 研判在 P0-15 到 P0-20 闭合前不得宣称基本可用。
- **2026-07-29**：动态沙箱目标改为“失败前路径完整记录”的动态路径调试器：TracePlan + World Pack + 三轨 Posture + Docker-only 强达 + Sensor Agent + PathTrace；禁止继续把 Agent Bypass Zoo 当主路线。
- **2026-07-29**：ADR-0004 `ACCEPTED`；digest-pinned runtime 含 Sensor Agent；授权 Boot fixture 三轨 PathTrace live 验收通过。P0-21 声明范围 `AUDITED`，OSS 实战 JAR 全链路召回仍不在范围内。

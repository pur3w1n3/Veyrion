# Veyrion 开发与 AI 实施手册

> 本文是工程实施的统一手册，回答技术选型、模块边界、跨语言扩展、任务执行、测试和审计问题。稳定产品决策见 [PROJECT_MEMORY](../PROJECT_MEMORY.md)，产品验收见 [PRD](PRD.md)，实现状态见 [MVP Backlog](MVP_BACKLOG.md)。本手册不能扩大工具、沙箱或授权范围。

## 1. 为什么不是只靠提示词

防止 AI 把实现写偏需要分层约束，优先级从高到低为：

1. **服务端和沙箱硬门禁**：权限、网络、命令、挂载、预算和验证状态必须由代码与测试强制执行。
2. **版本化合同**：JSON Schema、API、Worker、Security IR、事件和迁移合同决定组件能交换什么。
3. **架构与回归门禁**：依赖方向、兼容性、fixture、coverage 和安全测试阻止错误实现合入。
4. **作用域 Agent 指令**：根目录及子目录 `AGENTS.md` 约束某类文件允许做什么。
5. **任务包**：每次实施明确目标、允许路径、禁止项、验收、测试和文档影响。
6. **提示词**：负责让模型按上述材料工作，不能替代任何确定性门禁。

因此不维护一份包罗所有细节的巨型全局记忆，也不依赖一段“万能提示词”。详细规则进入领域文档，`PROJECT_MEMORY.md` 只保留稳定决策，任务上下文使用 [AI 任务包模板](AI_TASK_TEMPLATE.md) 按需组装。

## 2. 当前技术路线判断

| 领域 | 当前路线 | 判断 | 保留条件 | 需要演进的边界 |
|------|----------|------|----------|----------------|
| GUI | React 19 + TypeScript + Vite | 适合继续使用 | 只消费版本化 API，运行时校验响应 | 拆分巨型 `api.ts`，由合同生成/校验类型，页面不感知语言或框架特例 |
| Control Plane | Java 17 + JDK `HttpServer` + Jackson | 适合本地 MVP，不需为多语言重写 | 作为编排、授权、证据和投影中心 | HTTP、应用服务、领域合同、持久化和分析实现逐步解耦 |
| Persistence | SQLite + 追加迁移 | 适合个人单节点版 | 只经 repository/port 访问，迁移只追加 | 多用户或多节点成为明确需求后再引入 PostgreSQL/对象存储 |
| JVM 静态分析 | ASM 有界解析 | 适合作为 JVM 快速索引和 fallback | 输出中立 IR、coverage 和 stop reason | 成熟 CFG/SSA/points-to 引擎通过 Analyzer 合同接入 |
| JVM 动态分析 | Java Agent + Docker Worker | 适合 JVM 垂直切片 | 能力和运行计划由服务端固定 | 每种运行时独立 Runtime Adapter，不把 JVM Agent 事件当通用协议 |
| 组件通信 | REST/SSE + JSON/JSONL schema | 适合本地和早期多进程 | schema version、作用域、幂等、终态明确 | 大图使用分块/流式清单；达到吞吐触发条件后才评估 gRPC/Protobuf |

结论：前后端框架不是未来多语言的主要障碍。主要障碍是当前公共 DTO、控制面编排、静态分析对象和动态探针仍带有 JAR、Spring、HTTP、sink/taint 和 JVM Agent 假设。迁移目标是稳定控制面，不是改写控制面。

### 2.1 暂不更换的技术

- 不因“未来可能多语言”把 Java Control Plane 改写为 Node、Go 或 Rust。
- 不因 `HttpServer` 简单就立即引入 Spring Boot；先抽离 transport port，是否更换 HTTP 框架由生产需求触发。
- 不因未来可能分布式而立即替换 SQLite、引入消息队列或工作流引擎。
- 不在 Control Plane 进程内嵌入多个语言运行时、任意插件代码或不可信解析器。
- 不让前端为 Spring、Servlet、Python Flask 等框架各写一套页面和判断分支。

### 2.2 触发重新选型的条件

只有满足可观测条件才启动选型 ADR：

| 触发条件 | 可评估变化 |
|----------|------------|
| 需要远程访问、生产会话、标准中间件和高并发 HTTP | Java HTTP 框架或独立网关 |
| 多用户并发写、远程部署、HA 或超出 SQLite 单写者预算 | PostgreSQL 与对象存储 |
| IR/trace 流量使 JSON 编解码或传输成为已测瓶颈 | Protobuf/gRPC 或列式批传输 |
| 任务跨节点、租约/重试吞吐超过单节点状态机 | 专用队列或工作流引擎 |
| 桌面安装、自动更新和系统集成成为发布目标 | `jlink/jpackage`，必要时单独评估 Tauri |

“更现代”“以后可能需要”或 AI 偏好不是选型依据。

## 3. 多语言、多框架目标架构

```text
React/TypeScript GUI
        |
Versioned REST/SSE API
        |
Java Control Plane
  | authorization / orchestration / policy / evidence / projection
  |
  +-- Analyzer Protocol ------------------------------+
  |                                                   |
  |      JVM Analyzer      JS/TS Analyzer      Other Analyzer
  |      ASM + engine      parser + engine     parser + engine
  |             \              |              /
  |              +---- Security IR fragments -+
  |
  +-- Runtime Protocol -------------------------------+
         JVM Runtime       Node Runtime        Other Runtime
         Java Agent        runtime hook        runtime hook
                \              |              /
                 +-- RuntimeObservation/PathRun
```

### 3.1 五条正交扩展轴

1. `ArtifactPackager`：识别、展开和归一化归档、源码包、镜像层、配置与依赖。
2. `LanguageAnalyzer`：把某语言的语法、符号、调用、控制流、数据流和位置降为 Security IR。
3. `FrameworkAdapter`：组合某框架的入口、Guard、Effect、Sanitizer、Summary 和运行映射 Provider。
4. `AnalysisPack`：组合与语言无关或声明适用范围的 detector、假设、实验形状和报告映射。
5. `RuntimeAdapter`：在授权沙箱中启动特定运行时并把观测归一化为 RuntimeObservation。

这五条轴不可互相替代。识别 ZIP 不等于理解 Java，理解 Java 不等于识别 Spring，识别 Spring 不等于检测 IDOR，能启动 JVM 也不等于能安全启动 Node。

### 3.2 进程和信任边界

- Control Plane 只运行可信编排代码，不加载被测类，不执行第三方分析插件。
- Language Analyzer 默认进程外运行；输入是内容寻址制品引用、策略摘要和预算，输出是版本化 IR 分片、诊断和 coverage gap。
- Runtime Adapter 只能经 Worker 能力清单和服务器生成的 Run Profile 工作；Analyzer 不能获得动态执行权限。
- FrameworkAdapter 和 AnalysisPack 若为数据/声明可在受信注册表加载；若包含代码，按 Analyzer 插件处理并隔离。
- 任何扩展只能贡献事实候选、摘要、检测器或实验形状，不能直接写 Finding、修改授权或提升验证状态。

### 3.3 中立核心合同

公共合同不得强制出现 Java/Spring/HTTP/source-sink 专属字段：

| 合同 | 必需中立字段 | 专属信息放置方式 |
|------|--------------|------------------|
| Artifact | digest、mediaType、size、scope、components、coverage | `packagingKind` 和 namespaced extension |
| ProgramNode | stableId、language、kind、symbol、location、provenance | `extensions.jvm.*`、`extensions.typescript.*` |
| EntrySurface | protocol、operation、address、inputs、guards | HTTP route、topic、CLI argv 等作为协议属性 |
| SecurityHypothesis | family、securityProperty、subjects、evidence、gaps、detector | dataflow 才需要 origin/effect path |
| RuntimeObservation | runtime、eventKind、correlation、subjects、payload summary | JVM class/method、Node module 等放 extension |
| CoverageGap | scope、reason、producer、budget、suggested capability | 不能用空数组或“扫描成功”掩盖 |

核心枚举必须提供版本化扩展策略；未知 kind 要能保存、查询和展示，而不是反序列化失败。namespaced extension 不能参与授权、状态提升或跨语言通用判断，除非先经明确 Provider 转为中立事实。

### 3.4 Analyzer 协议

第一阶段继续使用 JSON Schema + JSONL/分块清单，至少包含：

- `analyzerId/version`、支持的 language/mediaType/schema 范围和能力清单；
- artifact digest、scan、policy digest、预算、请求的 analysis kinds；
- IR chunk manifest、每块摘要、顺序、压缩类型和总预算；
- diagnostics、unresolved facts、coverage gaps、stop reason 和资源使用；
- 确定的成功、失败、取消、超时、协议不兼容终态；
- 相同输入/版本/策略下可比较的 deterministic fingerprint。

Control Plane 只接受兼容 schema、同作用域、摘要正确且预算内的输出。输出先进入隔离暂存区，完整校验后原子发布；部分失败不能伪装成完整图。

### 3.5 Runtime 协议

RuntimeAdapter 描述 capability，不接收模型给出的任意命令。服务端根据已注册模板产生运行计划，至少绑定：

- runtime kind/version、artifact digest、entry/sequence 和 identity track；
- 镜像/运行时摘要、固定命令模板、只读挂载、UID、network mode 和资源预算；
- probe/experiment/stage attempt 身份与 correlation strategy；
- 允许的 observation kinds、trace budget、完整性摘要和 stop reason；
- release attestation 与允许的最高验证状态。

JVM Agent、Node hook 或其他运行时 hook 只负责观测，不是授权边界或不可篡改证据源。

## 4. 目标代码和模块边界

迁移可以先在同一仓库、同一 Java 进程内建立端口，再按压力拆进程。禁止大爆炸重写。

| 目标边界 | 职责 | 禁止依赖 |
|----------|------|----------|
| `contracts` | API、事件、IR、Worker/Analyzer schema 与兼容规则 | HTTP server、SQLite、ASM、React |
| `domain` | hypothesis、evidence、coverage、状态机和策略 | transport、数据库实现、具体语言解析器 |
| `application` | 用例编排、事务、幂等、授权调用 | HTTP DTO 拼装、SQL、ASM |
| `adapters/http` | REST/SSE 解析、认证入口、schema 映射 | 分析算法、直接 SQL |
| `adapters/persistence` | repository 与迁移实现 | HTTP、GUI、分析器实现 |
| `orchestration` | pipeline、job/task/attempt、终态和恢复 | 语言/框架特例 |
| `analyzers/*` | 语言语义到中立 IR | Control Plane 内部数据库与授权状态 |
| `runtimes/*` | 沙箱运行和观测 | AI prompt、Finding 状态提升 |
| `frontend` | capability-driven 审阅和操作 | SQLite、制品解析、验证决策 |

当前 `ControlPlaneServer`、`ApiDtos`、`ControlPlaneStore` 和前端 `api.ts` 存在集中耦合。迁移规则是先加端口与兼容测试，再移动逻辑；不得在一次功能任务中顺便全量拆分。

### 4.1 依赖方向

```text
frontend -> public contracts
http/persistence adapters -> application -> domain -> contracts
orchestration -> application/domain/contracts
language analyzers -> analyzer contracts + Security IR contracts
runtime workers -> runtime contracts
```

Control Plane 可以调用 Analyzer/Runtime port，但 domain 不得反向依赖具体 JVM、Spring、Docker、SQLite 或 React 类型。

### 4.2 前端规则

- API 类型、解析器和 mock 必须来自同一 schema 版本或有契约一致性测试。
- 页面按 `family`、`securityProperty`、`entry.protocol`、capability 和 extension renderer 展示，不按具体语言/框架写主流程分支。
- 语言特有详情使用可选 renderer；未知 extension 仍显示通用 evidence、coverage 和原始受限属性。
- SSE 只触发刷新，GET 是最终状态事实源。
- 前端不能推导或提升验证状态，不能产生 Worker 命令、网络策略或工具 allowlist。

## 5. 变更分类与决策门禁

### 5.1 普通实现变更

满足以下全部条件可直接按 Backlog 实施：

- 不改变公共 schema、权限、验证状态、迁移语义、阶段顺序或扩展轴；
- 只在已有端口内补齐行为；
- 有明确 fixture、断言和允许修改路径；
- 不新增基础设施、语言运行时或核心依赖。

### 5.2 架构变更

出现任一项必须先新增或修订 ADR：

- 新增/替换前后端框架、数据库、队列、RPC 或静态分析引擎；
- 改变 API/IR/Worker/Analyzer schema 的兼容策略；
- 新增语言、运行时、插件执行方式或信任边界；
- 改变六角色顺序、工具权限、动态网络、验证门禁或 evidence provenance；
- 让当前单节点语义升级为远程、多用户或分布式语义；
- 引入跨模块反向依赖或绕过既有端口。

ADR 必须写 Context、Decision、Alternatives、Consequences、Security、Migration、Compatibility、Validation 和 Status。普通 AI 实施任务不得顺便接受自己的架构提案。

## 6. AI 任务执行协议

每次实现使用 [AI 任务包模板](AI_TASK_TEMPLATE.md)，按以下状态推进：

1. `DISCOVER`：阅读根/作用域 `AGENTS.md`、PROJECT_MEMORY、任务引用和相关领域文档；检查工作区与现有实现。
2. `CONTRACT`：复述当前行为、目标行为、允许路径、禁止项、风险和验收；发现架构触发项则先停在 ADR。
3. `BASELINE`：运行最小相关测试或说明为何不能运行；确认失败能复现且不是已有无关变更。
4. `IMPLEMENT`：按最小垂直切片修改；先合同/领域，再适配器/投影，最后 UI；不做无关重构。
5. `VERIFY`：执行单元、契约、集成、安全和回归测试；记录实际执行数量，零测试不算通过。
6. `DIFF_AUDIT`：核对文件范围、依赖方向、迁移、schema、权限、日志/隐私、current/target 文档表述。
7. `REPORT`：报告文件、行为、测试、假设、未完成项和残余风险；未经证据不得称已验证或生产可用。

### 6.1 强制停止条件

AI 遇到以下情况不得猜测后继续写：

- 任务要求与 AGENTS、安全边界或已接受 ADR 冲突；
- 需要扩大网络、命令、挂载、宿主文件、凭据或模型工具权限；
- 需要改已应用迁移、删除证据、覆盖历史 attempt 或提升验证状态；
- 目标 schema 没有兼容/迁移策略；
- 允许路径不足以完成任务且扩展范围会触及其他所有者修改；
- 测试无法区分目标行为与已有错误，或 fixture 未授权动态执行。

停止时输出阻断证据和最小决策问题，不以临时 fallback 绕过。

## 7. 测试与发布门禁

| 变更类型 | 最低测试 |
|----------|----------|
| Domain/状态机 | 单元 + 状态转换/非法转换 + 重试/幂等 |
| API/schema | schema compatibility + consumer contract + malformed/unknown field |
| Persistence | 新迁移 + 空库/旧库升级 + 重启 + checksum；禁止改旧迁移 |
| Analyzer | positive/near-negative/mutation/holdout + coverage/stop reason + deterministic fingerprint |
| FrameworkAdapter | 入口/guard/effect 正负 fixture + 未命中保留 unknown |
| Detector | recall/precision 基线 + 反证 + budget truncation |
| Runtime/Sandbox | policy denial + timeout/cancel + trace integrity + 无宿主 fallback |
| AI tool/role | allowlist/schema/scope/budget + prompt injection + evidence refs |
| Frontend | schema parser + loading/empty/error/unknown + narrow viewport + status semantics |

合并门禁最终应由 CI 执行：

- 编译、真实非零测试、格式和 Markdown 链接；
- JSON Schema/生成类型漂移检查；
- 架构依赖与禁止 import 检查；
- 数据库迁移 checksum 和升级矩阵；
- 安全策略、验证状态和 prompt injection 回归；
- detector/adapter coverage 基线与性能预算；
- 任务包声明路径与实际 diff 对照。

本地可执行门禁入口见 `scripts/ci-gates.ps1`（AcceptanceTestRunner、schema/architecture/migration checksum、docs 链接、`git diff --check`）。完整目标门禁仍以 Backlog P0-14 为准；手册不能把未审计项描述为当前能力。

## 8. Definition of Done

任务只有同时满足以下条件才能标完成：

- 目标行为在允许范围内实现，未夹带架构改写和无关重构；
- public contract、schemaVersion、兼容读取和迁移策略完整；
- provenance、scope、attempt、budget、stop reason 和 evidence refs 未丢失；
- 安全拒绝路径有测试，失败不回退到更高权限路径；
- 相关测试真实执行且非零，新增风险有正负/异常断言；
- GUI/API/report 对 current、target、unknown 和验证状态表达一致；
- Backlog 状态只依据审计证据更新；稳定决策才进入 PROJECT_MEMORY；
- 最终报告列出残余风险和未覆盖范围。

## 9. 常见写偏模式

- 在 Control Plane 增加 `if language == ...` 或 `if framework == ...` 主流程分支，而不是调用 Provider/Analyzer port。
- 为新漏洞族复用 sink DTO 并填 `sink-none`、伪 entry 或空路径。
- 在前端重新实现服务端权限、验证或风险判定。
- 为完成动态任务接受模型提供的 shell、镜像、URL、挂载或网络策略。
- 只新增接口/schema/类名就把 Backlog 标为 `AUDITED`。
- 用规则数量、扫描成功或 AI 报告数量代替 recall/precision/coverage。
- 修改已应用 SQL，或为兼容问题直接清空数据库。
- 新增语言时复制整条控制面流水线、数据库表和 GUI 页面。
- 在 `PROJECT_MEMORY.md` 记录实现流水账、测试输出或大段提示词。
- 先做大规模模块拆分，再补合同和兼容回归。

## 10. 文档维护

- 产品行为变化更新 PRD；组件/协议/信任边界更新技术架构；执行阶段更新 AUDIT_FLOW。
- IR/Provider/语言框架扩展更新 EXTENSIBLE_ANALYSIS；动态证据更新 PATH_EXPERIMENT_MODEL。
- 实现状态和验收证据只更新 MVP_BACKLOG；稳定决策摘要才进入 PROJECT_MEMORY。
- 架构取舍写 ADR；AI 的一次任务输入不写入长期文档。
- 本手册只维护通用开发规则。任何具体任务的允许文件和验收条件写在任务包中。


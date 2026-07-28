# 溯脉 · Veyrion

Veyrion 是面向已授权闭源 JVM 制品的本地安全分析与路径验证工具。它把静态事实、受控动态实验、AI 辅助研判和可追溯证据组织成固定审计流程。

当前范围是个人本地版，优先支持 Spring Boot 可执行 JAR。Java package `com.aq.jvmsentinel`、Maven artifactId `jvm-security-verifier` 和 API 前缀 `/api/v1` 保持兼容。项目不承诺任意语言、完整多租户、企业 SSO、100% 路径覆盖或生产攻击能力。

## 快速开始

环境要求：Java 17+、Maven、Node.js/npm。Docker Desktop 仅在显式启用 `TRUSTED_DOCKER` 动态调试时需要。

```powershell
.\Start-Veyrion.ps1
```

默认 GUI 为 `http://127.0.0.1:5173`，Control Plane 为 `http://127.0.0.1:18080/api/v1`，状态保存在 `samples/.veyrion/control-plane.db`。脚本会初始化工作目录、编译 Java、恢复 SQLite，并启动两个 loopback 服务。可通过 `-Artifacts`、`-BackendPort`、`-FrontendPort` 和 `-JavaHome` 覆盖默认值；制品目录必须位于工作区内。

显式启用本地 Docker 动态调试：

```powershell
.\Start-Veyrion.ps1 -WithDockerRuntime
```

该模式只面向用户信任、由后端管理并重新校验摘要的内部 JAR，不是恶意制品的强化隔离环境。

## 构建与检查

```powershell
mvn '-Dmaven.repo.local=.m2' test
```

`mvn test` / `mvn -q test` 经 Surefire **仅**执行 `AcceptanceTestGate`，再调用 `AcceptanceTestRunner.runGate()` 遍历官方 curated `GATE_CLASSES`（不是仓库全部 acceptance 类，与直接 `java … AcceptanceTestRunner` 同一列表）。门禁 fail-closed：`executed==0`、`assertions==0`，或任一 main 失败，都会让 Surefire 失败（非零退出）。若某 acceptance 类“跑完但未记录断言”，也会记入 failures。离线完整门禁也可用：

```powershell
mvn -q '-Dmaven.repo.local=.m2' -DskipTests compile test-compile
# 或: mvn -q test
java -ea -cp $cp com.aq.jvmsentinel.AcceptanceTestRunner
```

公共 schema 字段常量可由 `scripts/generate-contract-types.ps1` 生成到 `frontend/src/generated/contracts.ts`；`SchemaContractAcceptanceTest` 校验其与 `contracts/schemas` required 集合一致。详情见 [MVP Backlog](docs/MVP_BACKLOG.md) §8.4 / P0-09。

```powershell
mvn -q '-Dmaven.repo.local=.m2' dependency:build-classpath '-Dmdep.outputFile=target/runtime-classpath.txt'
$cp = 'target/test-classes;target/classes;' + (Get-Content -Raw target/runtime-classpath.txt).Trim()
java -ea -cp $cp com.aq.jvmsentinel.ControlPlaneAcceptanceTest
```

前端单独运行：

```powershell
cd frontend
npm install
npm run dev
```

环境变量和浏览器安全边界见 [frontend/README.md](frontend/README.md)。

## CLI

CLI 只做有界静态读取；没有 `--authorize` 会拒绝运行：

```powershell
java -cp target/classes com.aq.jvmsentinel.cli.Main C:\path\to\sample.jar --authorize
```

输出包含制品摘要、入口、依赖、sink 和版本化事件摘要。JAR/WAR 在内存中有界读取，不解压到磁盘；单独 CLASS 标记为 `staticOnly=true`。注解、调用边和污点结果是静态事实或候选，不代表运行时可达或漏洞已验证。

## Control Plane

手工启动：

```powershell
java -cp "<runtime classpath>" com.aq.jvmsentinel.control.ControlPlaneMain --root C:\authorized-artifacts --port 18080 --token local-demo
```

| 目的 | API |
|------|-----|
| 健康与能力 | `GET /api/v1/health` |
| 项目、制品 | `/api/v1/projects`、`/api/v1/projects/{projectId}/artifacts` |
| 浏览器上传 | `/api/v1/projects/{projectId}/artifact-uploads` |
| 推荐审计入口 | `POST /api/v1/projects/{projectId}/audit-runs` |
| 扫描与证据 | `/api/v1/scans/{scanId}`、`paths`、`findings`、`evidence` |
| 实时通知 | `GET /api/v1/scans/{scanId}/events` |
| 动态任务 | `POST /api/v1/scans/{scanId}/dynamic-tasks` |
| Provider 与角色 | `/api/v1/providers`、`/api/v1/projects/{projectId}/role-assignments` |
| AI Job 与审计 | `/api/v1/projects/{projectId}/ai-jobs`、`/api/v1/ai-jobs/{jobId}/events` |

写操作需要 `X-Sentinel-Authorization` 或 Bearer token。扫描必须显式提交 `authorized:true`；组合审计还必须独立提交 `aiAuthorized:true`。调用认证不代替制品和 AI 授权。创建类操作应携带 `Idempotency-Key`；已覆盖的幂等记录保存在 SQLite 并跨重启复用。SSE 只用于增量通知，断线或终态后必须通过 GET 查询最终状态。

## 执行流程

固定流程如下，模型不能增删或重排阶段：

```text
静态扫描
  -> PRE_ANALYSIS
  -> AUTH_ANALYSIS
  -> 按身份轨动态观察
  -> AUTH_ANALYSIS 绕过确认
  -> DYNAMIC_VERIFICATION
  -> PATH_EXPLORATION
  -> VULNERABILITY_TRIAGE
  -> REPORT_GENERATION
```

角色、工具门禁和当前执行缺陷见 [AUDIT_FLOW](docs/AUDIT_FLOW.md)。PathRun、身份轨、探针和 SQL 状态门禁见 [PATH_EXPERIMENT_MODEL](docs/PATH_EXPERIMENT_MODEL.md)。

目标角色契约要求：

- `AUTH_ANALYSIS` 必须用 `code_query` 阅读实际鉴权代码，并在有界多轮中提出多个机制不同的 PoC 或给出不可行证据。
- `PATH_EXPLORATION` 可针对明确 coverage gap 调用服务端闸门后的 `sandbox_probe`。
- `VULNERABILITY_TRIAGE` 可用 `sandbox_probe` 复现或证伪候选，并保留结构化 root cause 与证据引用。

这些目标契约尚未全部实现，不能据此宣传为已验证能力。

目标代码审计内核不再只围绕固定 source/sink：Artifact Universe 进入 Security IR / Evidence Graph，由 dataflow、guard/ownership、state/sequence、typestate/API misuse、configuration/dependency 和 concurrency/resource detector 产生 `SecurityHypothesis`，再由服务端实验规划与 PathRun 反馈支持或证伪。详细设计见 [技术架构](docs/TECHNICAL_ARCHITECTURE.md)。

## 技术路线与多语言边界

当前 React/TypeScript/Vite GUI、Java 17 Control Plane 和 SQLite 适合个人本地 JVM 垂直切片，暂不为远景目标重写。多语言按 [ADR-0001](docs/adr/0001-polyglot-control-plane-and-workers.md) 演进：Control Plane 保持语言无关，新语言通过进程外 `LanguageAnalyzer` 输出 Security IR，新运行时通过独立 `RuntimeAdapter` 输出 RuntimeObservation；框架和漏洞族分别由 FrameworkAdapter/AnalysisPack 扩展。

公共 API、证据、Hypothesis 和 GUI 不得增加 JVM、Spring、HTTP 或 source/sink 必填假设。规模触发前不提前引入 PostgreSQL、队列、微服务或 gRPC。后续 AI 实施使用 [开发手册](docs/DEVELOPMENT_PLAYBOOK.md) 和 [任务包模板](docs/AI_TASK_TEMPLATE.md)，架构变化先写 [ADR](docs/adr/README.md)；提示词不能替代 schema、测试和服务端安全门禁。

## 数据与安全边界

- 浏览器上传使用分块摘要、完整 SHA-256、格式复核和内容寻址安装；旧路径登记只用于 Control Plane 可直接访问的本地兼容场景。
- SQLite 保存项目、扫描、证据、Provider、角色、AI Job/Event、Worker task/trace、上传会话、幂等记录和流水线元数据。迁移文件一旦应用不得修改，只能追加新版本。
- Provider 凭据由后端使用 AES-256-GCM 加密；响应不返回明文或密文。浏览器 token 仅适合 loopback 本地调试。
- 模型、制品文本和前端输入都按不可信数据处理，不能改变工具白名单、沙箱策略、网络、挂载、UID、预算或验证等级。
- 隐藏 chain-of-thought 不保存。Provider 显式返回的可见 `reasoning_content` / thinking 摘录当前可能经有界截断和脱敏后作为 `MODEL_THINKING` 事件保存；它不是证据，也不能作为工具授权依据。该留存策略在生产发布前仍需单独完成隐私审计。
- `TRUSTED_DOCKER` 固定断网、只读制品挂载和资源上限，但仍是普通 runc 开发后端。沙箱不可用时动态能力必须保持 disabled，绝不回退到宿主 Java 执行制品。

## 结果语义

| 状态 | 含义 |
|------|------|
| `STATIC_INFERRED` | 静态事实或分析表明可能可达 |
| `DYNAMIC_SUSPECTED` | 受控运行到达关键点，但闭环不足 |
| `DYNAMIC_CONFIRMED` | 满足服务端 H3 动态门禁；不等于生产实库证实 |
| `VERIFIED` | 强化隔离和可重放证据门禁通过；当前保持关闭 |
| `UNREACHED` | 受身份、预算、启动、超时或依赖限制未覆盖 |

模型、MOCK、规则生成或前端展示均不能单独升级状态。动态结论必须关联 PathRun；静态候选可以没有 PathRun，但必须保留静态证据和停止原因。

## 当前关键限制

- 流水线阶段 attempt、异步回调隔离、重试/取消和无 Worker 终态尚有 P0 缺口。
- 同一 AI Job 多个不同 probe 的身份与有效尝试门禁尚未完整实现。
- AUTH 强制代码审阅、多 PoC、多轮修订是目标契约，服务端门禁尚待补齐。
- 当前 source 主要限于 Spring MVC 参数、sink 依赖固定签名表，完整 BytecodeFactIndex 未持久化；FrameworkAdapter/AnalysisPack 还不能扩展核心检测器。
- 当前 `code_query` 不是通用方法/CFG/dataflow 查看工具，`PATH_EXPLORATION` 也尚未获得目标 `sandbox_probe` allowlist。
- 请求级 HTTP/Agent/JDBC 关联、TRIAGE root cause 保真和 ExperimentPlan 贯穿仍待修复。
- Control Plane/API/GUI 尚未完成语言中立解耦，Analyzer/Runtime 通用协议、schema drift 和架构依赖门禁尚未实现。
- 没有通过 gVisor/Kata 逃逸套件，`VERIFIED` 保持 fail-closed。
- 当前不是生产级多租户、SSO、会话、安全出站网关或分布式 exactly-once 系统。

当前状态和验收条件以 [MVP Backlog](docs/MVP_BACKLOG.md) 为准。

## 文档导航

| 文档 | 职责 |
|------|------|
| [PROJECT_MEMORY.md](PROJECT_MEMORY.md) | 稳定项目上下文和不可破坏决策 |
| [PRD](docs/PRD.md) | 产品目标、用户流程、功能与验收合同 |
| [技术架构](docs/TECHNICAL_ARCHITECTURE.md) | 当前组件、数据、安全、持久化与目标架构 |
| [审计流程](docs/AUDIT_FLOW.md) | 阶段状态机、角色提示词合同和执行缺陷 |
| [路径实验模型](docs/PATH_EXPERIMENT_MODEL.md) | PathRun、身份轨、probe、SQL 和状态门禁 |
| [MVP Backlog](docs/MVP_BACKLOG.md) | 已审计能力、缺口、优先级和验收要求 |
| [GUI 规范](docs/GUI_DESIGN.md) | 页面、交互、状态展示和前端安全 |
| [可扩展分析](docs/EXTENSIBLE_ANALYSIS.md) | ArtifactPackager、LanguageAnalyzer、FrameworkAdapter、AnalysisPack、RuntimeAdapter 扩展合同 |
| [开发与 AI 实施手册](docs/DEVELOPMENT_PLAYBOOK.md) | 技术选型、模块边界、实施流程和确定性防偏门禁 |
| [AI 任务包模板](docs/AI_TASK_TEMPLATE.md) | 可直接交给其他 AI 的任务合同与报告模板 |
| [ADR](docs/adr/README.md) | 已接受、提议和被替代的架构决定 |

实现历史和已完成迁移由 Git 保留，不再写入全局记忆或单独维护迁移流水账。

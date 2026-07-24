# 项目记忆（权威决策记录）

## 1. 项目使命

本项目要建设一个面向已获授权闭源 JVM 应用（JAR/WAR/CLASS）的 AI 安全验证平台。平台先理解业务和外部入口，再在隔离沙箱中尽可能深入执行代码逻辑，最后用有证据的数据流和攻击链帮助安全人员判断风险。

核心价值不是单点规则扫描，而是：

```text
入口发现 → 业务建模 → 依赖可观测化 → 路径探索 → 证据验证 → 全局攻击链推理
```

## 1.1 产品名称

- 正式产品名：**溯脉 · Veyrion**（英文：**Veyrion**）。
- 中文名强调沿数据脉络回溯闭源代码的入口、变换、依赖和 sink；英文名是本项目的定制品牌名。
- `com.aq.jvmsentinel` Java 包名、`jvm-security-verifier` Maven artifactId 和 `/api/v1` 路径属于兼容性标识，暂不随品牌更名。
- 商标、域名和正式公司名称尚未完成检索；在商业发布前必须补做名称可用性与法务审查。

## 2. 已确认的产品决策

### 2.1 代码逻辑优先

数据库、第三方服务、时间、随机数、缓存和消息系统等不可控依赖，不能因为连接失败就让路径探索提前结束。系统优先采用 Mock、快照、录制回放或影子环境继续执行代码逻辑。

替身执行不等于真实环境已验证。结果必须明确标注依赖模式，并报告真实流向，例如数据库库、表、字段、读写类型和查询摘要。

### 2.2 权限、租户和业务状态不跳过

如果路径需要管理员角色、特定租户或先前业务状态，平台仍应使用合成身份、状态种子或快照继续执行；报告中必须显示前置条件，不能把“需要权限”误报成“匿名可利用”。

### 2.3 路径覆盖的表达

不承诺数学意义上的“所有路径全部完成”。产品要报告入口发现率、方法/分支/sink/状态覆盖度、预算、停止原因和未覆盖区域。疑似不终止路径必须可控停止并可解释。

### 2.4 AI 的职责边界

静态分析和运行时观测提供事实，AI 负责代码/业务解释、输入规划、数据流归纳和跨入口关联。LLM 不能单独确认漏洞；“已验证”必须来自沙箱中可重放的证据。

### 2.5 安全边界

仅对用户明确授权的制品和范围运行。默认无外网、最小权限、无破坏性 payload、敏感信息脱敏和全量审计。AI 不能直接获得宿主机命令执行权限，只能调用 allowlist 工具。

## 3. 当前文档基线

- [产品需求文档](docs/PRD.md)
- [技术架构文档](docs/TECHNICAL_ARCHITECTURE.md)
- [MVP 任务拆解](docs/MVP_BACKLOG.md)
- [文档审计摘要](docs/DOC_AUDIT.md)
- [GUI 设计规范](docs/GUI_DESIGN.md)

这三份文档是产品方向和 MVP 范围的基线；若实现与文档冲突，先由根 Agent（决策者/审计者）裁定并更新文档或本文件。

## 4. 协作与审计规则

1. 根 Agent 是产品决策者、架构把关者和最终审计者。
2. 子 Agent 负责明确分配的实现任务，不得自行扩大范围或改变核心产品决策。
3. 子 Agent 完成任务时必须提供：改动文件、设计假设、测试命令、测试结果、已知限制和未完成项。
4. 根 Agent 必须审阅 diff、运行相关测试，并检查安全边界、数据契约和文档一致性后，才能接受功能。
5. 未通过审计的代码不得作为已完成能力对外宣称；可以保留为实验性分支/模块并明确标记。
6. 每次重要决策、范围变化、模型/依赖变化和审计结论都追加到本文件的变更记录。

本环境没有可选的 GPT-5.5 模型标识，已使用可用的 GPT-5.6-sol 实现 Agent；这不改变“子 Agent 实现、根 Agent 决策和审计”的协作规则。

## 5. 当前实施顺序

第一条垂直切片固定为：

```text
Spring Boot JAR/WAR
  → 制品登记与入口清单
  → 前置 AI 结构化建模（可先用可替换的规则/Stub）
  → 隔离运行画像
  → HTTP 单入口路径追踪
  → JDBC/文件依赖观测
  → 结构化证据与 GUI/API 展示
```

在这条链路可重放之前，不扩展到多语言、复杂分布式真实连接或自动破坏性利用。

## 6. 实现约束

- 所有跨模块消息必须有版本号和 JSON Schema/等价契约。
- 原始制品和轨迹不能未经脱敏直接发送给云端模型。
- 依赖替身的每个返回值都要标注来源：用户提供、录制回放、规则生成或模型推断。
- 生产制品必须进入内容寻址、只读存储；当前 M0 本地切片仅允许受控目录原文件并在分析前复核摘要。
- 结果状态至少区分：`STATIC_INFERRED`、`DYNAMIC_SUSPECTED`、`VERIFIED`、`UNREACHED`。
- 每个任务都必须有资源预算、超时、取消和恢复语义。

## 7. 变更记录

### 2026-07-24

- 建立项目记忆。
- 确认“代码逻辑优先 + 外部依赖可观测化”的产品原则。
- 确认根 Agent 负责决策和审计，子 Agent 负责受限实现。
- 确认首条垂直切片为 Spring Boot/JVM HTTP 路径验证闭环。
- 完成三份设计文档审计：补充威胁模型、提示注入防护、事实/推断/模拟分层、事件契约、启动失败降级、沙箱发布门槛和量化验收指标。
- 确认 GUI 与 Java 分离：React/TypeScript/Vite 负责现代 Web 交互，Java 17 负责 JVM 分析和控制面；后续可用 Tauri 包装桌面版，不维护 JavaFX/Swing 分支。
- 根 Agent 审计 M0/M1 切片并修正：制品路径/大小/归档条目边界、注册后变更校验、配置脱敏、元数据读取上限、JSON 控制字符转义、模型输入校验和事件作用域上下文；验收主类通过。
- 完成 GUI：`frontend/` 使用 React 19 + TypeScript + Vite 6.4，包含项目总览、入口地图、路径探索器和攻击链画布；Demo 仅在 `VITE_DEMO_MODE=true` 时启用，真实模式通过 `src/api.ts` 访问后端边界。
- GUI 审计：移除外部字体请求，增加演示数据标识、键盘入口选择、弹窗语义和响应式布局；Vite 依赖升级至 6.4.3，`npm audit --omit=dev` 和完整审计均无已知漏洞，生产构建通过。
- 增加 `AGENTS.md` 作为进入项目时读取本记忆的入口。
- 最终验证：Java 17 release 编译、Maven clean/test 和 `AcceptanceTest` 均通过；GUI `npm run build` 通过，完整 `npm audit --audit-level=high` 无已知漏洞。

## 8. 待决策事项

以下事项不阻塞第一条本地垂直切片，但在对外试用前必须确认：

1. 首版部署形态：本地单机、私有化服务，还是云端控制面；是否允许云端模型。
2. 安全验证 payload 分级和审批角色；默认只允许无害标记和模拟文件。
3. 基准样例规模、框架版本和真实（已授权、脱敏）制品样本。
4. 事件队列和图谱存储的首版选型；默认先使用数据库任务表与 PostgreSQL/JSONB 思路。

## 9. 下一步执行顺序

Control Plane API/SSE 和 GUI 真实 DTO 接入已完成一个受限 MVP slice，后续顺序调整为：

1. 根 Agent 审计受限 classfile/注解解析实现，并补充真实授权样本的 Spring MVC 入口召回基准。
2. 设计沙箱 Worker 合约（资源预算、网络/DNS deny-by-default、停止/恢复、不可变 trace），并先通过逃逸与越权测试。
3. 选择 PostgreSQL/JSONB 与对象存储持久化方案，加入项目/租户授权、证据访问审计和生产级限流。
4. 在证据契约稳定后接入 AI Gateway：只允许脱敏 DTO、工具白名单和人工复核，AI 不直接定性漏洞。

## 10. Control Plane API/SSE 切片（2026-07-24，根 Agent 审计记录）

- 已完成 Java 17 `ControlPlaneServer` 与 `ControlPlaneMain`：默认 `127.0.0.1`，`/api/v1` 版本化 REST，内存 MVP store。
- 已接通项目、JAR/WAR/CLASS 制品登记、入口、扫描、路径、发现、证据、攻击链和 dashboard DTO；所有响应带 `schemaVersion`、作用域字段、`verificationStatus`、`dependencyMode`、`evidenceRefs`（未扫描项目明确为 `UNREACHED`）。
- 扫描只调用安全的元数据读取与 `PreAnalysisService`，结果固定为 `STATIC_INFERRED`，依赖模式为 `MOCK`；不启动制品、不连接数据库/网络、不执行命令。
- 变更操作需要本地 token；扫描还必须显式 `authorized=true`。制品登记前后均复核 SHA-256/文件大小，路径继续受允许根目录、非符号链接和归档边界约束。
- SSE 已支持有界历史/客户端队列、心跳、`Last-Event-ID` 补发、平铺与嵌套作用域上下文，并在 `ScanCompleted`/`TaskStopped` 后结束有限流；前端以 GET 扫描状态作最终补偿。
- `frontend/src/api.ts` 已从 Mock 适配为真实 DTO/SSE 适配，`VITE_DEMO_MODE=true` 才启用 Demo；真实模式错误不会静默回退到 Mock。GUI 的入口、路径、发现和依赖模式展示改为消费 dashboard DTO。
- 已补充 `ControlPlaneAcceptanceTest`：授权拒绝、项目/制品/扫描幂等键、制品摘要、显式扫描授权（含幂等重放）、入口/路径/发现/证据路由、dashboard 和 SSE schema/replay。

当前未完成/不可宣称能力：

- 尚未实现真实字节码调用图、运行时入口发现、沙箱/JVM Agent、动态污点/路径洪水、数据库替身、LLM 子 Agent 或 VERIFIED 结论；受限 classfile 注解入口解析正在等待根 Agent 审计。
- store 是进程内非持久化实现，尚无企业身份、多租户隔离、对象存储和生产级限流；对外部署前必须补齐这些边界。
- 默认启动器只绑定 loopback；可注入的非 loopback 构造器仅供受控集成/测试使用，尚未提供生产级读权限、SSO/RBAC 和跨租户隔离。
- `POST /findings/{id}/replay` 明确返回 `STATIC_ONLY`，不能把静态推断伪装成动态验证。

## 11. 本轮同步（2026-07-24）

- 产品工作名从有冲突的候选名改为 **溯脉 · Veyrion**；这是品牌层变更，Java 包名、Maven artifactId、内部 service name 和 API 路径保持兼容。
- 根 Agent 审计并修正扫描幂等重放：即使复用已有 `Idempotency-Key`，请求仍必须显式提供 `authorized=true`；制品登记也支持按项目作用域的幂等重放。
- 幂等键存储增加每类 50,000 条上限，达到上限 fail-closed 返回 429，避免本地 API 因无限键值增长耗尽内存。
- README、PRD、技术架构、MVP backlog、GUI 规范和文档审计摘要已同步 Control Plane REST/SSE 的实际完成状态、静态分析边界、真实 GUI 配置和未完成能力。
- 验证结果：使用 IntelliJ JBR 21 按 Java 17 编译，`mvn -Dmaven.repo.local=.m2 test`、`AcceptanceTest`、`ControlPlaneAcceptanceTest` 均通过；在 `frontend/` 执行 `npm run build` 通过，`npm audit --audit-level=high` 为 0 vulnerabilities。系统默认 Maven 缓存下的 `mvn test` 仍可能因 Surefire 目录权限失败，属于环境问题。

当前未完成工作：扩大真实授权 Spring 制品的入口召回基准、真实 OpenSandbox 部署验收、持久化和租户授权，最后才接入受证据约束的 AI Gateway。

## 12. 受限 classfile 注解切片（2026-07-24，根 Agent 审计通过）

- 新增 Java 17、无第三方依赖的最小 classfile parser，只读取字节与 ZIP 条目，不解压、不加载、不初始化或执行被测类。
- 识别 Spring MVC controller/mapping、常见参数注解和 `PreAuthorize`/`Secured`/`RolesAllowed`；类/方法路径与 HTTP method 会形成静态入口，权限只保留为前置条件和 `PermissionMatrix`。
- classfile 中真实存在的注解证据标为 `FACT`，入口仍为 `STATIC_INFERRED`，不得据此宣称运行时路由存在、匿名可达、权限绕过或动态验证。
- 保留配置脱敏及类名 sink/dependency 辅助规则；Controller 类名入口规则只对无法获得有效注解元数据的类降级启用。
- 读取边界：单 class 4 MiB、class 总量 64 MiB、最多 20,000 个 class 与 100,000 个归档文件条目，并限制常量池、成员、属性、注解数量、数组数量、递归深度和展示值长度。超限受控拒绝，局部畸形 class 安全降级。
- 支持 `BOOT-INF/classes` 与 `WEB-INF/classes` 名称归一化。当前不解析自定义组合/元注解、继承/接口映射、运行时注册、完整 Spring 条件或调用图。
- 新增 `ClassfileAnnotationAcceptanceTest`，用 `JavaCompiler` 构建同名注解 fixture 后只读取产物；以 5 个预期 Spring MVC method/route 做精确集合基准，并覆盖参数、权限、无注解类不误报、畸形/超限 class、配置脱敏和辅助规则回归。
- 根 Agent 已逐文件审阅解析器、读取边界、服务接入、测试和文档，并使用 IntelliJ JBR 21 复验 `mvn -Dmaven.repo.local=.m2 test`、`AcceptanceTest`、`ClassfileAnnotationAcceptanceTest`、`ControlPlaneAcceptanceTest`，全部通过；IDE lint 无错误。
- 审计结论仅接受为“受限静态注解切片”。5/5 合成 fixture 不代表真实制品召回率，仍需按 Spring 版本、组合注解和授权样本扩大基准；不能标记为完整 M1 或生产可用。

## 13. OpenSandbox Worker 决策（2026-07-24）

- 动态执行采用 OpenSandbox 协议作为可插拔后端；Veyrion 控制任务授权、租约、资源预算、证据状态和不可变 trace，OpenSandbox 只提供生命周期与隔离执行面。
- 后端能力分为 `STATIC_ONLY`、`FIXTURE_RUNC`、`HARDENED_GVISOR`、`HARDENED_KATA`。普通 runc 只允许仓库内可信 fixture，不能运行用户导入的闭源制品。
- Windows 只作为 Control Plane/开发宿主，动态任务运行在 Linux Worker。强化运行时未通过 P0 网络/DNS、宿主路径、非 root、只读根、资源耗尽和逃逸测试前，health 必须保持 `DYNAMIC_DISABLED` 并 fail-closed。
- Worker 合约必须版本化并绑定项目、制品摘要、扫描和任务四元组；trace 采用带前序 SHA-256 的追加链。GUI token、Worker token 和 OpenSandbox API key 相互隔离。
- JVM Agent 是观测层而不是安全边界。首个动态切片只在受控 fixture 上产出 `DYNAMIC_SUSPECTED`；在强化沙箱和可重放证据完成前不得生成 `VERIFIED`。
- OpenSandbox 本地开发仍依赖 Docker；后续可替换为其他兼容后端，但不得静默降级到宿主 Java 子进程执行外部制品。

## 14. Worker、OpenSandbox 与 JVM Agent 实现审计（2026-07-24）

- 已完成版本化 Worker 任务、租约、检查点和 trace 合约，以及作用域绑定、幂等状态机、租约过期回收和带前序 SHA-256 的追加 trace 链。
- Control Plane 已接入独立 GUI/Worker token 的任务与 trace API，并强制 `ResourceBudget.maxTraceBytes`；本轮仍是进程内协调器，不代表持久化或多租户生产能力。
- OpenSandbox 适配器按 sandbox ID 从 lifecycle API 解析 44772 Execd 代理端点；运行时能力只接受部署运维方配置的 attestation，响应数据不能授予能力。适配器限制同源、端点路径和凭据头，拒绝网络放开、root、可写根目录及能力降级。
- 独立 `agent/` Maven 模块提供 Java 17 `premain`/`agentmain`、类加载观测和 HTTP/FILE/JDBC/PROCESS 显式探针，输出受目录授权、事件/字节预算、字段边界、控制字符清理和敏感键脱敏约束的 JSONL。
- JVM Agent 不是安全边界。类加载等 Agent 自有事件标为 `RUNTIME_OBSERVED`；显式探针可被应用调用，必须标为 `APPLICATION_REPORTED`。两者当前都只能是 `DYNAMIC_SUSPECTED`，不得生成 `VERIFIED`。
- 根 Agent 已逐文件审阅三个并行实现轨并修正显式探针证据来源；使用 JBR 21 复验根 Maven、六个 main-style 验收类、Agent Maven test/package 和真实 `-javaagent` 子进程，全部通过。
- Git 审计备份：`94d55fb`（OpenSandbox 适配器）、`1108a98`（Worker Control Plane API）、`41d36a9`（JVM Agent）。下一步只接通仓库内受控 fixture；普通 runc 仍禁止执行用户导入制品。

## 15. 受控 Spring Fixture 动态闭环（2026-07-24，根 Agent 审计通过）

- 已接通 public 动态任务排队、独立 Worker HTTP 客户端、execute-one 启动器、OpenSandbox 固定执行模板、Agent JSONL 转换、不可变 trace 链以及 dashboard/path/evidence 投影。
- Public 请求只接受 `authorized` 和 fixture ID；镜像 URI、main class、命令、路径、预算和能力由 Control Plane 白名单与内部任务快照决定。Worker token 不能创建 `FIXTURE_RUNC` 任务。
- `fixtures/http-entry/` 是 Spring Boot 4.1.0 一次性 fixture：启动 Spring context、直接调用真实 controller mapping 后退出；HTTP/JDBC/FILE/PROCESS 均为无害显式 intent，依赖操作标记 `executed=false`。
- 镜像默认使用 `registry.invalid`；运维方只能以 digest-pinned 环境配置覆盖。仓库提供显式 push 后读取真实 repository digest 的脚本，但本轮未运行 Docker、未发布镜像，也未完成真实 OpenSandbox 部署验收。
- runc fixture 要求 deny-all 网络、非 root、只读根、资源预算和 `writable-tmp-v1` attestation；Agent trace 统一写入 `/tmp/veyrion-trace`。任何能力缺失均 fail-closed。
- 动态证据仅为 `DYNAMIC_SUSPECTED`。Agent 自有事件保留 `RUNTIME_OBSERVED`，显式探针为 `APPLICATION_REPORTED`；trace 摘要不能把应用上报升级为 `VERIFIED`。
- 根 Agent 修正了 public 预算信任、Worker 任意 fixture 入队、清理后置、静态 GUI provenance、跨项目 evidence ID 和只读根写目录等边界；mock OpenSandbox 全链路、真实 `-javaagent` fixture 冒烟、Maven/GUI 回归均通过。
- 分阶段 Git 备份：`04d314f`、`a54fdb7`、`a39a88d`、`b76c155`、`7b6ef23`、`fb82aa3`、`c624e74`。这些提交证明受控切片可测试，不代表生产沙箱或外部制品动态执行可用。

## 16. 本地一键开发启动器（2026-07-24）

- 新增 `DevLauncherMain` 与根目录 `Start-Veyrion.ps1`：自动创建工作区内 `samples/`、生成进程内随机 mutation token、启动 loopback Control Plane、创建本地项目并以环境变量启动 Vite。
- 启动器只直接执行仓库前端的 `npm run dev`，不经过 shell，不执行导入制品，也不属于 Worker fallback；前端退出时后端随之关闭，JVM 关闭钩子负责清理子进程。
- 制品目录必须位于工作区内，前后端端口必须不同；实际冒烟已验证后端 health 与 Vite 首页均可访问。

## 17. 本地首版管理与分析闭环（2026-07-24，根 Agent 审计通过）

- 本地默认 Store 改为 SQLite/plain JDBC，使用 V001/V002 有序迁移和历史 checksum 校验；项目、制品元数据、扫描、证据、发现、攻击链、Provider、AI 角色绑定、阻断态 AI job、操作员 PAT 和审计事件可跨重启恢复。数据库与密钥路径必须留在授权根目录下。
- Provider API Key 只进入专用请求字段，使用后端文件根密钥与 AES-256-GCM 加密；AAD 绑定 workspace/provider/credential/version，数据库、响应、异常和审计不返回明文或密文。远程 Provider 只接受无 userinfo/query/fragment 的 HTTPS；LOCAL 只接受 loopback。真实 Provider 请求仍未启用。
- 操作员 PAT 只保存 SHA-256 hash，写操作按本地 RBAC 默认拒绝；Worker token/header 不能进入操作员权限域。当前仍是 loopback 单 workspace 首版，没有 SSO、HttpOnly session、多租户或生产读权限；为兼容 SSE，既有结果 GET 仍未全部要求操作员认证。
- AI 角色固定为 `PRE_ANALYSIS`、`PATH_EXPLORATION`、`VULNERABILITY_TRIAGE`、`REPORT_GENERATION`。创建 AI job 只生成四阶段数据流并固定 `BLOCKED / PROVIDER_EXECUTION_DISABLED`，不得伪造模型输出或生成 `VERIFIED`。
- classfile 事实层新增类层次、字段/方法、字段读写、`invoke*`、`invokedynamic`、直接/保守 CHA/未解析动态边；保留字节码 offset/ordinal 证据和事实预算。它不加载类、不展开完整 classpath、不做跨方法数据流，反编译器仍未进入 Control Plane 进程。
- GUI 改为默认亮色、可持久化暗色，并接通项目 CRUD、制品登记、扫描策略、执行时间线、结果、Provider、AI 四角色和 AI job。失败状态明确显示，不创建本地替代成功数据，也不把 API Key 写入 Web Storage。
- 根 Agent 修正持久化启动器的运行时 classpath、SQLite 接入、开发项目复用和 bootstrap token 跨重启轮换；活动管理员不能自我撤销或降权。真实 Chrome 已验证项目/设置 API 均为 200、默认亮色、主题持久化且无失败请求。
- 分阶段 Git 备份：`40e500f`（受限字节码事实索引）、`da644e4`（SQLite、安全管理与启动器）。

## 18. 最终打包决策（2026-07-24）

- 默认产物采用按平台构建的自包含 Desktop Core：`jlink + jpackage` 生成 Windows EXE/MSI、macOS DMG/PKG、Linux DEB/RPM/便携包。不存在可同时运行于三个操作系统的单一 EXE，CI 必须在对应 OS/架构构建和签名。
- React 生产产物应嵌入 Java 应用并由 loopback Control Plane 提供，安装后打开系统浏览器；最终用户不需要预装 Java、Node 或 Docker。当前 Vite 双进程启动器仅用于开发。
- Docker Compose 作为可选 Sandbox Pack，提供 Linux Worker/OpenSandbox 动态能力；缺少 Docker 时 Desktop Core 的静态审计和管理能力仍可用，动态能力保持 disabled，绝不回退到宿主 Java 进程执行外部制品。
- GraalVM Native Image 技术上可作为后续便携版 PoC，但在 SQLite JNI、Jackson DTO、反射资源和插件边界稳定前不作为首发唯一产物。

## 19. 本轮剩余边界

- 幂等窗口、SSE 历史、Worker 任务、租约和动态 trace 仍为内存状态；SQLite 是本地单节点，不是生产多租户数据库。
- 审计事件已持久化且脱敏，但尚无独立签名 checkpoint、禁止 UPDATE/DELETE 的数据库门禁或远端不可变归档。
- 真实 LLM、反编译隔离 Worker、完整调用图/污点、内容寻址对象存储、生产 SSO/session、真实 OpenSandbox 部署和用户制品强化沙箱仍未完成；这些能力不得在 UI 或文档中标记为已验证。

## 20. 外部 Spring Boot JAR 动态分析契约（2026-07-24，根 Agent 审计通过）

- 决策不是“Agent 或反编译”二选一：原始 classfile 是事实源，隔离反编译与 AI 只生成结构化输入/harness，最终裁决必须在强化沙箱中调用原始 digest-verified JAR。
- 新增外部制品执行器：只接受内部 task scope 与 artifact catalog，执行前复核文件身份/大小/ZIP signature/SHA-256；固定 Agent/JAR 路径、非 root UID/GID、deny-all 网络、只读制品、受控 tmpfs 和资源预算，无宿主执行 fallback。Sandbox 请求只发送 `sha256:` 内容引用，不发送宿主 `file://` 路径。
- 外部任务只允许 `HARDENED_GVISOR`/`HARDENED_KATA`，并要求与 P0 release decision 的 runtime image/capability 一致。release gate 必须覆盖网络、DNS、metadata、宿主挂载、Docker socket、root/文件系统/capability、资源耗尽、trace 篡改、Agent 缺失和 escape suite，证据超过 30 天或未验证即拒绝。
- Agent 模块引入并 relocation Byte Buddy 1.18.11，采用 startup-only 插桩：Spring mapping/Servlet、JDBC implementation 与应用侧 JDK HTTP/文件/进程调用点。事件新增 `AGENT_INSTRUMENTED` 并回指 caller method descriptor、target 和 invocation ordinal；bootstrap/JNI/反射等盲区明确上报。Agent 与目标同 JVM，来源仍可被恶意目标干扰，只能是 `DYNAMIC_SUSPECTED`。
- 新增固定 HTTP、精确 SQL、tmpfs 文件和默认拒绝进程的依赖替身；每个结果绑定 scope/policy/sequence/provenance/executed/budget/stop reason，并生成脱敏稳定 transcript 摘要。SQL 归一化保留引号内字面量，避免跨语义规则误匹配。
- 新增 Vineflower 主/CFR 校验的隔离 Worker 契约以及只链接原始 JAR 的 `HarnessPlan`/javac 边界；本轮未捆绑或实际运行反编译器，也未启用真实模型。
- 外部 trace 已接入严格 Agent JSONL converter、Worker trace 提交和公共路径/证据投影；双次重放绑定原始 JAR、Agent、runtime image、harness、替身 transcript 和 outcome。即使匹配也只形成 `DYNAMIC_SUSPECTED` 候选，不生成 `VERIFIED`。
- 根 Maven 编译、11 个相关 main-style 验收、Agent Maven clean/test/package 和重定位后 packaged `-javaagent` 验收通过；IDE lint 无错误。真实 OpenSandbox/gVisor/Kata、协议级数据库替身、公开外部执行 API 和真实恶意样本仍未验收，外部动态能力不得对用户标记为 enabled。
- 分阶段 Git 备份：`a17755f`（自动 Agent 插桩）、`fc69d5d`（外部执行、替身、反编译/harness、重放与发布门禁）。

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
7. 对可安全拆分且文件边界明确的任务，默认并行启动多个子 Agent；根 Agent 负责划分互不冲突的范围、汇总结果、解决集成冲突并执行统一回归。

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
- 生产制品必须进入内容寻址、只读存储；浏览器上传切片已将校验后的副本安装到内容寻址目录。旧路径登记仍只允许受控目录原文件并在分析前复核摘要。
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
- 后端能力最初包含仓库样例专用的 `FIXTURE_RUNC`；该能力随后被 `TRUSTED_DOCKER` 后端管理制品路线取代并删除。当前保留 `STATIC_ONLY`、`TRUSTED_DOCKER`、`HARDENED_GVISOR`、`HARDENED_KATA`。
- Windows 只作为 Control Plane/开发宿主，动态任务运行在 Linux Worker。强化运行时未通过 P0 网络/DNS、宿主路径、非 root、只读根、资源耗尽和逃逸测试前，health 必须保持 `DYNAMIC_DISABLED` 并 fail-closed。
- Worker 合约必须版本化并绑定项目、制品摘要、扫描和任务四元组；trace 采用带前序 SHA-256 的追加链。GUI token、Worker token 和 OpenSandbox API key 相互隔离。
- JVM Agent 是观测层而不是安全边界。动态结果只能产出 `DYNAMIC_SUSPECTED`；在强化沙箱和可重放证据完成前不得生成 `VERIFIED`。
- OpenSandbox 本地开发仍依赖 Docker；后续可替换为其他兼容后端，但不得静默降级到宿主 Java 子进程执行外部制品。

## 14. Worker、OpenSandbox 与 JVM Agent 实现审计（2026-07-24）

- 已完成版本化 Worker 任务、租约、检查点和 trace 合约，以及作用域绑定、幂等状态机、租约过期回收和带前序 SHA-256 的追加 trace 链。
- Control Plane 已接入独立 GUI/Worker token 的任务与 trace API，并强制 `ResourceBudget.maxTraceBytes`；本轮仍是进程内协调器，不代表持久化或多租户生产能力。
- OpenSandbox 适配器按 sandbox ID 从 lifecycle API 解析 44772 Execd 代理端点；运行时能力只接受部署运维方配置的 attestation，响应数据不能授予能力。适配器限制同源、端点路径和凭据头，拒绝网络放开、root、可写根目录及能力降级。
- 独立 `agent/` Maven 模块提供 Java 17 `premain`/`agentmain`、类加载观测和 HTTP/FILE/JDBC/PROCESS 显式探针，输出受目录授权、事件/字节预算、字段边界、控制字符清理和敏感键脱敏约束的 JSONL。
- JVM Agent 不是安全边界。类加载等 Agent 自有事件标为 `RUNTIME_OBSERVED`；显式探针可被应用调用，必须标为 `APPLICATION_REPORTED`。两者当前都只能是 `DYNAMIC_SUSPECTED`，不得生成 `VERIFIED`。
- 根 Agent 已逐文件审阅三个并行实现轨并修正显式探针证据来源；使用 JBR 21 复验根 Maven、六个 main-style 验收类、Agent Maven test/package 和真实 `-javaagent` 子进程，全部通过。
- Git 审计备份：`94d55fb`（OpenSandbox 适配器）、`1108a98`（Worker Control Plane API）、`41d36a9`（JVM Agent）。后续路线已转为后端管理制品与显式 `TRUSTED_DOCKER`/强化运行时。

## 15. 早期受控样例动态切片（2026-07-24，已退役）

- 该早期切片曾验证 public 排队、Worker HTTP、Agent JSONL、不可变 trace 与 dashboard/path/evidence 投影；随后由后端管理制品的 `TRUSTED_DOCKER` 路线取代。
- 仓库受控样例、固定镜像模板、专用 public/Worker 合约和相关验收现已删除。历史备份不代表生产沙箱或外部制品动态执行可用。
- 保留的安全结论不变：动态证据仅为 `DYNAMIC_SUSPECTED`；Agent 自有事件为 `RUNTIME_OBSERVED`，应用或插桩事件不能被摘要升级为 `VERIFIED`。

## 16. 本地一键开发启动器（2026-07-24）

- 新增 `DevLauncherMain` 与根目录 `Start-Veyrion.ps1`：自动创建工作区内 `samples/`、生成进程内随机 mutation token、启动 loopback Control Plane、创建本地项目并以环境变量启动 Vite。
- 启动器只直接执行仓库前端的 `npm run dev`，不经过 shell，不执行导入制品，也不属于 Worker fallback；前端退出时后端随之关闭，JVM 关闭钩子负责清理子进程。
- 制品目录必须位于工作区内，前后端端口必须不同；实际冒烟已验证后端 health 与 Vite 首页均可访问。

## 17. 本地首版管理与分析闭环（2026-07-24，根 Agent 审计通过）

- 本地默认 Store 改为 SQLite/plain JDBC，使用 V001/V002 有序迁移和历史 checksum 校验；项目、制品元数据、扫描、证据、发现、攻击链、Provider、AI 角色绑定、阻断态 AI job、操作员 PAT 和审计事件可跨重启恢复。数据库与密钥路径必须留在授权根目录下。
- Provider API Key 只进入专用请求字段，使用后端文件根密钥与 AES-256-GCM 加密；AAD 绑定 workspace/provider/credential/version，数据库、响应、异常和审计不返回明文或密文。Provider endpoint 拒绝 userinfo/query/fragment，LOCAL 只接受 loopback。后续为兼容受信内网网关增加了远程 HTTP，但其传输不保密。
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

## 21. 浏览器分块制品上传（2026-07-24，根 Agent 审计通过）

- GUI 默认通过文件选择器读取用户明确选择的 JAR/WAR/CLASS，使用 Web Crypto 计算完整 SHA-256，并以 1 MiB 顺序分块上传；显示进度、支持取消，旧路径登记移入高级兼容区域。
- Control Plane 新增项目作用域的初始化、PUT 分块、完成和取消路由，统一要求操作员 `MANAGE_PROJECTS`，Worker token 被拒绝。上传会话限制数量、声明总量、TTL、顺序 offset 和单块 4 MiB，并验证每块摘要。
- 完成时复核大小、完整 SHA-256、扩展名和 JAR/WAR ZIP 结构，通过 `ArtifactRegistry` 后原子安装到 `.veyrion/artifacts/sha256/<prefix>/<digest>.<ext>`。项目登记和后续扫描只引用该受控副本；删除浏览器源文件不影响扫描。
- 重启只清理内部命名的残留 `.part`，不删除已安装内容。当前会话仍是进程内状态，浏览器完整摘要上限为 256 MiB，尚未提供跨重启续传或流式前端摘要。
- 根 Agent 审阅服务、API、前端契约和负向验收；`ArtifactUploadAcceptanceTest` 覆盖篡改、乱序、跨项目、未授权、超限、坏 ZIP、取消、重复摘要、源文件删除和启动残留清理。Maven test-compile/验收与 GUI 生产构建通过。

## 22. 有界 AI Job 首版（2026-07-24，根 Agent 审计通过）

- 在 SQLite V004 上实现 `QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED/BLOCKED` 状态与 workspace/project/scan/artifact/role/provider/model/policy 快照；中断进程遗留的排队或运行任务重启后 fail-closed 为 `PROCESS_RESTARTED`。
- 只有显式 `authorized=true`、启用且有凭据的角色绑定，以及 `OPENAI_CHAT`、`ANTHROPIC_MESSAGES` 或旧 `OPENAI_COMPATIBLE` 才可进入异步编排；`AZURE_OPENAI`、`LOCAL` 和缺失配置保持阻断。GET 不触发 Provider 清单或聊天出站。
- 生产聊天传输使用 Java `HttpClient`、HTTP(S) 固定协议路径、禁止重定向，并限制连接/请求/响应/轮次/token/工具调用和响应读取时间。明文 HTTP 仅用于兼容用户明确配置的受信网关，不提供凭据或模型数据机密性。工具执行仍由代码侧 `AiToolRegistry` 决定；请求要求 Provider 禁用 parallel，若兼容网关忽略该提示，则后端在固定总预算内顺序处理并逐条审计。
- 模型、制品文本和工具结果固定标记为不可信数据；最终仅持久化经截断和脱敏的 `INFERENCE` 摘要、最小运行元数据与工具决策摘要，不生成 `VERIFIED`。
- 根 Agent 补强 OpenAI strict schema、未完成工具结果顺序、未知/越权调用预算、迭代 JSON 深度、运行任务删除竞态、创建字段 allowlist、Provider/角色绑定/scan 配置漂移复核和响应临时字节清零。
- mock 传输验收覆盖 OpenAI/Anthropic 各一次工具循环、无授权/绑定、429/500/超时、取消、重启恢复、配置漂移、提示注入、越权、预算、截断、畸形响应与敏感内容不落 AI job/审计；9 个相关 Java main-style 验收及 GUI 生产构建通过。
- 审计结论只接受为“本地有界 AI Job 首版”。尚无真实供应商互操作、生产 egress/DNS rebinding 防护、流式协议、成本计量或多租户调度，不得标记为生产可用；模型输出始终只能是 `INFERENCE`。

## 23. 静态结果与 loopback Provider 修正（2026-07-25）

- 修复 Spring Boot loader 类名误报：有效 classfile 不再仅因类名包含 `File`、`Path`、`Exec` 等词生成 sink；class-name sink/dependency 规则只保留给元数据无法解析时的显式降级。
- 修复静态推断 severity 误导：`UNBOUND` 信号固定为 `info`；已绑定入口的静态 file/command 信号最高为 `low`/`medium`，不再把无路径、无动态证据的名称命中显示为 `high/critical`。
- Provider endpoint 允许 OpenAI Chat/Anthropic Messages 使用显式 HTTP(S)，满足本机和受信内网代理场景；继续拒绝 userinfo/query/fragment、重定向、链路本地/metadata 与组播目标。非本机 HTTP 会明文暴露 API Key 和模型数据，不得描述为安全默认。
- 旧 scan 是不可变历史快照，不会被后台改写；用户需要重新扫描才能看到修正后的结果。

## 24. 管理 GUI 可用性修正（2026-07-25）

- 扫描策略页在工作区切换后自动清空旧目标并加载该项目制品，异步响应带组件生命周期保护；移除“刷新目标”按钮。
- AI 角色的 `providerModelName` 改为可搜索 datalist 输入，既可选择 inventory 模型，也可手工输入兼容网关模型名；绑定仍需显式点击保存。
- 真实动态状态仍取决于独立 Linux Worker/OpenSandbox。Windows 本地启动器不会把宿主 JVM 或普通 Docker 冒充强化沙箱；未部署时 UI 保持 `UNAVAILABLE`。

## 25. Windows Docker 调试路线演进（2026-07-25）

- 最初的仓库受控样例调试切片已退役；其代码、镜像、public/Worker 合约和专用验收不再保留。
- Docker Desktop 当前为 Linux/WSL2 Engine，但 runtime 清单只有 runc，没有 runsc；Windows 本地能力只能声明 `TRUSTED_DOCKER`，不能标记为 `HARDENED_GVISOR`。
- 对照当前官方协议后确认既有 OpenSandbox 适配器尚未完成 SSE/status、认证和 endpoint 校验互操作；在这些边界完成前不得启用或宣称 OpenSandbox/gVisor 已验收。

## 26. TRUSTED_DOCKER 内部 JAR 直接执行与 AI 可审计性修正（2026-07-25）

- 用户可见动态入口不再选择或运行受控 Fixture。`POST /api/v1/scans/{scanId}/dynamic-tasks` 只接受 `authorized=true`，Control Plane 根据不可变 scan 快照选择首个入口，并只从后端 artifact catalog 解析已登记、内容寻址且执行前复核 SHA-256 的可执行 Spring Boot JAR；浏览器不能提供镜像、命令、宿主路径、挂载或 capability。
- Windows 本地显式开关为 `-WithDockerRuntime` 与 `-RebuildRuntimeImage`；旧 Fixture 命名 alias 已删除。Sandbox Pack 构建只包含固定 Agent 的 digest-pinned runtime image，并启动 loopback registry；当前直接 Docker Worker 不依赖或假装经过 OpenSandbox。
- 该开发能力单独声明 `TRUSTED_DOCKER`，不是 `FIXTURE_RUNC`，也不是 gVisor/Kata 强化运行时。容器固定 `--network none`、只读 rootfs、单个只读 artifact bind mount、非 root `65532:65532`、cap-drop ALL、no-new-privileges、PID/内存/CPU 上限和有界 trace tmpfs，创建后复核有效 Docker 配置；任何失败均 fail-closed，绝不回退到宿主 Java。
- `--network none` 同时阻断外部 DNS 和外部网络；执行器的 HTTP probe 由同一容器内的 Agent helper 访问目标 JVM loopback，不是外部网络探测。Docker runc 仍不是运行恶意制品的强化隔离边界，对外生产启用仍需 gVisor/Kata 与 P0 release gate。
- 首轮真实 AI 失败的根因是 Provider 拒绝带点号的函数名；代码侧工具标识统一改为 Provider 可接受的 snake_case：`facts_search`、`evidence_get`、`plan_propose`。这属于协议互操作修正，不扩大工具 allowlist、作用域或权限。
- SQLite V005 为每个 AI job 保存最多 128 条顺序事件，记录有界 Provider 请求/结果元数据、工具名、参数形状/字节数、工具结果状态、脱敏截断的模型摘要和失败诊断。API 展示的是可审计事件摘要，不保存 Provider 原始响应、秘密、模型隐藏推理或 chain-of-thought；模型结论仍只能是 `INFERENCE`。
- `LocalDockerDynamicLoopAcceptanceTest` 现要求通过 `VEYRION_TEST_ARTIFACT_JAR` 显式提供后端管理的 executable 测试 JAR；仓库不再携带受控 Fixture 代码、镜像或专用合约测试。回归继续覆盖 public 排队、内容寻址只读挂载、断网容器、容器内 loopback HTTP、不可变 trace commit 与 dashboard `DYNAMIC_SUSPECTED` 投影；这只验证本地受信 JAR 开发路径，不代表恶意制品隔离或真实外部 Provider 互操作已验证。
- GUI 不再把“当前 scan 尚未创建动态任务”误显示为 Worker `UNAVAILABLE`。`GET /api/v1/scans/{scanId}/dynamic-tasks` 返回当前进程内任务状态、停止原因和失败代码，审计页对 `QUEUED/RUNNING` 自动轮询；进程重启后任务协调状态仍不会持久化。历史 AI `FAILED` 状态保持不可变，审计页可显式重新创建四角色任务并自动刷新新任务，不能把旧任务原地改写为成功。
- AI 审计页创建任务时必须显式提交当前页面 `scanId`，后端复核 scan 属于项目并将其固化到 job 快照，避免依赖隐式“最新扫描”导致 `SCAN_REQUIRED`。Docker Worker 失败现在通过内部合约提交最长 2 KiB 的脱敏诊断，public 动态任务状态可显示该诊断；旧任务在加入该字段前的失败细节无法追溯恢复。
- AI 审计详情对运行中任务自动轮询，能够在结束前显示 `PROVIDER_REQUEST`、`PROVIDER_RESPONSE` 与后续工具事件；仍不保存隐藏思维链。用户可显式清理 `FAILED/BLOCKED/CANCELLED` job 及其事件。非协议类异常保存脱敏后的异常类型/消息，避免统一 `AI_JOB_FAILED` 丢失可操作原因。TRUSTED_DOCKER 对已限定为 executable Spring Boot JAR 的制品固定追加 `--server.address=127.0.0.1 --server.port=8080`，使容器内 HTTP 探针不受制品自定义监听端口影响；程序化禁用 Web Server 的应用仍会按真实失败报告。
- AI 数据发送确认只在当前浏览器页面会话首次创建 Job 时弹出一次，不写入持久存储；每个后端 Job 请求仍必须单独携带 `authorized=true` 并通过权限校验。Provider 返回 2xx 但协议解析失败时，仅持久化代码生成的协议名与解析规则诊断（不保存响应正文），用于区分缺少 `choices`、`finish_reason`、assistant message 等兼容性问题。
- 全局设置中的单角色操作合并为“保存分配并创建 AI Job”：先等待角色绑定持久化成功，再基于该绑定创建任务，避免用户对每个角色连续点击两个按钮；任一步失败均显示后端错误且不伪造任务成功。
- 左侧导航拆分独立“模型服务”和“AI 审计过程”：模型服务承载 Provider、模型清单和四角色绑定，AI 审计过程承载 Job 队列、Provider/工具事件与清理操作；“审计执行”只保留扫描策略和 Docker 动态时间线，“全局设置”只保留外观与固定安全默认值。
- 修复 dashboard 前后端 provenance 枚举漂移：Agent/Worker 会产生 `AGENT_INSTRUMENTED`，前端此前遗漏该合法值并以 `invalid path.provenanceKind` 拒绝整个 dashboard。前端现与 Agent JSONL 合约一致接受该值；本机真实 dashboard 已确认包含 `RUNTIME_OBSERVED` 与 `AGENT_INSTRUMENTED/HTTP`，Java AI 编排、动态投影验收及前端生产构建通过。
- 完整用户路径回归扩展为同一隔离 Control Plane 内执行：真实后端管理 JAR 静态扫描、`TRUSTED_DOCKER` 断网运行、Agent HTTP trace、dashboard 投影、四角色绑定、OpenAI Chat 两轮工具调用，以及 Provider/工具/推断事件读取。回归使用合约一致的受控 Chat transport，不声明用户实际 Provider 网关兼容性；2026-07-25 本机真实 Docker 与全部四角色均通过。
- 修复首次启动项目选择：GUI 不再假定不存在的 `default` 项目；项目列表返回后保留仍存在的选择，否则自动选择首个项目或明确保持未选择，避免启动即请求 `/projects/default/dashboard`。
- “模型服务”中的“保存分配并创建 AI Job”现在必须取得并显式提交当前 dashboard `scanId`；没有静态扫描时按钮禁用且显示说明，不再依赖后端 latest-scan 回退或创建 `SCAN_REQUIRED` 任务。
- Windows 启动器会在启动 Sandbox Pack 或执行 Maven 前预占测试 backend/frontend loopback 端口；旧实例占用时返回明确端口错误，避免最后以 `BindException` 失败。Sandbox Pack 的 Compose 启动使用 `--remove-orphans`，自动清理已退役的 OpenSandbox service 容器。
- 部分 OpenAI-compatible 网关会忽略请求中的 `parallel_tool_calls=false`。适配器接受协议上限内的多个调用，但 Orchestrator 只按返回顺序执行，仍受固定角色 allowlist、总调用预算、参数/结果字节和截止时间限制；每个调用都产生独立审计事件，超预算调用由 Registry 返回 `NOT_EXECUTED`，不并行执行也不扩大模型权限。

## 27. 受控 Fixture 样例退役（2026-07-25）

- 删除 `fixtures/http-entry/`、旧 `FIXTURE_RUNC` public/Worker/OpenSandbox 专用验收以及 Fixture Worker/本地 Fixture sandbox 验收。
- 本地真实 Docker 动态回归不再依赖仓库样例；测试操作者必须显式设置 `VEYRION_TEST_ARTIFACT_JAR`，指向后端可登记并复核摘要的 executable Spring Boot 测试 JAR。
- 删除 `-WithDockerFixture`、`-RebuildFixtureImage`、`-SkipFixtureBuild` 兼容 alias。保留 `TRUSTED_DOCKER` 安全边界和 AI 审计文档，不将普通 Docker 描述为强化恶意代码隔离。

## 28. 工作区与审计主流程信息架构重构（2026-07-25）

- 打开应用的默认首页是「工作区」：以小格子展示已有授权工作区，点击切换并进入审计执行；页面提供新建与删除。侧栏当前工作区芯片可返回该首页。
- 左侧主导航顺序：`工作区 → 审计执行 → 审计过程 → 审计结果 → 模型服务 → 全局设置`。切换工作区后 dashboard、制品、角色绑定和模型事件全部按项目重新加载。
- 「审计执行」承载制品导入、策略、阶段进度与自动流水线。用户点击“开始审计”后，GUI 只调用 `POST /projects/{id}/audit-runs`；Control Plane 完成静态事实与入口发现，并创建绑定同一不可变 `scanId` 的前置建模任务。请求分别要求 `authorized:true` 与 `aiAuthorized:true`，且必须提供幂等键。
- 「审计过程」在审计执行与审计结果之间，以对话形式展示系统提示词、任务说明、模型思考（若返回）、工具调用、最终输出与底部实时动向。
- 主流程固定为：`制品摘要复核 → 静态事实/入口发现 → 前置建模 → 路径探索 → 断网动态观察 → 动态验证 → 漏洞研判 → 报告生成`。一次授权后由服务端流水线自动推进；模型不能改写静态事实，也不能单独生成「已验证」。
- “模型服务”只负责接口密钥、模型清单和项目角色绑定；保存角色绑定不顺带创建任务。
- 组合入口仍以 `audit-runs` 启动；流水线在进程内武装，重启后未完成的自动接续不保证恢复。

## 29. aaaaa.jar 真实全流程回归与思考模型互操作（2026-07-25）

- 使用根目录 `aaaaa.jar`（SHA-256 `190a206da4767a39cb68ac22e63ab8dca729a448e9f37fc5611dd990064fc4ca`）通过真实 GUI 新建 `aaaaa.jar full-flow 20260725-1635` 工作区、浏览器分块上传，并将四角色绑定到 `api3 / OPENAI_CHAT / deepseek-v4-pro`。
- DeepSeek 思考模式要求工具轮次把响应中的 `reasoning_content` 原样回传。OpenAI 适配器现在只在当前 Job 的有界内存 wire turn 中保留并回传该不可信字段；不会把它映射为模型摘要、工具输入、AI Job event、审计记录或数据库字段。
- 真实模型会在多个轮次批量查询事实。AI Job 仍保持有界，但调整为最多 5 轮、16 次只读工具、单请求 90 秒和 Job 工具期限 300 秒；达到 12 次工具调用或进入倒数轮次后，服务端关闭工具阶段，后续请求不再发送工具定义，并要求模型仅基于已有证据形成最终推断。
- “审计结果”页新增当前 scan 的 `REPORT_GENERATION` 最终摘要，只按纯文本显示并标记 `AI INFERENCE`，不渲染模型 HTML，也不提升为 `VERIFIED`。前端 AI event 校验允许摘要中的 TAB/LF/CR，其他控制字符和 16 KiB 上限继续拒绝。
- AI 工具事实源新增 `SCAN`、`DYNAMIC_EVIDENCE`/`RUNTIME_EVIDENCE`，并将同一 Control Plane 内的动态投影以只读安全摘要注入；每条动态记录必须再次匹配 project/artifact/scan，工具只获得摘要、来源、状态和作用域，不获得原始 trace 或执行权限。
- 最终真实回归 `scan-cf2a6763368f4c7a` 完成 PRE_ANALYSIS、PATH_EXPLORATION、TRUSTED_DOCKER、VULNERABILITY_TRIAGE 和 REPORT_GENERATION；报告正确识别 7 条 `DYNAMIC_SUSPECTED` Agent 记录。
- 该回归同时确认当前动态能力仍只观察到 `AGENT_STARTED`、插桩能力和应用类 `CLASS_LOAD`；没有 HTTP 入口调用、参数绑定、sink 或副作用事件，5 个入口覆盖率仍为 0，所有静态路径仍以 `STATIC_ONLY_NOT_EXECUTED` 停止。任务容器“COMPLETED”只表示受控运行/探针流程结束，不等于入口已执行或漏洞已验证。

## 30. 双语 Markdown 报告与可展开 AI 数据流（2026-07-25）

- 全局 AI 输出语言固定为 `ZH_CN` 或 `EN`，默认中文。GUI 偏好只影响新建任务；Control Plane 将 `outputLanguage` 与 `outputFormat=MARKDOWN` 固化到每个 AI Job 的不可变 policy snapshot，旧任务和旧报告不被改写。
- 四角色提示按语言由服务端生成，模型或前端输入不能覆盖。中文报告必须包含执行摘要与结论边界、入口—触发点矩阵、多条推测链路、组合漏洞可能性、动态证据与覆盖、风险分级、未覆盖区域和下一步验证；证据不足时必须明确写出，不能为满足模板编造 sink 或漏洞。
- 英文模式使用等价 Markdown 结构。类名、方法、路由、证据 ID 与状态枚举保持原文；所有模型结论仍为 `INFERENCE`，语言和格式选择不能提升验证等级。
- 默认仍不把完整 Provider 原始响应写入数据库。自 §34 起，允许把服务端实际下发的系统/用户提示、可见中间输出，以及模型返回的思考摘录写入有界事件，供对话式审阅；这些内容仍不能改变工具权限或证据等级。
- 工具参数审计增加受限字段：事实类别、limit、query 是否存在/字节数、合法 evidence/entrypoint 引用、候选数量和 objective 字节数；不保存原始 query、候选 payload、objective、Provider 原始响应或凭据。
- 结果页使用 `react-markdown` + `remark-gfm` 渲染表格等 Markdown，固定 `skipHtml`，并按安全化后的 scan ID 下载 `.md`；报告保持 `AI INFERENCE`。浏览器回归确认原始 `<script>` 不进入 DOM、语言偏好跨刷新、事件可展开且下载文件名正确。
- 修正开发页面 CSP 控制台噪声：移除 Chrome 不接受的 IPv6 wildcard source 和 meta 中不会生效的 `frame-ancestors`，补充 data URI favicon。生产点击劫持防护仍必须由最终 HTTP 响应头提供，不能依赖 meta CSP。

## 31. Java checklist 驱动的字节码 sink 扩展与流向校正（2026-07-25）

- `JAVA checklist.md` 只作为候选目录，静态检测不使用 `parse/read/execute` 等裸关键词。新增规则必须同时约束 JVM target owner 与 method，必要时约束 descriptor；单次命中只证明 classfile 中存在敏感 API 调用。
- 当前高信号目录覆盖命令/原生库、反序列化、表达式与模板、JNDI、反射/类加载、SQL/NoSQL/LDAP/XPath/XML/XSLT、文件读写删除/归档、SSRF 与重定向。需要常量、版本、安全配置、入参可控性或跨方法数据流才能判断的项目继续标为条件性低置信度候选。
- 每个调用候选生成 `FACT` classfile-call evidence，但 Sink 和 Finding 保持 `STATIC_INFERRED`；未绑定入口固定为 `info`，已绑定候选最高 `medium`，置信度低于 0.80 时最高 `low`。规则不得生成 `VERIFIED`。
- Spring Boot 可执行包自带的 `org.springframework.boot.loader.*` 类加载、归档 I/O 与 URL handler 调用被识别为框架启动基础设施，不进入应用 sink，避免所有 Boot 制品重复出现相同噪声。
- 修复静态路径错误投影：不再把全部 dependency/sink 追加到每个入口。入口 annotation evidence 的 `class#method` 与调用 evidence 的 caller `class#method` 精确匹配后，才把该 sink 放入对应路径；同类不同 handler 不互相继承 sink。
- 静态攻击链只在同一已绑定 handler 至少有两个候选时生成，并明确命名为 “flow not verified”；unbound 候选不形成攻击链，链证据只包含该组 finding 的引用。
- 合成回归覆盖 12 个类别、同类 safe/danger 两个 handler、框架噪声抑制和 API 路径映射。`aaaaa.jar` 复核结果为 5 个入口、3 个应用调用候选：`/debug-resource → SSRF`、`POST /parse → Fastjson DESERIALIZATION`、`/debug-cl → SSRF`；原先 24 条 Spring Boot loader 调用不再污染结果。

## 32. 二次审计与前后端版本错位诊断（2026-07-25）

- Vite 热更新后会发送新增的 `outputLanguage`，但已经运行的 Java Control Plane 不会热加载；若后端仍是旧进程，会以 `AUDIT_RUN_FIELD_REJECTED` 返回 400。更新 Java 合约后必须重启本地启动器，不能只依赖前端 HMR。
- 前端现在对所有 JSON 4xx 响应只读取 allowlist 的 `code/message/requestId`，不再把具体校验错误隐藏成泛化的 `start audit failed: 400`；HTML、任意字段和 5xx 诊断仍不传播到页面。
- `AuditRunAcceptanceTest` 新增同项目、同已登记制品、相同策略但不同 Idempotency-Key 的二次审计：必须创建不同的不可变 scan/PRE_ANALYSIS Job，语言快照均为 `ZH_CN`；原 key 重放仍返回首个任务且不重复创建。
- 当前本地 18084/15177 栈已重启并加载最新 Java/前端代码，SQLite 状态与 Provider 配置保留。

## 33. 表达规范与第五角色「动态验证」（2026-07-25）

### 33.1 全局表达规范（对用户与文档一律生效）

- **说人话**：界面、报告、记忆文档与对用户说明必须使用可理解的中文，条理清楚、前后逻辑通顺。
- **禁止 AI 黑话堆砌**：不允许用“AI 短语”、内部黑话或炫技缩写代替本可用中文说清的含义。对外优先写「模型服务」「模型任务」「前置建模」「动态验证」，而不是把 `AI Job`、`PRE_ANALYSIS` 当成主文案。
- **专有名词例外**：仅当名词本身就叫这个、或 API/状态枚举/类名必须原样保留时，才保留英文原名（如产品名 Veyrion、证据状态 `VERIFIED`、路由 `/parse`、类名 `ParseController`）。技术代码可在次要位置出现，不得压过人话标题。
- **枚举要对人翻译**：执行模式对外写「替身执行 / 录制回放」，网络策略写「禁止外网」，危险动作写「空跑演练」；后端字段 `MOCK`/`REPLAY`/`DENY`/`DRY_RUN` 仍可在契约中使用。

### 33.2 固定五个模型角色

对 `scan-b94880412cbc4586` 的复盘确认：该扫描完成了前置建模、路径探索、漏洞研判、报告生成，但**没有**独立的动态验证角色；断网容器只是运行时阶段，不等于模型已解读动态证据。

主流程更新为：

```text
制品摘要 → 静态事实/入口 → 前置建模 → 计划评审 → 路径探索
→ 断网容器动态观察 → 动态验证 → 漏洞研判 → 报告生成
```

- 新增角色 `DYNAMIC_VERIFICATION`（界面名：**动态验证**）：在容器观察之后，读取同扫描「路径探索」最终推断作为不可信假设，再独立对照 `DYNAMIC_EVIDENCE` 与静态事实，逐条判定支持/反证/证据不足，并提出可重放验证步骤。
- **边界不变**：动态验证不能单独把结论升级为「已验证」；容器任务“完成”只表示受控运行/探针结束，不等于入口已执行或漏洞已证实。先前角色结论不得被写成事实。
- 工具白名单与路径探索/漏洞研判相同：`facts_search`、`evidence_get`、`plan_propose`；不能扩大权限、不能改写事实层。
- 数据库迁移 `V006` 扩展角色 CHECK；旧扫描不会自动补跑该角色，需在新审计中绑定并由流水线推进。
- 静态发现标题与路径说明默认使用中文（新建扫描生效）；历史扫描载荷保持不可变。

## 34. 自动流水线与对话式审计过程（2026-07-25）

- `AuditPipelineCoordinator` 在 `audit-runs` 成功创建后武装该 `scanId`：前置建模完成 → 路径探索 → 断网容器 → 动态验证 → 漏洞研判 → 报告生成。模型输出不能武装、跳过或扩展阶段。
- 编排器新增可审计对话事件：`PROMPT_SYSTEM`、`PROMPT_USER`、`MODEL_THINKING`、`MODEL_OUTPUT`，并保留 `MODEL_INFERENCE` 作为最终输出。`MODEL_THINKING` 仅保存模型返回的可见思考摘录（如 `reasoning_content`），经脱敏与长度限制；不得作为工具输入、不得扩大权限、不得当作已验证证据。
- 动态验证与后续角色的用户提示会注入先前角色的 `conclusion.summary`，并明确标记为 `PRIOR_ROLE_INFERENCE` 不可信假设。
- GUI：默认首页为工作区格子页；「审计过程」作为左侧独立导航，位于审计执行与审计结果之间，承载对话式提示词/思考/输出与实时动向；开始审计前需绑定全部五个角色。

## 35. 工作区首页与导航调整（2026-07-25）

- 默认进入「工作区」主页面，用小格子展示全部工作区；点击格子切换当前上下文并可直接进入审计执行；提供新建与删除按钮，删除仍走后端权限校验。
- 侧栏顺序固定为工作区、审计执行、审计过程、审计结果、模型服务、全局设置；侧栏芯片仅显示当前工作区并返回首页，不再用下拉菜单管理。

## 36. 本地 GUI 授权令牌同步（2026-07-25）

- 写操作需要浏览器携带与控制面一致的本地授权令牌。若只重启前端、或旧 Vite 进程仍持有过期令牌，会出现 `AUTHORIZATION_REQUIRED`（“a local authorization token is required”）。
- `DevLauncherMain` 将令牌持久化到 `samples/.veyrion/mutation.token`（跨重启复用），并同步写入 `frontend/.env.local`；同时仍通过进程环境变量注入 Vite。该文件已被 gitignore，仅用于本机 loopback 开发。
- 前端对 `AUTHORIZATION_REQUIRED` 给出可操作提示：必须用 `Start-Veyrion.ps1` 同时重启控制面与界面。

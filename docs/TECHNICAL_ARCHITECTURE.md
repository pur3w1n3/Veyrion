# 溯脉 · Veyrion 技术架构

正式产品名：**溯脉 · Veyrion**（英文：**Veyrion**）。Java 包名、Maven artifactId、内部 service name 和 `/api/v1` 路由继续使用兼容标识；商标和域名尚需检索。

## 1. 设计原则

1. 代码逻辑优先，外部依赖可替身、可记录、可回放。
2. 静态分析负责扩大视野，动态分析负责提供事实，AI 负责解释和关联。
3. 所有探索任务可暂停、可恢复、可重放、可审计。
4. 任何漏洞结论都必须携带来源、证据和置信度。
5. 扫描资源、网络和危险操作默认最小权限。

## 2. 逻辑架构

```text
┌─────────────── GUI / API ───────────────┐
│ 项目、入口、路径、图谱、报告、策略中心 │
└──────────────────┬────────────────────┘
                   │
┌──────────────────▼────────────────────┐
│ Control Plane                           │
│ Project · Policy · Scheduler · Audit   │
└──────────────┬───────────────┬─────────┘
               │               │
     ┌─────────▼────────┐ ┌────▼─────────────┐
     │ Analysis Plane   │ │ Agent Plane       │
     │ 反编译/调用图/污点 │ │ 入口/路径/漏洞/中枢 │
     └─────────┬────────┘ └────┬─────────────┘
               │               │
     ┌─────────▼────────────────▼─────────┐
     │ Exploration Plane                   │
     │ JVM Instrumentation · Input · State │
     │ Dependency Virtualization           │
     └──────────────────┬─────────────────┘
                        │
              ┌─────────▼─────────┐
              │ Isolated Sandbox   │
              │ Container/VM       │
              └────────────────────┘
```

## 3. 组件职责

### 3.1 Artifact Service

- 接收并校验 JAR/WAR/CLASS。
- 计算制品哈希，保存版本和依赖清单。
- 生产模式将制品复制到内容寻址的只读对象存储；M0 本地切片暂存原路径，并在每次分析前执行摘要/大小复核。
- 提取 MANIFEST、配置、注解、字符串和资源。
- 生成反编译视图，同时保留原始字节码定位信息。

### 3.2 Runtime Profiler

- 识别 Java 版本、主类、Web 容器和框架。
- 监听路由注册、Bean、Filter、Interceptor、WebSocket handler 和消息监听器。
- 将静态入口与运行时入口合并，生成 `EntryCatalog`。

### 3.3 Static Analysis Engine

- 基于字节码建立类层、方法层和调用层图。
- 识别 source、transform、sink、权限检查和状态检查。
- 建立数据库表/字段、文件路径、URL、命令和脚本的静态数据流。
- 输出候选路径和分支约束，不直接判定为已验证漏洞。

### 3.4 Pre-analysis AI

前置 AI 的输入包括反编译代码、字节码摘要、配置和静态图；输出必须是版本化 JSON：

```json
{
  "entryCatalog": [],
  "businessFlows": [],
  "permissionMatrix": [],
  "dependencyMap": [],
  "sinkCatalog": [],
  "explorationPlan": []
}
```

模型推断的字段必须包含 `source` 和 `confidence`，并与静态事实区分。前置 AI 不负责执行任意代码，只能调用只读分析工具。

### 3.5 Exploration Orchestrator

负责把入口和候选路径拆成任务，并维护以下状态：

- 当前入口、身份、租户和业务状态；
- 请求和输入生成器；
- 已满足的分支约束；
- 覆盖率、污点和敏感操作；
- 沙箱快照 ID；
- 停止原因和重试次数。

推荐使用持久化工作流引擎或可靠任务队列，使长任务可以恢复。第一版可以用数据库任务表加 Worker，后续再替换为专用工作流系统。

### 3.6 JVM Instrumentation

通过 Java Agent/字节码插桩采集：

- 方法进入、返回和异常；
- 分支命中和代码覆盖；
- 参数、返回值和污点标签；
- 文件、网络、进程、反射和类加载行为；
- JDBC 调用和 SQL 参数；
- 当前身份、租户和会话标识。

敏感值在采集端脱敏，原始值只在沙箱短期内保留。对高频方法采用采样和动态过滤，避免轨迹爆炸。

## 4. 外部依赖虚拟化

### 4.1 数据库

优先使用 JDBC 代理或驱动层拦截，将查询路由至模拟数据库。模拟数据库需要：

- 根据 SQL 和 ORM 元数据推断表、字段和关系；
- 支持空结果、单记录、多记录、边界记录和异常响应模板；
- 记录读写表、字段、条件和数据血缘；
- 允许用户导入脱敏快照；
- 对写操作使用事务回滚或影子数据库。

轨迹中要保留类似以下事实：

```text
入口 /api/a
  → UploadService.save
  → table=attachment, fields=(path, owner_id)
  → write
  → 依赖模式=mock
```

### 4.2 HTTP、缓存和消息服务

- HTTP：按主机白名单路由到 Mock Server，支持录制/回放。
- Redis/缓存：内存实现，记录 key 模式和权限边界。
- JMS/Kafka：本地代理队列，记录生产者、消费者和消息字段。
- 时间/随机数：可控时钟和种子，保证重放一致。
- 文件系统：临时工作区、路径映射和写入审计。

### 4.3 真实连接策略

真实连接必须显式开启，并同时满足：白名单、只读、脱敏、超时、审计和回滚。连接失败时继续使用替身执行逻辑，但报告必须标记“真实依赖未验证”。

## 5. 路径洪水与回溯算法

### 5.1 路径模型

路径由以下元素组成：

```text
Entrypoint → Input → Transform* → Branch* → State Transition* → Sink/Effect
```

每个节点保存快照、覆盖率增量、约束、身份和依赖状态。

### 5.2 任务优先级

优先探索：

1. 静态上可达高危 sink 的路径；
2. 新增代码覆盖率高的输入；
3. 能改变业务状态的路径；
4. 需要特殊权限但尚未执行的路径；
5. 已发现漏洞的上下游入口。

### 5.3 回溯流程

```text
执行请求
  → 记录约束/覆盖率/依赖
  → 约束失败或异常
  → 定位最近可行快照
  → 生成满足约束的新输入或身份
  → 重放并比较覆盖增量
  → 加入任务队列
```

对于权限、租户和业务状态，不跳过路径，而是建立合成身份或状态，并在结果中写入前置条件，例如“需要管理员角色”“需要同租户对象”“需要先完成订单创建”。

### 5.4 停止条件

- 单任务墙钟时间；
- 指令数、CPU、内存和磁盘上限；
- 状态哈希重复；
- 分支预算耗尽；
- 依赖连续失败；
- 检测到疑似非终止循环。

停止时必须输出 `stopReason`，而不是静默丢弃路径。

## 6. Agent 协议与中枢图谱

每个 Agent 通过受控工具工作，工具包括：查询静态图、获取脱敏轨迹、创建输入、启动沙箱、恢复快照、提交验证任务和写入事实图谱。

统一结果字段：

- `findingId`
- `source`
- `transforms`
- `sink`
- `impact`
- `preconditions`
- `evidenceRefs`
- `confidence`
- `verificationStatus`

中枢图谱使用 PostgreSQL + 图扩展或 Neo4j；高吞吐轨迹和覆盖率可放入 ClickHouse；原始制品和快照放对象存储。第一版可先用 PostgreSQL 表和 JSONB，避免过早引入多套基础设施。

## 7. 安全边界

- 每个项目、任务和 Worker 独立身份。
- 沙箱默认无外网，系统调用和子进程受限。
- AI 工具调用采用 allowlist，不允许直接执行任意宿主机命令。
- 制品、配置、凭据和轨迹加密；日志脱敏。
- 所有危险测试需策略审批；提供 dry-run 和只读模式。
- 生产模式支持私有化、离线模型和租户隔离。

## 8. 推荐实现栈

- GUI：独立 React + TypeScript + Vite 应用；TanStack Query 管理服务端状态，React Flow/Cytoscape 绘制图谱，Monaco 查看代码，ECharts 展示覆盖率。GUI 不直接访问数据库或沙箱。
- GUI 实时通道：MVP 优先 SSE，双向控制需要时再启用 WebSocket；事件丢失后以幂等查询接口补偿。
- 桌面形态：后续用 Tauri 2 包装同一套前端，不维护 JavaFX/Swing 分支。
- Control Plane：Java/Kotlin 或 Go；第一版优先选择团队最熟悉的技术。当前 JVM 分析核心使用 Java 17。
- JVM 分析：ASM + Soot/WALA 类调用图能力，配合自研框架适配器。
- AI 服务：独立 Agent Gateway，兼容云端和本地模型。
- 数据：PostgreSQL、对象存储；轨迹量增大后引入 ClickHouse。
- 沙箱：OCI 容器起步，企业版提供 Kata/Firecracker 等更强隔离。

GUI 与 Control Plane 之间只交换版本化 DTO。DTO 必须包含项目、制品摘要、扫描、验证状态、依赖模式和证据引用；前端不可根据自然语言模型输出自行生成漏洞结论。

## 9. 运行契约、数据一致性与故障处理

### 9.1 任务和事件契约

Control Plane 与 Worker 之间应使用版本化事件，而不是共享内部对象。至少定义 `ScanCreated`、`TaskLeased`、`TraceCommitted`、`FindingUpdated`、`TaskStopped` 和 `ScanCompleted` 事件；事件包含 `projectId`、`artifactDigest`、`scanId`、`taskId`、`schemaVersion`、幂等键和时间戳。重复投递必须幂等，事实证据采用追加写，禁止原地覆盖历史轨迹。

最小事件信封示例：

```json
{
  "eventId": "evt-01",
  "eventType": "TraceCommitted",
  "schemaVersion": 1,
  "projectId": "project-01",
  "artifactDigest": "sha256:...",
  "scanId": "scan-01",
  "taskId": "task-01",
  "idempotencyKey": "trace-01",
  "occurredAt": "2026-07-24T04:00:00Z",
  "payloadRef": "object://evidence/trace-01"
}
```

`payloadRef` 指向经过权限校验的对象，而不是把未经脱敏的轨迹直接塞进消息总线；事件消费者必须先验证项目边界、制品摘要和 schema 版本。

### 9.2 事实、推断与模拟结果分层

存储层应分开保存三类数据：

1. `Fact`：字节码、运行时和系统调用直接观测到的事实；
2. `Inference`：静态分析或模型推断，带来源和置信度；
3. `Simulation`：替身/回放产生的结果，带依赖模式和有效范围。

图谱查询和报告不能把三者无提示地合并。每条边保留 `evidenceRefs`、`observedAt`、制品摘要、工具版本和模型版本，便于审计和回归比较。

### 9.3 启动失败与降级

闭源制品常缺少配置、许可证或第三方服务。Runtime Profiler 应先生成启动诊断（Java 版本、缺失类、端口、环境变量和依赖连接），再按“替身—录制回放—用户补充—受控真实连接”的顺序降级。无法启动时仍可运行静态建模，但扫描必须标记为 `static_only`，不得生成动态已验证结论。

## 10. 沙箱隔离与多租户基线

- 容器使用只读根文件系统、非特权用户、最小 Linux capabilities、seccomp/AppArmor（或等效策略），并禁用宿主机路径、Docker socket、内核接口和不必要的设备。
- 出站网络按域名/IP/端口白名单控制，同时防止 DNS rebinding、IPv6 绕过和云元数据地址访问；所有允许的流量写入审计日志。
- Worker、对象存储和数据库按项目/租户使用独立身份；临时文件、快照和密钥在任务结束或保留期到期后可验证销毁。
- 沙箱逃逸、资源耗尽和代理绕过测试属于发布前 P0 安全门槛，而不是可延后的性能优化。

## 11. 可观测性与容量规划

系统至少输出任务排队时延、执行时长、轨迹吞吐、快照大小、替身命中率、模型调用耗时/成本、覆盖率增量和 Worker 失败率。按单项目并发任务、单任务最大轨迹大小和对象存储保留期建立容量预算；达到预算时优先压缩/采样并给出 `stopReason`，不能静默丢弃证据。

## 12. AI 治理与提示注入防护

Agent Gateway 对模型、工具和提示模板做版本登记；模型输出必须经过 JSON Schema 校验、权限检查和事实引用校验。代码中的注释、字符串、接口返回内容全部标为“不可信上下文”，不得覆盖系统策略。模型不可用或输出不合规时，系统应回退到静态规则和人工待审队列，而不是阻塞或自动扩大权限。

## 13. OpenSandbox Worker 决策

动态执行后端采用可替换的 OpenSandbox 协议适配器，使用其 `/v1` 生命周期 API 和 execd 执行面。Veyrion 自身持有任务授权、租约、资源预算、证据和验证状态；OpenSandbox 只负责隔离环境生命周期，不能反向扩大扫描策略。

后端能力必须显式分级：

- `STATIC_ONLY`：没有可用 Worker，拒绝动态执行；
- `TRUSTED_DOCKER`：运维显式启用的本地 Docker runc，只接受后端管理并复核摘要的内部可执行 JAR；不是强化隔离；
- `HARDENED_GVISOR`：通过 gVisor 运行时自检和安全门槛；
- `HARDENED_KATA`：通过 Kata/微虚拟机运行时自检和安全门槛。

Windows 可作为 Control Plane 和开发宿主；本地调试可显式启动进程内 `TRUSTED_DOCKER` Worker，生产动态任务应运行在独立 Linux gVisor/Kata Worker。普通 Docker/runc 不能作为恶意闭源制品的安全边界；只有强化运行时完成网络/DNS、宿主路径、非 root、只读根、资源耗尽和逃逸测试后，才允许不受信制品生产执行。任何动态后端失败时都退回静态分析，不得降级为宿主 Java。

Worker 与 Control Plane 之间只交换版本化合约。每个任务、租约、checkpoint 和 trace chunk 都绑定 `projectId`、`artifactDigest`、`scanId`、`taskId`，运行时轨迹以 SHA-256 前序摘要链追加提交。GUI token、Worker token、OpenSandbox API key 和沙箱内凭据相互隔离；任何来自制品、模型或前端的字段都不能修改运行时能力等级、网络策略或挂载范围。

## 14. 本地首版持久化与管理控制

- Desktop Core 使用 SQLite/plain JDBC 保存项目、制品元数据、扫描结果、Provider、AI 角色绑定、有界 AI job、本地操作员 PAT hash 和脱敏审计。迁移按版本顺序执行并校验历史文件摘要，未知版本、断档或 checksum 漂移均拒绝启动。
- Provider secret 使用数据库外根密钥和 AES-256-GCM；AAD 绑定 workspace、Provider、credential 和版本。HTTP DTO 不包含明文、密文、nonce 或可逆片段。根密钥文件权限在支持的平台尽力收紧，非 loopback/生产形态无法确认权限时必须拒绝启用。
- 本地 bootstrap token 映射到 `local-admin`，每次进程启动轮换，旧 token 失效；操作员 PAT 与 Worker token 使用不同格式、header、存储和校验器。当前只完成 loopback 单 workspace RBAC，生产 SSO/session 和全部 GET 的身份边界仍待实现。
- AI Gateway 已支持 OpenAI Chat/Anthropic Messages 非流式请求和单工具调用循环；只有显式授权、固定角色绑定、启用 Provider、后端凭据和完整配置快照一致时才出站。模型输出无权修改工具、网络、沙箱、预算或验证等级，结论固定为 `INFERENCE`。

### 14.1 浏览器制品上传边界

- GUI 只读取用户通过文件选择器明确选择的 JAR/WAR/CLASS，并在本地计算完整 SHA-256；不接收浏览器伪造的宿主路径。
- Control Plane 以项目作用域创建有 TTL 和总预算的进程内上传会话，只接受顺序 offset、明确 Content-Length、单块不超过 4 MiB 且 `X-Chunk-SHA256` 匹配的字节。
- 完成时再次核对声明大小和完整摘要，并通过 `ArtifactRegistry` 检查扩展名、文件边界及 JAR/WAR ZIP 结构。通过后只能原子移动到授权根内的内容寻址路径，项目登记和扫描引用该副本。
- 启动时仅清理匹配内部命名规则的残留 `.part`；已安装内容不受影响。取消和过期会释放会话预算。上传权限属于操作员 `MANAGE_PROJECTS`，Worker 凭据不能进入该域。
- 旧路径登记暂时保留为本地兼容入口，但 GUI 默认折叠；它不具备浏览器上传语义。上传会话尚未持久化，断线续传只在同一进程生命周期内有效。

## 15. 字节码事实索引

- 在既有有界 classfile reader 上提取类层次、字段、方法、字段读写、调用指令与稳定指令证据，不加载或初始化被测类。
- `invokestatic`/`invokespecial` 只记录符号直接目标；虚调用和接口调用标为保守 CHA 声明目标；`invokedynamic`、反射、JNI 和动态代理标为 unresolved。当前不展开完整 classpath 子类、不执行 bootstrap、不做跨方法污点或反射字符串求值。
- 反编译只作为未来隔离分析 Worker 的派生阅读视图，不能作为事实源，也不能在 Control Plane 进程内运行。

## 16. 交付与部署形态

默认交付采用两层产物：

1. **Desktop Core**：使用 `jlink + jpackage` 在目标平台分别构建安装包，包含裁剪 Java runtime、Control Plane、SQLite native library 和 React 静态资源。应用只绑定 loopback，并打开系统浏览器。
2. **Sandbox Pack（可选）**：以 digest-pinned Docker Compose 提供 Linux Worker/OpenSandbox。Desktop Core 通过版本化 Worker 合约连接；健康或 attestation 不通过时动态能力关闭。

该拆分满足无 Docker 的静态开箱使用，也保留强化动态隔离。Compose 只提供部署一致性，不自动成为恶意制品安全边界；本地普通 runc 仅允许操作员信任、由后端管理并复核摘要的内部 JAR。多平台产物必须在对应 OS/架构 CI 构建、签名并生成 SBOM。GraalVM Native Image 待反射、JNI 与插件契约稳定后另行评估。

## 17. 外部 Spring Boot JAR 动态分析首版

外部制品采用“原始事实—派生理解—原始制品重放”的三层结构：

1. classfile/事实索引定位入口、调用点和依赖；
2. Vineflower/CFR 派生视图与 AI `HarnessPlan` 只用于输入和状态规划，不能编译为替代目标；
3. harness 只能链接 digest-verified 原始 JAR，最终观察来自强化沙箱中的原始字节码。

`ExternalArtifactTaskExecutor` 只消费内部 task scope 和 artifact catalog。执行前复核文件身份、大小、ZIP signature 和 SHA-256；浏览器请求不携带宿主路径，命令、Agent 路径、runtime image、UID/GID、tmpfs、网络和预算由部署策略固定。本地调试任务可使用部署方显式启用的 `TRUSTED_DOCKER`；面向不受信制品的生产任务必须使用 `HARDENED_GVISOR` 或 `HARDENED_KATA`，并与 P0 release decision 的镜像/capability 一致。

Agent 使用 startup-only Byte Buddy 插桩，不修改 bootstrap class：Spring mapping/Servlet 与 JDBC implementation 采用方法 Advice，JDK HTTP/文件/进程采用应用调用点插桩。事件区分 `RUNTIME_OBSERVED`、`AGENT_INSTRUMENTED`、`APPLICATION_REPORTED`，并回指 caller class、method descriptor、target 与 invocation ordinal。Agent 与目标同 JVM，恶意目标理论上可以干扰或伪造进程内状态，因此 Agent 永远不是安全或不可篡改边界；Worker 负责 trace 预算、摘要链、完整性和双次重放。

替身层仅提供 loopback 固定 HTTP route、精确 SQL 规则结果、授权 tmpfs 文件和默认拒绝的进程模拟。每个结果绑定项目/制品/扫描/任务、policy digest、sequence、provenance、executed、预算与 stop reason；完整 transcript 有稳定摘要。替身不允许外部转发、真实 JDBC URL、宿主路径或任意进程。

不受信制品的生产能力发布前必须具备最近 30 天内、由受信 verifier 验证的完整 P0 证据：网络、DNS、metadata、宿主挂载、Docker socket、非 root、只读根、capability、资源耗尽、trace 篡改、Agent 缺失与沙箱逃逸套件。当前仓库未执行真实 gVisor/Kata 逃逸测试；本地 `TRUSTED_DOCKER` 即使可用，也不能据此标记强化动态能力已通过发布门禁。

## 18. 有界 AI Job 与工具协议

- Provider 类型显式区分 `OPENAI_CHAT` 与 `ANTHROPIC_MESSAGES`，保留旧 `OPENAI_COMPATIBLE` 读取兼容。模型 inventory 仅表示远端发现结果，不证明工具、上下文窗口或 allowlist 能力，也不自动创建角色绑定。
- AI Job 创建必须显式 `authorized=true`，并固化项目、扫描、制品摘要、角色、Provider、模型、角色绑定版本、Provider kind/base URL/配置版本、`outputLanguage`、`outputFormat=MARKDOWN` 和资源预算。执行前再次比对扫描和配置；发生漂移即 fail-closed。
- 两类协议先转换为 canonical `ToolCall`。服务端固定注册表再检查角色 allowlist、scope、JSON schema/深度/字节、调用次数、deadline 和结果预算；模型字段不能携带权限、审批、网络、沙箱或租户覆盖。
- OpenAI 使用 strict function schema、`parallel_tool_calls=false` 和相邻 `role=tool` 结果；Anthropic 使用 `disable_parallel_tool_use=true` 和紧邻 `tool_result`。截断、过滤、拒绝、畸形参数、重复 ID、未知 block 或缺失结果均不执行工具。
- 生产传输只允许经过 Provider 边界验证的显式 HTTP(S) endpoint，禁止重定向，并限制连接、请求、响应和读取时间。为兼容受信内网网关可使用明文 HTTP，但这会暴露凭据与模型数据，公网部署应强制 HTTPS。凭据只在最短解密作用域内进入 header；响应原始字节在解析后清零。
- 当前工具只读取同一 project/artifact/scan 的入口、依赖、sink、静态证据和动态安全摘要，不能执行制品、联网、调用 shell、反编译或创建动态任务。持久化只保留状态、停止原因、请求 ID、耗时、轮次、工具决策摘要和脱敏截断的 `INFERENCE`。
- 真实 Provider 首轮互操作失败定位为 dotted function names 被 Provider 拒绝。代码侧名称固定改为 snake_case：`facts_search`、`evidence_get`、`plan_propose`；Provider 不能借此注册新工具或扩大角色 allowlist。
- SQLite V005 为单个 AI job 最多追加 128 条顺序事件：Provider 请求/结果仅保留协议、轮次、输出语言、限额、HTTP 状态、耗时、请求 ID、停止原因和工具数等有界元数据；工具参数只保留 shape/field count/encoded bytes，以及白名单化的事实类别、limit、合法证据引用、候选数量和原始敏感字段的存在/字节数，另存工具结果状态、脱敏截断的模型摘要和失败诊断。
- 事件接口不保存或返回 Provider 原始响应、API Key、完整工具参数、模型隐藏推理或 chain-of-thought。`modelInferenceSummary` 是经过脱敏和 16 KiB 截断的用户可见模型文本，不是推理轨迹，结论仍固定为 `INFERENCE`。
- 当前仍是本地单节点、进程内执行器，未完成真实供应商互操作、生产 egress/DNS rebinding 防护、流式协议、成本计量或多租户调度；Azure/LOCAL 聊天保持 disabled。

## 19. 静态信号与本地 Provider 兼容边界

- 类名包含 `File`、`Path`、`Exec` 等词不是 sink 事实。class-name 规则只对无法解析有效 classfile 元数据的对象降级启用；可正常解析的 Spring Boot loader、框架类和应用类不会仅凭名称生成 sink。
- 静态发现的 severity 表示排查优先级，不表示漏洞严重度。没有入口绑定的信号固定为 `info`；静态绑定的 file/command 信号最高为 `low`/`medium`，不得显示为 `high/critical`。
- OpenAI Chat 与 Anthropic Messages 接受显式 HTTP(S)，支持本机及 RFC1918/ULA 内网兼容网关；仍拒绝 userinfo、query、fragment、重定向、链路本地/metadata 和组播目标。该兼容能力不提供传输机密性：非本机 HTTP 的 API Key、模型输入和结果均可能被窃听。

## 20. Windows TRUSTED_DOCKER 开发运行时

Docker Desktop/WSL2 提供 Linux runc，但当前 runtime inventory 没有 runsc；本地运行时因此只声明 `TRUSTED_DOCKER`。`sandbox-pack` 只在 loopback 启动 registry，构建并推送包含固定 JVM Agent 的 digest-pinned runtime image；当前开发 Worker 使用 `LocalDockerTrustedSandboxClient` 直接执行后端管理的内部 JAR：

- public 动态请求 body 只允许 `authorized=true`；Control Plane 从不可变 scan 快照选择入口并从 artifact catalog 解析内容寻址副本，浏览器不能提供镜像、命令、路径、挂载或 capability；
- 执行前复核文件身份、大小、ZIP signature 和 SHA-256，只挂载一个目标 JAR 到固定 `/opt/veyrion/artifact/application.jar`，且 mount 为只读；
- 容器固定 `--network none`、只读 rootfs、专用有界 trace tmpfs、`65532:65532`、cap-drop ALL、no-new-privileges、PID/内存/CPU 限制；
- 容器创建后以 `docker inspect` 复核网络、mount、身份、rootfs、capability、tmpfs 和资源配置，并以非 root probe 验证 rootfs 不可写、trace tmpfs 可写；
- runtime 内以固定 `java -javaagent:... -jar /opt/veyrion/artifact/application.jar` 启动目标，`java.io.tmpdir` 指向有界 tmpfs，Agent class prefix 由 scan 入口声明类的包名派生，避免框架启动类淹没 trace。若进程存活，Agent helper 从同一容器访问目标 JVM loopback 入口；`--network none` 同时阻断外部 DNS 和外部网络，该 loopback probe 不会离开容器；
- Worker 仍通过独立 token 的 HTTP contract 拉取任务、租约、提交 trace 和完成任务；任何 Docker 或策略检查失败均 fail-closed，不存在宿主 Java fallback。

该 backend 是显式开发能力，不是 OpenSandbox 故障降级，也不是 gVisor/Kata 强化隔离。它只适用于操作员信任的内部 JAR；恶意或不受信制品的生产执行仍须部署到支持 runsc/Kata 的 Linux Worker 并通过 P0 release gate。本机真实 Docker 回归要求通过 `VEYRION_TEST_ARTIFACT_JAR` 显式提供后端管理的可执行测试 JAR，覆盖 public 排队、断网运行、loopback HTTP、不可变 trace commit 和 dashboard `DYNAMIC_SUSPECTED` 投影。

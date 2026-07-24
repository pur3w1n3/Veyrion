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
- `FIXTURE_RUNC`：普通 runc，仅可运行仓库内受控测试 fixture；
- `HARDENED_GVISOR`：通过 gVisor 运行时自检和安全门槛；
- `HARDENED_KATA`：通过 Kata/微虚拟机运行时自检和安全门槛。

Windows 可作为 Control Plane 和开发宿主，动态任务运行在 OpenSandbox 管理的 Linux Worker。普通 Docker/runc 不能作为恶意闭源制品的安全边界；只有强化运行时完成网络/DNS、宿主路径、非 root、只读根、资源耗尽和逃逸测试后，才允许外部制品执行。在此之前 health 必须报告 `DYNAMIC_DISABLED`，失败时退回静态分析而不是降级到不安全执行。

Worker 与 Control Plane 之间只交换版本化合约。每个任务、租约、checkpoint 和 trace chunk 都绑定 `projectId`、`artifactDigest`、`scanId`、`taskId`，运行时轨迹以 SHA-256 前序摘要链追加提交。GUI token、Worker token、OpenSandbox API key 和沙箱内凭据相互隔离；任何来自制品、模型或前端的字段都不能修改运行时能力等级、网络策略或挂载范围。

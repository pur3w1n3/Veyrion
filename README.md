# 溯脉 · Veyrion

JVM 应用安全验证平台（本地首版）

产品正式名称为 **溯脉 · Veyrion**（英文：**Veyrion**）。现有 `com.aq.jvmsentinel` 包名、Maven artifactId、内部 service name 和 API 兼容标识暂不变，避免破坏已有调用方。商标、域名和公司名称尚未完成正式检索。

主 Control Plane 是 Java 17 本地分析服务，使用 SQLite JDBC 持久化并以 AES-256-GCM 加密 Provider 凭据。它登记 JAR/WAR/CLASS、计算 SHA-256、校验扫描策略，并以有界 classfile 解析识别 Spring MVC/权限注解以及方法、字段、调用点和保守调用边。浏览器上传的制品会在完整校验后进入内容寻址受控目录；旧路径登记仅作为本地兼容入口。另有独立 JVM Agent、可插拔 OpenSandbox Worker 适配器和显式启用的本地 `TRUSTED_DOCKER` Worker；本地 Docker 路径只执行后端管理并重新校验摘要的内部 JAR，不接受浏览器提供的镜像、命令、路径或能力。

## 构建

需要 Java 17+ 和 Maven：

Windows 本地开发可在仓库根目录一键启动后端和 Vite 前端：

```powershell
.\Start-Veyrion.ps1
```

脚本会创建 `samples/`、按需安装前端依赖、解析运行时 classpath、编译 Java、初始化/恢复 SQLite、复用本地项目并启动两个 loopback 服务。默认 GUI 为 `http://127.0.0.1:5173`，Control Plane 为 `http://127.0.0.1:18080/api/v1`；按 `Ctrl+C` 一并停止。可用 `-Artifacts`、`-BackendPort`、`-FrontendPort` 覆盖默认值，但制品目录必须位于工作区内。状态默认保存在 `<Artifacts>/.veyrion/`（默认即 `samples/.veyrion/control-plane.db`）。

若 Control Plane 因 `database migration checksum mismatch` 拒绝启动：表示已应用的迁移文件被改写，校验故意 fail-closed。本地开发可先备份再重建 SQLite（不要在生产库上跳过校验）：

```powershell
$dbDir = 'samples\.veyrion'
Copy-Item "$dbDir\control-plane.db" "$dbDir\control-plane.db.bak-$(Get-Date -Format yyyyMMddHHmmss)"
Remove-Item "$dbDir\control-plane.db","$dbDir\control-plane.db-wal","$dbDir\control-plane.db-shm" -ErrorAction SilentlyContinue
```

然后重新运行 `.\Start-Veyrion.ps1`；全新库会按当前迁移顺序初始化。已应用迁移文件本身不得再改写，schema 变更只能追加新的 `V00N__*.sql`。

如果系统默认 `java` 低于 17，可直接指定 JDK，不需要手工修改 PowerShell 环境变量：

```powershell
.\Start-Veyrion.ps1 -JavaHome 'E:\AQ\jdk\jdk-17.0.11'
```

```powershell
mvn '-Dmaven.repo.local=.m2' test
mvn -q '-Dmaven.repo.local=.m2' dependency:build-classpath '-Dmdep.outputFile=target/runtime-classpath.txt'
$cp = 'target/test-classes;target/classes;' + (Get-Content -Raw target/runtime-classpath.txt).Trim()
java -ea -cp $cp com.aq.jvmsentinel.ManagementConfigurationAcceptanceTest
java -ea -cp $cp com.aq.jvmsentinel.ControlPlanePersistenceAcceptanceTest
java -ea -cp $cp com.aq.jvmsentinel.BytecodeFactIndexAcceptanceTest
java -ea -cp $cp com.aq.jvmsentinel.ControlPlaneAcceptanceTest
```

`mvn test` 负责完整编译，但当前 main-style 验收类仍需显式运行其 `main` 方法。

## CLI

未授权运行会被拒绝；授权参数只代表用户确认范围，不会打开外网或危险操作：

```powershell
java -cp target/classes com.aq.jvmsentinel.cli.Main C:\path\to\sample.jar --authorize
```

输出包含 artifact、EntryCatalog、DependencyMap、SinkCatalog 和版本化事件/幂等键的 JSON 摘要。JAR/WAR 只在内存中有界读取 ZIP 条目、classfile 注解、调用指令和配置文本，不解压到磁盘；单独 CLASS 标记为 `staticOnly=true`。Spring Boot 的 `BOOT-INF/classes` 与 WAR 的 `WEB-INF/classes` 会归一化为 JVM 类名。敏感调用按 target owner + method（必要时 descriptor）匹配，不使用裸 `parse/read/execute` 关键词。

当前注解能力识别 `Controller`、`RestController`、`RequestMapping`、五种 HTTP shortcut mapping，合并类/方法路径并提取 HTTP method；同时提取常见请求参数注解的位置/名称候选，以及 `PreAuthorize`、`Secured`、`RolesAllowed` 前置条件。classfile 中真实存在的注解证据为 `FACT`，入口仍固定为 `STATIC_INFERRED`，因为尚未观察 Spring 运行时注册。

解析边界为：单 class 最大 4 MiB、class 总读取量最大 64 MiB、最多 20,000 个 class 条目、最多 100,000 个归档文件条目；另有常量池、成员、属性、注解和值数量/深度上限。超限会受控拒绝，局部畸形 class 会安全降级为旧类名规则。已成功解析但没有有效映射的类不会因名称含 `Controller` 被制造成入口。

## Control Plane REST/SSE

完整阶段顺序和分支见 [审计流程图与阶段契约](docs/AUDIT_FLOW.md)。

Control Plane 已完成本地 SQLite 首版，路由前缀为 `/api/v1`。静态扫描不会执行 JAR/WAR/CLASS。显式启用本地 Docker runtime 后，动态入口会把当前 scan 的后端管理可执行 Spring Boot JAR 排队到 `TRUSTED_DOCKER` Worker；生产方向仍是通过 P0 release gate 的独立 Linux gVisor/Kata Worker。

启动：

```powershell
java -cp "<target/classes + Maven runtime dependencies>" com.aq.jvmsentinel.control.ControlPlaneMain --root C:\path\to\authorized-artifacts --port 18080 --token local-demo
```

Windows Docker Desktop 本地动态调试：

```powershell
.\Start-Veyrion.ps1 -JavaHome 'E:\path\to\jdk-17' -WithDockerRuntime
```

首次执行会启动 loopback registry，构建并推送包含固定 JVM Agent 的 digest-pinned runtime image，然后启动 GUI、Control Plane 与本地 artifact Worker；后续启动复用镜像，Agent/runtime 源码变化时增加 `-RebuildRuntimeImage`。真实 Docker 验收保留 `VEYRION_DOCKER_RUNTIME_IMAGE` 作为 digest-pinned runtime image 输入，并通过 `VEYRION_TEST_ARTIFACT_JAR` 显式指定后端管理的 executable Spring Boot 测试 JAR，覆盖容器内 loopback HTTP、Agent JSONL、不可变 trace commit 与 dashboard 投影。

GUI 在静态扫描后可显式授权执行该 scan 对应的后端管理 JAR。Control Plane 只接受 `authorized=true`，运行时镜像、命令、挂载和 capability 均由后端固定。个人本地 `TRUSTED_DOCKER` 保留 `--network none`、单个只读 artifact mount、资源上限和专用 trace tmpfs，但不强制只读 rootfs 或非 root，允许受信应用写日志和完成 root 启动检查；容器内 Agent 记录 HTTP、Socket、URL、DNS 和 JNDI 尝试，`--network none` 负责阻断外部连接。AI 的 `sandbox_probe` 工具只能提交已有入口引用，由服务端按固定计划发包并保存结果。该 runc 模式便于本地受信调试，不是安全运行恶意 JAR 的强化边界，且没有宿主 Java fallback。

主要路由：

- `GET /api/v1/health`：默认返回 `persistenceMode=SQLITE`、`analysisMode=STATIC_METADATA_ONLY` 和动态能力边界。
- `GET|POST /api/v1/projects`、`GET|PATCH|DELETE /api/v1/projects/{projectId}`：项目列表、创建、更新和软删除。
- `POST|GET /api/v1/projects/{projectId}/artifacts`：登记或列出受控根目录内的制品。
- `GET /api/v1/projects/{projectId}/entries`：查询入口清单。
- `POST|GET /api/v1/projects/{projectId}/scans`：创建或列出静态前置分析扫描。
- `POST /api/v1/projects/{projectId}/audit-runs`：推荐的主流程入口；同一请求内完成静态扫描并创建绑定该不可变 `scanId` 的 `PRE_ANALYSIS` Job。必须分别提交 `authorized:true` 与 `aiAuthorized:true`，并携带 `Idempotency-Key`。
- `GET /api/v1/scans/{scanId}`、`GET /api/v1/scans/{scanId}/paths`、`GET /api/v1/scans/{scanId}/paths/{pathId}`、`GET /api/v1/scans/{scanId}/findings`：查询扫描、路径、发现和静态证据。
- `GET /api/v1/scans/{scanId}/events`：SSE 事件流。
- `POST /api/v1/scans/{scanId}/dynamic-tasks`：显式授权排队当前 scan 的后端管理可执行 JAR；body 只接受 `authorized`，不能提供镜像、命令、路径、挂载或能力。
- `GET /api/v1/projects/{projectId}/dashboard`、`GET /api/v1/projects/{projectId}/evidence`、`GET /api/v1/scans/{scanId}/evidence`：仪表盘和证据。
- `GET /api/v1/findings/{findingId}`、`POST /api/v1/findings/{findingId}/replay`、`GET /api/v1/attack-chains`：发现、受控动态重放和攻击链查询。finding replay 必须显式 `authorized:true` 并携带幂等键；服务端只创建固定策略的沙箱任务，完成前后均不会直接升级为 `VERIFIED`。
- `GET|POST /api/v1/providers`、`PATCH|DELETE /api/v1/providers/{providerId}`：管理 Provider；API Key 只以加密形式保存在后端，响应不返回明文或密文。
- `POST /api/v1/providers/{providerId}/models/refresh`：按受管凭据获取 OpenAI/Anthropic 模型 inventory；结果不自动启用或绑定，GET 不触发外部请求。
- `GET|PATCH|DELETE /api/v1/projects/{projectId}/role-assignments[/role]`：为前置建模、动态验证、路径探索、漏洞研判和报告生成分配 Provider/模型。
- `GET|POST /api/v1/projects/{projectId}/ai-jobs`、`GET|PATCH|DELETE /api/v1/ai-jobs/{jobId}`：显式授权后运行有界 AI Job、查询状态或取消；运行中任务必须先取消才能删除。
- `GET /api/v1/ai-jobs/{jobId}/events`：查询最多 128 条按序 AI Job 审计事件；仅包含有界元数据、工具决策、脱敏模型摘要和失败诊断。
- `GET|POST /api/v1/operators`、`PATCH /api/v1/operators/{operatorId}`、`GET /api/v1/audit-events`：本地 PAT、RBAC 和脱敏审计。

最小产品顺序是“选择工作区 → 上传或兼容登记制品 → 显式授权启动静态事实/入口发现 → 前置建模 → 授权沙箱动态观察 → 动态验证/loopback 本地发包 → 路径探索 → 漏洞研判 → 报告生成”。GUI 默认使用文件选择器和分块上传；旧的路径登记仅用于 Control Plane 能直接访问该路径的兼容场景：

```http
POST /api/v1/projects
X-Sentinel-Authorization: local-demo
Idempotency-Key: project-demo-1
{"name":"authorized-sample"}

POST /api/v1/projects/{projectId}/artifacts
X-Sentinel-Authorization: local-demo
Idempotency-Key: artifact-demo-1
{"path":"C:\\authorized-artifacts\\sample.jar"}

POST /api/v1/projects/{projectId}/audit-runs
X-Sentinel-Authorization: local-demo
Idempotency-Key: audit-demo-1
{"artifactDigest":"<sha256>","authorized":true,"aiAuthorized":true,"networkMode":"DENY","dangerousActionMode":"DRY_RUN"}
```

浏览器上传协议为 `POST /projects/{projectId}/artifact-uploads` 初始化、带 `offset` 与 `X-Chunk-SHA256` 的顺序 `PUT` 分块、`POST .../{uploadId}/complete` 完成或 `DELETE` 取消。后端限制会话、声明总量、TTL 和单块 4 MiB，复核扩展名、大小、每块摘要、完整 SHA-256 与 JAR/WAR ZIP 结构，然后原子安装到 `.veyrion/artifacts/sha256/<prefix>/<digest>.<ext>`；项目和后续扫描只引用该受控副本。V008 将上传会话元数据、偏移和过期时间持久化到本地 SQLite，控制面重启后会校验并恢复合法 `.part`，无记录孤儿分片会被清理。

写操作要求 `X-Sentinel-Authorization: <token>`，也接受 `Authorization: Bearer <token>`。扫描请求必须在 body 中显式 `authorized: true`；组合审计还必须独立提交 `aiAuthorized:true`，令牌认证不等于扫描或远端 AI 授权同意。制品登记可选传入 `authorized`，但显式 `false` 会拒绝。写操作建议携带 `Idempotency-Key`；V011 起，项目创建、制品创建、扫描创建、组合审计（audit-run）创建、动态任务创建、finding replay，以及 AI `sandbox_probe` job 绑定均按作用域写入 SQLite 并跨重启复用。相同键和相同 payload 返回原资源；相同键提交不同 payload 返回 409。组合审计重放返回原始 scan/job，不会重复创建 PRE_ANALYSIS。非法、空白或超过 256 字符的键会被拒绝；幂等记录最多 50,000 条，达到上限会 fail-closed 返回 429。

SSE 客户端通过 `Last-Event-ID` 请求头断线续接。事件包含 `id`、`event`、`data`，并携带项目/制品/扫描上下文、`schemaVersion`、`verificationStatus`、`dependencyMode` 和 `evidenceRefs`。SSE 仅作增量提示，断线或终态后必须以 `GET /api/v1/scans/{scanId}` 等幂等查询为准；终态事件包括 `ScanCompleted` 或 `TaskStopped`。

当前限制：默认启动器只绑定 loopback；项目、制品元数据、扫描结果、Provider、角色、AI job、AI job event、审计、Worker 任务、租约、checkpoint、trace chunk、上传会话、SSE 历史、幂等记录、流水线 cursor 和 probe plan 元数据已进入 SQLite。`audit_pipeline_runs` 会保存下一阶段与 `armed` 状态；控制面重启后会从持久化任务和 cursor 恢复阶段，重启前的 `QUEUED/RUNNING` AI job 保留为 `FAILED/PROCESS_RESTARTED`，再创建新的阶段 job，不改写旧记录。`dynamic_probe_plans` 只保存 task/scan/entry、候选输入、请求上限和 plan hash 等有界元数据，不携带命令或授权。上述恢复是单节点 SQLite 语义，不是分布式 exactly-once；删除、修改等其他 mutation 尚未全部纳入统一持久化幂等。操作员是本地 PAT/RBAC，尚无 SSO、HttpOnly session 或多租户隔离。字节码调用边是无 classpath 展开的保守事实，不是完整数据流。OpenAI Chat/Anthropic Messages 已支持 inventory 与有界工具循环，但仍是本地单节点首版，未完成生产出站网关验收；模型结论只允许 `INFERENCE`。Windows Docker Desktop `TRUSTED_DOCKER` 是显式 runc 调试能力，不是 gVisor/Kata；动态结果固定为 `DYNAMIC_SUSPECTED`，不得用于不受信或恶意制品的生产执行。

静态 class-name 规则只在 classfile 无法正常解析时作为降级信号；有效 Spring Boot loader/framework 类不会再因名称包含 `File`、`Path`、`Exec` 等词生成 sink。Java checklist 增量覆盖命令/原生库、反序列化、表达式/模板、JNDI、反射/类加载、SQL/NoSQL/LDAP/XML、文件和 SSRF 等调用，但每项仍只是调用事实。入口与 sink 只有在 annotation 和 call evidence 的 caller `class#method` 一致时才进入同一路径；不会把所有 sink 复制到每个入口。未绑定信号为 `info`，已绑定静态候选最高 `medium`，低置信度条件性 API 最高 `low`。

OpenAI/Anthropic Provider 接受显式 `http://` 或 `https://` Base URL，便于连接本机和内网兼容网关；仍拒绝 userinfo、query、fragment、重定向、链路本地/metadata 和组播目标。非本机 HTTP 会明文传输 API Key、模型输入和结果，只应连接受信内网网关，公网必须优先使用 HTTPS。

首轮真实 Provider 工具调用失败的根因是带点号的函数名被 Provider 拒绝。内置工具现统一使用兼容的 snake_case 名称：`facts_search`、`evidence_get`、`plan_propose`；改名不扩大服务端 allowlist、作用域或权限。AI Job event 只保存 Provider 请求/结果元数据、工具参数形状与字节数、工具结果状态、脱敏截断的最终模型摘要和失败诊断；不保存 Provider 原始响应、秘密、隐藏推理或 chain-of-thought。

OpenAI-compatible 思考模型可能要求在工具后续轮次回传专用 `reasoning_content`。该字段只作为有界、不可信的内存 wire token 原样回传给同一 Provider，不进入工具、事件、数据库或最终报告。工具阶段最多 16 次只读调用；进入收束阶段后请求不再携带工具定义，只允许模型基于已返回的静态/动态安全摘要生成最终 `INFERENCE`。结果页展示当前 scan 的报告摘要，但不会渲染模型 HTML 或把它升级为 `VERIFIED`。

全局设置可选择新 AI Job 使用简体中文或 English，默认 `ZH_CN`；语言与 `MARKDOWN` 输出格式固化在 Job policy snapshot 中，旧报告保持不可变。报告模板要求入口—触发点矩阵、多条证据化推测链路、组合漏洞可能性、动态覆盖与限制。AI 审计页的可展开流向只显示服务端持久化的 Provider/工具决策摘要和结果，不记录或还原隐藏思维链；原始 query、候选 payload、Provider 响应和凭据不会进入审计事件。

GUI 采用 React/TypeScript，默认亮色并支持持久化暗色主题。左上角全局工作区控件直接完成项目选择/创建/删除；“审计执行”统一承载制品导入、静态事实、前置建模和后续阶段时间线；“模型服务”通过已保存 API 侧边栏管理 Provider、模型清单和五角色绑定，并可分别编辑中文提示词与 English prompt，但不直接创建任务；“AI 审计过程”只展示当前扫描的有界执行事件。真实模式失败不会伪造成功或回退 Demo。

前端原型位于 `frontend/`：

```powershell
cd frontend
npm install
npm run build
```

仅在明确需要演示数据时设置 `VITE_DEMO_MODE=true`。接入真实 Control Plane 时设置：

```dotenv
VITE_DEMO_MODE=false
VITE_API_BASE_URL=http://127.0.0.1:8080/api/v1
VITE_PROJECT_ID=project-01
VITE_API_TOKEN=local-demo
```

真实模式连接失败不会静默回退到 Mock；浏览器只访问 Control Plane，不直接读取制品、数据库、沙箱或模型。

## 打包方向

最终交付采用“各平台自包含 Desktop Core + 可选 Sandbox Pack”，而不是要求所有用户安装 Docker：

- Desktop Core 使用 `jlink + jpackage`，分别构建 Windows EXE/MSI、macOS DMG/PKG、Linux DEB/RPM/便携包；内置 Java runtime，React 构建产物由本地 Control Plane 提供。
- 本地 Sandbox Pack 使用 Docker Compose 提供 loopback registry 和 digest-pinned Agent runtime image；生产 Sandbox Pack 仍需另行提供通过发布门禁的独立 Linux gVisor/Kata Worker。缺少 Docker 时静态审计仍可用，动态能力保持 disabled。
- GraalVM Native Image 待 DTO、反射和插件边界稳定后再评估，不作为首发唯一产物。

## Spring Boot JAR 动态分析边界

仓库已实现首版内部执行与证据契约，并通过受限动态任务 API 排队：

- `ExternalArtifactTaskExecutor` 只接受后端 artifact catalog 内、执行前重新校验文件身份/大小/ZIP signature/SHA-256 的可执行 Spring Boot JAR；运行时镜像、Agent、命令、挂载和 capability 不能由浏览器提供。
- 本地显式 `TRUSTED_DOCKER` 固定断网、制品只读挂载和资源策略，rootfs/UID 为受信应用兼容性选项；Agent 会记录网络/DNS 尝试，但该模式仍不是强化隔离。面向不受信制品的生产能力仍只允许通过版本化 P0 release evidence gate 的 `HARDENED_GVISOR`/`HARDENED_KATA`。
- 独立 Agent 使用启动期 Byte Buddy 插桩观测 Spring/Servlet、JDBC、HTTP client、文件和进程调用；事件回指 caller method descriptor 与调用序号，仍统一为 `DYNAMIC_SUSPECTED`。
- 静态事实索引额外产出制品内 `DIRECT`/`CHA`/`UNRESOLVED` 调用图，以及入口参数到敏感调用的有界跨方法污点候选。结果带调用图/污点预算、停止原因和不完整标记；分支合流、反射、代理、JNI、制品外 classpath 与运行时注册仍不能被静态解析。
- HTTP、JDBC、Redis 和数据库协议替身具有固定规则、来源、预算、脱敏 transcript 和完整摘要；Redis 使用有界 RESP2/RESP3 loopback 子集，检测到 MySQL Connector/J 时使用有界 MySQL Classic loopback 子集，未知命令和超预算请求 fail-closed。进程默认拒绝。Vineflower/CFR 和 AI harness 当前只有安全 Worker/命令/结果契约，未捆绑真实反编译器或启用模型调用。
- 动态任务、租约、checkpoint、trace chunk、幂等提交、流水线 cursor 和 probe plan 元数据已进入 SQLite；控制面重启会把未完成租约恢复为可重新领取状态，并从已提交 trace 重建投影。流水线恢复会保留旧的 `FAILED/PROCESS_RESTARTED` job，并为下一阶段创建新 job。该能力是单节点协调，不是分布式 exactly-once 队列；并非所有 mutation 都已纳入持久化幂等。
- 本地 `LocalDockerDynamicLoopAcceptanceTest` 曾在用户授权的 Docker Desktop Linux engine 中通过，覆盖固定 runtime digest、断网、只读制品挂载、loopback 探针、Agent trace 和 dashboard 投影；当前 rootfs/UID 兼容策略调整后的回归需重新执行，这只代表受信内部 JAR 的 `TRUSTED_DOCKER` 开发验收。
- 双次重放必须绑定原始 JAR、Agent、运行时镜像、harness、替身 transcript 和 trace 摘要；匹配结果也只形成候选动态证据，不自动升级为 `VERIFIED`。

## 明确未实现

- 没有 gVisor/Kata 强化运行时验收、真实反编译器镜像、完整数据库协议实现或真实漏洞利用；当前协议替身只覆盖有界 Redis RESP2/RESP3 与 MySQL Classic 启动/常见查询子集，`TRUSTED_DOCKER` 仍仅为显式本地 Docker runc 调试后端；
- 没有真实供应商互操作、生产出站代理、成本计量或流式聊天验收；当前 AI Job 仅支持 OpenAI Chat/Anthropic Messages 的非流式有界工具循环，Azure/LOCAL 聊天保持阻断；
- 没有生产级 SSO/session、多租户隔离或完整审计防篡改链；Worker/trace 已具备本地 SQLite 恢复语义，但仍不是多节点持久化队列或生产级租约服务；

### 个人本地版边界

Veyrion 当前服务个人用户的本地分析与验证工作流。完整多租户/RBAC、企业 SSO、跨租户调度以及真实供应商生产互操作明确不在当前产品范围内。动态测试必须提交到用户明确授权的沙箱；沙箱不可用时保持 `DYNAMIC_DISABLED` 或静态结果，绝不回退到宿主机直接执行制品。
- 注解入口、classfile 调用 sink 和类名降级推断均为 `STATIC_INFERRED`；跨方法污点也是静态候选，权限只作为前置条件保留，调用存在也不证明入参可控、运行时可达、配置不安全或漏洞已验证。

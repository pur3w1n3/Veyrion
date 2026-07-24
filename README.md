# 溯脉 · Veyrion

JVM 应用安全验证平台（M0/M1 与 Control Plane MVP slice）

产品正式名称为 **溯脉 · Veyrion**（英文：**Veyrion**）。现有 `com.aq.jvmsentinel` 包名、Maven artifactId、内部 service name 和 API 兼容标识暂不变，避免破坏已有调用方。商标、域名和公司名称尚未完成正式检索。

主 Control Plane 是 Java 17、无运行时第三方依赖的本地分析切片。它登记 JAR/WAR/CLASS、计算 SHA-256、校验扫描策略，并以有界 classfile 解析识别常见 Spring MVC 与权限注解。另有独立 JVM Agent、OpenSandbox Worker 适配器和仓库内受控 Spring fixture；普通 runc 只允许该 fixture，绝不执行用户导入制品。
M0 使用受控目录中的原文件并在分析前复核摘要；生产版需要改为内容寻址的只读制品存储。

## 构建

需要 Java 17+ 和 Maven：

Windows 本地开发可在仓库根目录一键启动后端和 Vite 前端：

```powershell
.\Start-Veyrion.ps1
```

脚本会创建 `samples/`、按需安装前端依赖、编译 Java、创建本地项目并启动两个 loopback 服务。默认 GUI 为 `http://127.0.0.1:5173`，Control Plane 为 `http://127.0.0.1:8080/api/v1`；按 `Ctrl+C` 一并停止。可用 `-Artifacts`、`-BackendPort`、`-FrontendPort` 覆盖默认值，但制品目录必须位于工作区内。

如果系统默认 `java` 低于 17，可直接指定 JDK，不需要手工修改 PowerShell 环境变量：

```powershell
.\Start-Veyrion.ps1 -JavaHome 'E:\AQ\jdk\jdk-17.0.11'
```

```powershell
mvn -q '-Dmaven.repo.local=.m2' '-Dmaven.test.skip=true' package
mvn -q '-Dmaven.repo.local=.m2' test-compile
java -ea -cp 'target/test-classes;target/classes' com.aq.jvmsentinel.AcceptanceTest
java -ea -cp 'target/test-classes;target/classes' com.aq.jvmsentinel.ClassfileAnnotationAcceptanceTest
java -ea -cp 'target/test-classes;target/classes' com.aq.jvmsentinel.ControlPlaneAcceptanceTest
java -ea -cp 'target/test-classes;target/classes' com.aq.jvmsentinel.FixtureDynamicLoopAcceptanceTest
java -ea -cp 'target/test-classes;target/classes' com.aq.jvmsentinel.DynamicTraceProjectionAcceptanceTest
```

当前测试使用依赖无关的可执行检查（Maven 负责编译，避免引入测试运行时依赖）。
如果本机 Surefire 缓存目录权限正常，也可以额外运行 `mvn test`；它不是当前验收检查的唯一入口。

## CLI

未授权运行会被拒绝；授权参数只代表用户确认范围，不会打开外网或危险操作：

```powershell
java -cp target/classes com.aq.jvmsentinel.cli.Main C:\path\to\sample.jar --authorize
```

输出包含 artifact、EntryCatalog、DependencyMap、SinkCatalog 和版本化事件/幂等键的 JSON 摘要。JAR/WAR 只在内存中有界读取 ZIP 条目、classfile 注解和配置文本，不解压到磁盘；单独 CLASS 标记为 `staticOnly=true`。Spring Boot 的 `BOOT-INF/classes` 与 WAR 的 `WEB-INF/classes` 会归一化为 JVM 类名。

当前注解能力识别 `Controller`、`RestController`、`RequestMapping`、五种 HTTP shortcut mapping，合并类/方法路径并提取 HTTP method；同时提取常见请求参数注解的位置/名称候选，以及 `PreAuthorize`、`Secured`、`RolesAllowed` 前置条件。classfile 中真实存在的注解证据为 `FACT`，入口仍固定为 `STATIC_INFERRED`，因为尚未观察 Spring 运行时注册。

解析边界为：单 class 最大 4 MiB、class 总读取量最大 64 MiB、最多 20,000 个 class 条目、最多 100,000 个归档文件条目；另有常量池、成员、属性、注解和值数量/深度上限。超限会受控拒绝，局部畸形 class 会安全降级为旧类名规则。已成功解析但没有有效映射的类不会因名称含 `Controller` 被制造成入口。

## Control Plane REST/SSE MVP

Control Plane 已完成一个本地、内存存储的 MVP slice，路由前缀为 `/api/v1`。静态扫描不会执行 JAR/WAR/CLASS。动态入口只会排队代码白名单中的 digest-pinned fixture；执行由独立 Linux Worker 经 OpenSandbox 完成。

启动：

```powershell
java -cp target/classes com.aq.jvmsentinel.control.ControlPlaneMain --root C:\path\to\authorized-artifacts --port 8080 --token local-demo
```

主要路由：

- `GET /api/v1/health`：返回 `persistenceMode=IN_MEMORY_MVP`、`analysisMode=STATIC_METADATA_ONLY` 和 `dependencyMode=MOCK`。
- `POST /api/v1/projects`、`GET /api/v1/projects/{projectId}`：创建/查询项目。
- `POST|GET /api/v1/projects/{projectId}/artifacts`：登记或列出受控根目录内的制品。
- `GET /api/v1/projects/{projectId}/entries`：查询入口清单。
- `POST|GET /api/v1/projects/{projectId}/scans`：创建或列出静态前置分析扫描。
- `GET /api/v1/scans/{scanId}`、`GET /api/v1/scans/{scanId}/paths`、`GET /api/v1/scans/{scanId}/paths/{pathId}`、`GET /api/v1/scans/{scanId}/findings`：查询扫描、路径、发现和静态证据。
- `GET /api/v1/scans/{scanId}/events`：SSE 事件流。
- `POST /api/v1/scans/{scanId}/dynamic-tasks`：显式授权排队受控 fixture；请求不能提供镜像、命令、路径或能力。
- `GET /api/v1/projects/{projectId}/dashboard`、`GET /api/v1/projects/{projectId}/evidence`、`GET /api/v1/scans/{scanId}/evidence`：仪表盘和证据。
- `GET /api/v1/findings/{findingId}`、`POST /api/v1/findings/{findingId}/replay`、`GET /api/v1/attack-chains`：当前静态发现/演示链查询；replay 仍是受限的元数据重放语义。

最小调用顺序是“创建项目 → 登记制品 → 显式授权创建扫描”；制品路径只对 Control Plane 可见，浏览器不会读取文件内容：

```http
POST /api/v1/projects
X-Sentinel-Authorization: local-demo
Idempotency-Key: project-demo-1
{"name":"authorized-fixture"}

POST /api/v1/projects/{projectId}/artifacts
X-Sentinel-Authorization: local-demo
Idempotency-Key: artifact-demo-1
{"path":"C:\\authorized-artifacts\\sample.jar"}

POST /api/v1/projects/{projectId}/scans
X-Sentinel-Authorization: local-demo
Idempotency-Key: scan-demo-1
{"artifactDigest":"<sha256>","authorized":true,"networkMode":"DENY","dangerousActionMode":"DRY_RUN"}
```

写操作要求 `X-Sentinel-Authorization: <token>`，也接受 `Authorization: Bearer <token>`。扫描请求必须在 body 中显式 `authorized: true`；制品登记可选传入 `authorized`，但显式 `false` 会拒绝。令牌认证不等于授权同意。写操作建议携带 `Idempotency-Key`，项目、制品和扫描创建会在内存窗口内按作用域去重；非法、空白或超过 256 字符的键会被拒绝。每类幂等键最多保留 50,000 个，达到上限会 fail-closed 返回 429。

SSE 客户端通过 `Last-Event-ID` 请求头断线续接。事件包含 `id`、`event`、`data`，并携带项目/制品/扫描上下文、`schemaVersion`、`verificationStatus`、`dependencyMode` 和 `evidenceRefs`。SSE 仅作增量提示，断线或终态后必须以 `GET /api/v1/scans/{scanId}` 等幂等查询为准；终态事件包括 `ScanCompleted` 或 `TaskStopped`。

当前限制：默认启动器只绑定 loopback；数据、任务和 trace 仅在进程内存中；无多租户/RBAC/持久化、真实字节码调用图、LLM 或真实依赖连接。动态闭环目前仅为受控 Spring fixture，结论固定为 `DYNAMIC_SUSPECTED`；没有已发布镜像，真实 OpenSandbox 运行仍需运维方构建并配置仓库 digest。外部制品动态执行保持禁用。

GUI 采用独立的 React/TypeScript 前端，已支持真实 Control Plane DTO/SSE 和显式 DEMO/MOCK 两种模式；设计和接口约束见 [docs/GUI_DESIGN.md](docs/GUI_DESIGN.md)。

前端原型位于 `frontend/`：

```powershell
cd frontend
npm install
npm run build
```

默认建议在本地演示时显式设置 `VITE_DEMO_MODE=true`。接入真实 Control Plane 时设置：

```dotenv
VITE_DEMO_MODE=false
VITE_API_BASE_URL=http://127.0.0.1:8080/api/v1
VITE_PROJECT_ID=project-01
VITE_API_TOKEN=local-demo
```

真实模式连接失败不会静默回退到 Mock；浏览器只访问 Control Plane，不直接读取制品、数据库、沙箱或模型。

## 明确未实现

- 没有用户导入制品的动态执行、强化运行时发布认证、数据库/HTTP 真实替身或真实漏洞利用；
- 没有 LLM 调用；前置分析仅为受限 classfile 注解解析和确定性辅助规则，不是完整框架建模；
- GUI 的真实 DTO/SSE 接入已完成 MVP slice，但尚未达到生产级身份、持久化、多租户和审计要求；
- 注解入口和类名推断的入口/sink 均为 `STATIC_INFERRED`；权限只作为前置条件保留，不能据此声称匿名可达、权限绕过或漏洞已验证。

## 受控动态 Fixture

`fixtures/http-entry/` 提供 Spring Boot 4.1.0 一次性 fixture、容器构建脚本和镜像配置说明。默认 catalog 使用 `registry.invalid`；只有运维方显式配置真实、digest-pinned 的 `VEYRION_HTTP_ENTRY_SMOKE_V1_IMAGE_URI` 后才可能执行。Worker 还要求 `FIXTURE_RUNC`、deny-all 网络、非 root、只读根和 `writable-tmp-v1` attestation。完整命令见 [fixture README](fixtures/http-entry/README.md)。

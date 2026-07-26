# 溯脉 · Veyrion GUI 设计规范

产品正式名称为“溯脉 · Veyrion”（英文：Veyrion）。前端显示使用该品牌；Java 内部包名 `com.aq.jvmsentinel`、Maven artifactId、内部 service name 和 `/api/v1` 路由保持兼容。商标和域名仍需法务检索。

## 1. 设计结论

**个人本地版边界**：GUI 只承载本地项目、制品、扫描、证据和沙箱任务。当前不提供多租户切换、企业 RBAC/SSO 或真实供应商生产连接入口；Provider 和动态能力均须显示本地授权与沙箱状态，沙箱不可用时明确显示不可用，而不是提供宿主机执行按钮。

模型服务页的**六个**角色卡片（前置建模、鉴权分析、动态验证、路径探索、漏洞研判、报告生成）同时提供中文提示词和 English prompt 编辑器。保存时由后端校验长度、控制字符和项目作用域；任务创建时固化提示词快照。审计执行页按以下顺序显示阶段（与 [AUDIT_FLOW.md](AUDIT_FLOW.md) 一致）：

- 前置建模 → 鉴权分析 → 沙箱按轨动态观察 → 鉴权绕过确认 → 动态验证 → 路径探索 → 漏洞研判 → 报告生成

结果页主视图应以 **PathRun 会话**（入口 × 身份轨 × 尝试）组织，展示超时分类码、HTTP/Agent/SQL 摘要与合成身份前置条件；`AUTH_GAP` 与 `DYNAMIC_CONFIRMED` 等状态可筛选。筛选选项包含 `STATIC_INFERRED` / `DYNAMIC_SUSPECTED` / `DYNAMIC_CONFIRMED` / `VERIFIED` / `UNREACHED`。

GUI 不采用 Swing、JavaFX 或把页面嵌入 Java 进程。Java 负责 JVM 制品分析、任务编排、证据和沙箱控制；GUI 作为独立的 React/TypeScript 应用，通过受控 API 访问后端。

推荐形态：

```text
React + TypeScript GUI
        │ REST / SSE（或 WebSocket）
Java/Kotlin Control Plane
        │
本地 Worker / 私有化沙箱
```

企业桌面版可以在第二阶段使用 Tauri 2 包装同一套前端，将控制面和 Worker 运行在本机或客户内网；不单独维护一套 JavaFX 界面。

## 2. 产品体验目标

1. 用户始终知道系统正在探索哪一个入口、哪条路径、哪个分支和哪个依赖。
2. 从任意风险结论都能一键回到请求、调用栈、字节码位置和依赖证据。
3. 候选、疑似、已验证和未覆盖状态必须通过视觉和文字同时区分。
4. 面对海量节点时优先提供筛选、聚合、时间线和局部展开，而不是一次绘制全部图谱。
5. 危险操作、真实连接和身份切换必须有明确的策略状态和二次确认。

## 3. 技术选型

### 3.1 MVP

- React 18+、TypeScript、Vite；
- TanStack Query：服务端状态、缓存和重试；
- React Router：项目、扫描和详情路由；
- Tailwind CSS + 可审计的组件库（例如 shadcn/ui）：统一设计令牌；
- React Flow 或 Cytoscape：入口图、数据流图和攻击链；
- Monaco Editor：反编译代码、配置和证据定位；
- Apache ECharts：覆盖率、任务吞吐和依赖统计；
- SSE 优先用于扫描进度和事件流；需要双向实时控制时再启用 WebSocket。

当前原型用轻量 SVG/CSS 绘制示例图，不把演示图误认为真实图谱；接入大规模事实图后再切换到 React Flow/Cytoscape 的局部/虚拟化渲染。

### 3.2 部署

- **本地开发/单机版**：Vite 静态资源由 Java API 服务提供，Worker 使用本地沙箱。
- **企业私有化**：前端静态资源、Control Plane、Worker 和对象存储分离部署，支持 SSO/RBAC。
- **桌面版（后续）**：Tauri 负责窗口、自动更新和本地服务生命周期；敏感制品默认不离开本机。

前端不直接访问数据库、对象存储、沙箱或模型供应商，所有访问必须经过 Control Plane 的鉴权、脱敏和审计层。
原型默认使用 `VITE_DEMO_MODE=true` 的本地 MOCK 数据；切换真实 API 必须显式关闭 demo 模式并配置项目 ID，避免把演示数据误认为扫描事实。

## 4. 信息架构

```text
全局工作区切换器（左上角）
├── 创建 / 选择 / 删除授权工作区
└── 切换项目作用域

主导航
├── 审计执行
│   ├── 制品导入与策略
│   ├── 静态事实 / 入口发现
│   ├── PRE_ANALYSIS 前置建模与计划评审
│   └── 沙箱动态观察 / 动态验证 / 路径探索 / 研判 / 报告时间线
├── 审计结果
│   └── 入口、路径、发现、证据和攻击链
├── 模型服务
│   ├── 已保存 API 侧边选择
│   ├── Provider / 模型清单
│   └── 项目 AI 角色绑定
├── AI 审计过程
│   └── Provider、工具、推断摘要和失败事件
└── 全局设置
```

工作区不是一次审计中的中转页面，而是所有页面共享的项目作用域。左侧导航保持稳定，顶部显示当前工作区和当前功能；任何结果和 AI 事件都必须绑定当前不可变扫描上下文。

## 5. 关键页面

### 5.1 项目总览

首屏只展示可行动信息：

- 入口总数、已运行入口、未覆盖入口；
- 方法/分支/sink 覆盖度；
- 已验证、动态疑似、静态推测和未覆盖数量；
- 当前任务、资源消耗、替身命中率和模型成本；
- 高价值攻击链卡片。

每个指标可点击进入过滤后的证据列表，避免“漂亮但不可追溯”的仪表盘。

### 5.2 入口地图

左侧是协议/模块/风险/权限筛选，中心是入口节点图或表格，右侧是选中入口的参数、前置条件和静态可达 sink。入口节点支持“加入探索计划”“查看调用图”和“打开最近轨迹”。

### 5.3 路径探索器

采用调试器式三栏布局：

```text
路径树        调用/分支时间线             详情与证据
入口          当前方法、参数、污点         请求/返回值
  └─分支      分支条件、快照、回溯         DB 表字段、文件、网络、进程
```

用户可在任意节点查看失败原因、修改合成身份/依赖响应并发起安全重放；重放结果生成新证据版本，不覆盖原轨迹。

### 5.4 数据流与攻击链画布

- 数据流图默认从一个 source 展开到 transform 和 sink；支持按表、字段、文件路径、域名和命令过滤。
- 攻击链画布显示入口、漏洞、共享资源、权限和状态边；推测边为虚线，疑似边为橙色，已验证边为红色实线，模拟依赖用紫色标识。
- 图谱采用局部展开、节点聚合和虚拟化渲染，默认不加载整个项目图。

### 5.5 漏洞详情

顶部显示状态、风险等级、置信度、CWE 和“依赖模式”；正文按证据顺序展示请求、身份、调用栈、污点转换、sink、副作用和复现结果；底部提供确认、驳回、复测、标记误报和关联攻击链操作。

## 6. API 与实时事件（Control Plane MVP 已完成）

前端只消费版本化 DTO，不直接依赖 Java 内部 record。最低接口集合：

- `POST /api/v1/projects`
- `POST /api/v1/projects/{id}/artifacts`
- `GET /api/v1/projects/{id}/entries`
- `POST /api/v1/projects/{id}/audit-runs`（静态扫描 + PRE_ANALYSIS 组合主入口）
- `POST /api/v1/projects/{id}/scans`
- `GET /api/v1/scans/{id}`
- `GET /api/v1/scans/{id}/events`（SSE）
- `GET /api/v1/scans/{id}/paths/{pathId}`
- `GET /api/v1/findings/{id}`
- `POST /api/v1/findings/{id}/replay`
- `GET /api/v1/attack-chains`

Control Plane 当前使用本地 SQLite 保存项目、制品元数据、scan、Provider、角色、AI Job/Event、审计记录、Worker task/trace、REST 幂等记录、probe plan 和流水线 cursor；这些恢复语义是单节点有界持久化，不是分布式 exactly-once。完整路由以实现为准，另包括：

- `GET /api/v1/projects/{id}/dashboard`、`GET /api/v1/projects/{id}/evidence`；
- `GET /api/v1/scans/{id}/paths`、`GET /api/v1/scans/{id}/evidence`、`GET /api/v1/scans/{id}/findings`；
- `GET /api/v1/evidence/{id}`；
- `POST /api/v1/findings/{id}/replay`（显式授权后，由服务端创建绑定原 scan/entrypoint 的 `TRUSTED_DOCKER` 动态任务；返回 `202` 和 task 状态，不直接把 finding 标记为 `VERIFIED`）。请求体只允许 `{ "authorized": true }`，并要求 `Idempotency-Key`。

写操作（创建项目、登记制品、创建扫描、组合审计、replay）要求 `X-Sentinel-Authorization: <token>`，也接受 `Authorization: Bearer <token>`。扫描 body 必须显式带 `authorized: true`；组合审计还必须独立带 `aiAuthorized:true`，并通过服务端一次编排创建 scan 与 PRE_ANALYSIS。令牌只完成本地调用认证，不代替授权同意。项目、制品、扫描、组合审计、动态任务、finding replay 和 AI `sandbox_probe` job 绑定使用 `Idempotency-Key` 去重（非空、无空白、最多 256 字符），记录写入 SQLite，最多 50,000 条，跨重启按 payload hash 复用；同键不同 payload 返回 409。删除、修改等其他 mutation 尚未全部纳入统一持久化幂等。

SSE 路由 `GET /api/v1/scans/{id}/events` 支持 `Last-Event-ID` 续接。客户端必须处理 `ScanCreated`、`TaskLeased`、`FindingUpdated`、`ScanCompleted`、`TaskStopped` 等事件，并在断线、事件窗口不足或收到终态后调用幂等 GET 进行补偿。SSE 是增量通知，不是事实来源；最终状态以 `GET /api/v1/scans/{id}` 为准。事件 DTO 带 `schemaVersion`、`projectId`、`artifactDigest`、`scanId`、`verificationStatus`、`dependencyMode` 和 `evidenceRefs`。

静态元数据限制必须在 UI 中持续可见：调用图和跨方法污点是预算内 `STATIC_INFERRED` 事实/候选；`MOCK`、沙箱 trace 和模型输出不能直接显示为 `VERIFIED`。`DYNAMIC_CONFIRMED` 必须展示 MOCK/合成身份前置条件，且不得文案暗示生产实库已证实。动态验证仍必须依赖用户授权沙箱，个人本地版不承诺多租户/RBAC 或生产供应商互操作。

DTO 必须带 `schemaVersion`、`projectId`、`artifactDigest`、`scanId`、`verificationStatus`、`dependencyMode` 和 `evidenceRefs`。前端只把事件当作增量提示，最终状态以幂等的查询接口为准。

## 7. 安全与隐私

- 使用严格 CSP、同源 API、CSRF 防护和短期令牌；禁止把制品内容插入 `innerHTML`。
- 代码、配置、SQL、响应和模型文本均按不可信内容渲染，统一转义并显示脱敏标识。
- 前端不保存原始凭据；下载证据前再次进行项目/角色校验。
- 危险操作按钮显示当前策略、审批人、范围和审计编号；默认只提供 dry-run/安全探针。
- 支持键盘导航、色盲可辨识状态、缩放和中英文文案；颜色不能是状态的唯一表达。

## 8. MVP 页面验收

1. 用户可以在项目总览看到扫描状态、覆盖度和依赖模式，并跳转到证据。
2. 用户可以从入口地图打开一条路径，看到参数、分支、表字段和停止原因。
3. 同一发现的候选/疑似/已验证状态在列表、详情和图谱中一致。
4. SSE 断线重连后不会重复计数或丢失最终扫描状态。
5. 低权限用户无法通过前端接口读取原始制品、未脱敏轨迹或其他项目数据。

## 9. 后续演进

- 支持大型图谱的 WebGL/分层渲染；
- 用户自定义仪表盘和报告模板；
- Tauri 桌面版离线工作区；
- 多人协作批注、审计签名和修复工单集成。

## 10. 前端运行模式与当前状态

- `VITE_DEMO_MODE=true`：启用本地 DEMO/MOCK 数据，不请求后端；适合产品演示和视觉开发。
- `VITE_DEMO_MODE=false` 或未设置：启用真实 Control Plane；必须配置 `VITE_API_BASE_URL`（默认 `/api/v1`）和 `VITE_PROJECT_ID`，可选 `VITE_SCAN_ID`。
- 当前本地 MVP 的写操作使用 `VITE_API_TOKEN`；它只适合短期调试并会进入浏览器 bundle。生产级 HttpOnly 会话、CSRF、SSO/RBAC 和 SSE 会话鉴权尚未在 Java Control Plane 实现，不能把该配置说明当作生产安全承诺。
- 真实模式连接失败时显示错误，不自动回退到 Mock，避免把演示数据误认为扫描事实。

当前完成：React/TypeScript/Vite 原型、全局工作区切换、制品上传、静态扫描与 PRE_ANALYSIS 连续启动、阶段式审计时间线、Provider/角色配置、AI Job 事件审计、当前 scan 的最终 `AI INFERENCE` Markdown 报告、真实 API DTO 校验和 SSE 订阅边界。全局设置决定新 AI Job 使用中文或英文，默认中文；旧结果不可变。结果页安全渲染 Markdown 并支持 Markdown/HTML/JSON 下载，发现列表支持筛选，选中发现后展示证据引用、前置条件和按节点查看的攻击链画布。AI 审计事件可展开查看数据来源、组件流向、白名单工具决策和结果，但明确不记录模型隐藏思维链。动态安全摘要按 project/artifact/scan 复核后可供后续 AI 角色只读查询。当前 `TRUSTED_DOCKER` 仅用于本地受信内部 JAR 调试，普通 Docker 不是恶意制品强化隔离；容器任务完成也不表示入口已调用。生产级鉴权、多租户、完整反编译/污点/入口覆盖反馈、gVisor/Kata 验收和真实漏洞 `VERIFIED` 闭环仍未完成。

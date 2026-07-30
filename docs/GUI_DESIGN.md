# 溯脉 · Veyrion GUI 设计规范

> 本文只定义界面信息架构、交互、状态展示和前端安全。运行方式见 [frontend/README](../frontend/README.md)，产品语义见 [PRD](PRD.md)，完成度见 [MVP Backlog](MVP_BACKLOG.md)。

## 1. 体验原则

1. 用户始终知道当前项目、制品、扫描、阶段、入口、身份轨和停止原因。
2. 任何风险结论都能回到 PathRun、请求、调用位置、依赖副作用和证据引用。
3. 静态推测、动态疑似、动态确认、已验证和未覆盖必须同时用文字与视觉区分。
4. 大规模数据优先使用筛选、聚合、时间线和局部展开，不一次渲染完整图谱。
5. 授权、真实连接、身份切换和动态执行必须显示策略状态并要求明确确认。
6. Demo 与真实数据严格分离；真实 API 失败时不得伪造结果或自动回退 Demo。

当前产品是个人本地版。界面不承诺企业 SSO、多租户切换或生产级 RBAC；沙箱不可用时展示 `DYNAMIC_DISABLED`，不得提供宿主机执行按钮。

## 2. 信息架构

```text
全局工作区
├── 创建、选择、删除项目
└── 固定当前 project / artifact / scan 作用域

主导航
├── 审计执行
│   ├── 制品导入与授权
│   ├── 静态事实与入口
│   └── 固定阶段时间线
├── 审计结果
│   ├── 最终报告（默认工作台）
│   ├── Findings / Evidence
│   ├── Entry Parameter Exploration
│   ├── PathRun / 身份轨
│   ├── Evidence Graph / Static-Dynamic Contrast
│   ├── Coverage Matrix / Unresolved
│   ├── Dynamic Diagnostics
│   └── Experiments / Replay / Downloads
├── 模型服务
│   ├── Provider / 模型
│   └── 六角色绑定与双语提示词
├── AI 审计过程
│   └── Provider、工具、可见摘要和错误
└── 全局设置
```

工作区是所有页面共享的作用域，不是一次审计中的中转页。结果页默认显示 `REPORT_GENERATION` 产生的最终 Markdown；coverage、hypothesis、PathRun、发现、Evidence Graph 和对照账本是并列证据视图，不以单一风险分数替代。

## 3. 审计执行

阶段顺序必须与流水线 as-built（[AUDIT_PIPELINE_ASBUILT](AUDIT_PIPELINE_ASBUILT.md)）一致；产品意图对照 [AUDIT_FLOW](AUDIT_FLOW.md)：

```text
前置建模 -> 鉴权分析 -> 按轨动态观察 -> 鉴权绕过确认
         -> 动态验证 -> 路径探索 -> 漏洞研判 -> 报告生成
```

每个阶段展示：

- 状态、当前 attempt、开始/结束时间和停止原因；
- 输入证据范围、输出摘要、创建的 AI Job 或动态 task；
- 是否等待 Worker、被策略阻断、取消、失败或进入证据投影；
- 下一阶段为何可推进或为何不能推进。

手工 job、焦点 probe、finding replay 和实验卡 replay 必须与主流水线 attempt 视觉隔离，不能表现成主阶段已完成。`BUSY`、`FAILED`、未投影 trace 和无 PathRun 的 probe 不能计为有效尝试。

## 4. 审计结果

审计结果不是单个 Markdown 页，而是围绕同一 scan 的证据工作台。当前实现已有基本功能，但布局必须按下列结构重排，避免 report、PathRun、hypothesis、coverage、graph、verified 和 SQL replay 混杂在同一个大组件中。

### 4.1 结果工作台骨架

所有结果子页共享同一层页面骨架：

```text
ResultsShell
├── ScanContextBand
│   └── project / artifact / scan / policy / dependencyMode / verificationStatus / current stage
├── EvidenceSummaryStrip
│   └── static findings / dynamic supported / dynamic failed / coverage gaps / high risk sinks
├── ResultsSubnav
│   └── report / findings / entry exploration / path runs / graph / coverage / diagnostics / replay / downloads
├── MainPane
│   └── active subpage
└── EvidenceInspector
    └── selected finding / path run / hypothesis / graph node / coverage gap / task diagnostic
```

布局要求：

- 桌面端使用上下文带 + 横向或左侧子导航 + 主内容 + 右侧检查器；窄屏将检查器变为可关闭的下方详情区。
- 上下文带固定展示 scan 作用域和停止原因；切换 scan 后清空选中项、筛选器和检查器，重新从服务端 GET 获取事实。
- 摘要条只显示服务端已给出的计数和状态，不在前端自行计算验证升级；动态失败与动态支持分开展示。
- 子导航每项显示名称、计数、最高证据状态和是否存在未覆盖；计数为 0 时仍显示入口，不能隐藏能力缺口。
- 主内容按表格、分组列表、时间线和局部图谱组织；避免卡片套卡片和整页营销式大标题。
- 检查器只展示当前选择的证据摘要、refs、provenance、scope 和 stop reason；不存在 selection 时展示“选择一项查看证据边界”，不得显示伪成功。
- 所有子页共享 `StatusPill`、`ProvenanceBadge`、`EvidenceRefs`、`CoverageGapLink`、`StopReasonBlock` 和 `FilterBar` 语义。

### 4.2 最终报告总览

最终报告仍是默认子页，但它的职责是“审计结论索引”，不是塞满所有原始数据。页面分为：

1. 结论摘要：高风险 finding、静态主召回、动态支持、动态失败、未覆盖区域和建议下一步。
2. Evidence scope：报告生成角色、语言、模型、策略快照、artifact digest、scanId、生成时间和输入 evidence refs。
3. Risk sections：按 `securityProperty` / hypothesis family 分组，每组显示 finding、状态、前置条件、影响组件和证据链入口。
4. Dynamic reliability：单独列出启动失败、`UNREACHED`、`UNKNOWN/-1`、MOCK 依赖和未投影 trace；这些不得进入漏洞主列表。
5. Coverage gaps：按入口族、调用解析、guard/effect/state、依赖替身和动态实验列出缺口。
6. Downloads：最终报告 Markdown、发现摘要 HTML、扫描快照 JSON，各自说明用途和不等价关系。

默认视图安全渲染 Markdown，显示生成角色、语言、模型、策略快照、证据范围和生成时间。报告中的 `INFERENCE` 不得渲染为事实徽标，模型 HTML 不得直接执行。

当前下载物要准确命名：

- 最终报告 Markdown；
- 发现摘要 HTML；
- 扫描仪表盘快照 JSON。

三者是不同制品，不得描述为同一报告的等价格式。

空态与错误态：

- 无 `REPORT_GENERATION` 任务时显示“报告未生成”，同时允许用户进入 Findings、PathRun 和 Coverage 子页查看已有事实。
- 报告任务失败时展示 jobId、errorCode、stop reason 和可审阅的证据子页链接，不回退 Demo。
- scan 为 `UNREACHED` 时报告页优先展示未覆盖原因和静态证据，不用空白页表达失败。
- Markdown 为空但已有 finding 时，页面应展示结构化 fallback 摘要并明确“模型报告缺失，结构化事实仍可审阅”。

### 4.3 Findings 与证据

Findings 是漏洞结论工作区，默认排序为：服务端标记的高危静态事实、动态支持的候选、证据不足但高影响候选、未覆盖或失败项。动态失败不得压过静态高置信结果。

发现列表支持标题、入口、状态、family、security property、CWE、provenance、动态支持状态和 coverage gap 筛选。详情依次展示：

1. 状态、严重度、置信度、前置条件、scope 和 verification gate；
2. `rootCause`、affected component、attack path、counterevidence 和 impact；
3. 静态证据、PathRun、RuntimeObservation、依赖副作用和 replay 引用；
4. 对应 hypothesis、detector、coverage gap、版本和停止原因；
5. 修复建议、人工处理记录和可重放实验。

动态结论必须绑定 PathRun。静态候选或未执行入口可以没有 PathRun，但必须保留静态证据、限制或停止原因。

Finding 以 `hypothesisId + securityProperty` 为核心，不强制显示传统 source/sink。数据流型显示 trust boundary、transforms、sanitizer 和 effect；IDOR/鉴权型显示 guard/ownership/tenant；状态型显示 transition/sequence；配置、typestate、并发和资源型显示各自证据关系。缺 source/sink 的 finding 不允许伪造 `sink-none`、`entry-unbound` 或空路径。

### 4.4 Entry Parameter Exploration

该子页承载“任意入口 × 0-n 参数 → 下游代码/效果/状态观测 → 反推漏洞”的产品设想，不能退化成固定 payload 洪水。

页面组织：

- Entry table：按协议、operation、route/topic/command、handler、参数签名、guard、业务前置、coverage 和风险信号展示入口。
- Parameter matrix：每个入口展示 query/body/header/path/form/file/session 等 0-n 参数组合；0 参数、空 body 和空 query 是合法输入形态，但必须显示 empty-input rationale。
- Hypothesis seeds：显示来自静态 sink/effect、AUTH PoC、Provider DynamicProbe、DTO/config 推断和运行时未知 effect 的候选实验来源。
- Downstream observation：展示本入口下已观察到的 EntryHit、parameterBound、Guard、Effect、State、Dependency、Exception、Branch 和缺失项。
- Experiment readiness：区分可执行、缺身份、缺业务状态、缺依赖替身、缺参数绑定、沙箱不可用和预算不足。

交互要求：

- 用户可以按入口、参数种类、family、coverage gap、身份轨和动态 readiness 筛选。
- 选择一个入口后，检查器显示参数来源、默认值、约束、已尝试组合、未尝试组合和停止原因。
- 运行计划只能由服务端根据合同编译；前端只能提交“请求生成/重放计划”的引用，不能提供命令、网络、镜像、挂载、UID 或预算。
- 入口探索结果必须回写为 PathRun、RuntimeObservation 或 CoverageGap；没有投影的 probe 只作为诊断，不进入 finding。

### 4.5 PathRun

按“入口 × 身份轨 × probe attempt”组织。每条 PathRun 至少展示请求摘要、HTTP 结果、`entryHit`、`parameterBound`、Agent/JDBC 事件摘要、依赖模式、验证状态、超时分类和停止原因。

支持按入口、轨、状态、阶段、technique 和 coverage gap 筛选。SQL 必须属于同一请求关联范围；任务级 SQL 不得无差别复制到多个 PathRun。合成身份与 MOCK 前置条件持续可见。

额外要求：

- `httpStatus=-1`、`outcomeClass=UNKNOWN`、空 trace、未投影、探针失败和依赖端口误判默认展示为 `UNREACHED` 或 diagnostic，不得直接显示为 `DYNAMIC_SUSPECTED`。
- 每条 PathRun 必须可展开 request window，显示 correlationId、probeAttemptId、experimentPlanId、identity track、entryRef、输入摘要、响应摘要、事件数量和 trace integrity。
- 大量 PathRun 使用聚合和虚拟列表；默认按 entry/track/outcome 聚合，用户选择组后再展开单条。
- 同一入口的多轮发包要显示序列关系，不能把 retry、replay 和主流水线 attempt 混成一次尝试。

### 4.6 Evidence Graph 与对照

Static-Dynamic Contrast 以 `STATIC_ONLY`、`DYNAMIC_REACHED`、`CONTRADICTED` 等明确标签呈现静态候选与动态观察的差异。图谱只局部展开选中的入口、source、transform 和 sink；推测边、运行时观察边和服务端确认边必须使用不同线型及文字标签。

Evidence Graph 支持按 hypothesis 展开 Program、Entry、TrustBoundary、Effect、Guard、Sanitizer、State、Resource 和 RuntimeObservation。默认只加载当前假设的一跳关系；所有边展示来源、分析器版本和 coverage 状态。

图谱交互：

- 从 finding、entry、PathRun、coverage gap 都可跳转到图谱，并保持相同 scope。
- 图谱节点点击只更新 EvidenceInspector，不改变服务端状态。
- 未解析调用、未知语言节点、运行时-only 节点和 namespaced extension 均可显示通用降级详情。
- 默认不渲染全图；节点数量超过预算时展示截断原因和继续分析建议。

### 4.7 Coverage Matrix

Coverage 页面至少展示 Artifact Universe 展开率、入口族、调用解析率、source/effect/guard/sanitizer model、各 detector、动态实验和 stop reason。`UNKNOWN`、`UNRESOLVED`、`TRUNCATED` 与 `UNREACHED` 必须可筛选并跳到对应 IR node 或 coverage gap。

扫描成功、报告已生成或 finding 为零都不能渲染为“项目安全”；只能显示“在声明覆盖范围内未发现已支持结论”。

Coverage 子页还要显示：

- 静态召回覆盖：入口族、effect/sink family、wrapper summary、sanitizer、guard 和 unresolved call。
- 动态覆盖：启动成功率、有效 PathRun、无效 PathRun、entryHit、parameterBound、RuntimeObservation 投影和失败分类。
- AI 覆盖：每个角色消费的 evidence scope、工具调用是否成功、是否存在缺代码切片或缺实验计划。
- Recall gate：实战样本和 fixture 的基线是否通过；没有 ground truth 时必须标“不可评价召回”。

### 4.8 Dynamic Diagnostics

动态诊断子页专门承载沙箱启动、端口、依赖替身和 probe 失败，避免污染 finding 主列表。

展示内容：

- Sandbox task lifecycle：排队、启动、就绪、保留、取消、TTL、销毁和失败原因。
- Port discovery：配置端口、日志端口、容器监听端口、应用 HTTP 端口和依赖端口；3306/6379/5432 等依赖端口必须标为 dependency listener。
- Startup diagnostics：JVM 退出码、OOM、主类缺失、配置缺失、DNS 失败、依赖替身异常、探针 JVM 失败、日志尾部和资源预算。
- Probe diagnostics：请求计划、探针参数、HTTP 状态、可写事件数量、probe-events 路径、trace commit 和投影状态。
- Sandbox retention：说明容器是否仍保留给 PATH/TRIAGE 多轮发包；未保留时显示销毁原因。

失败诊断可以作为 coverage gap、counterevidence 或重跑建议，不能单独成为漏洞。

### 4.9 Experiments、Replay 与下载

实验页按 `ExperimentPlan -> attempt -> PathRun/diagnostic -> hypothesis update` 展示，不以按钮触发未知动作。

- Plan list：显示来源、family、entry、0-n 参数摘要、identity track、expected/counter signal、预算和 stop condition。
- Attempt timeline：区分主流水线、AUTH_CONFIRM、PATH/TRIAGE probe、finding replay、SQL card replay 和人工 focus probe。
- Replay action：只能对服务端可重放计划发起新 attempt；按钮文案必须说明不会直接升级 `VERIFIED`。
- Downloads：Markdown、HTML、JSON 下载集中放置，保留 scanId、schemaVersion、verificationStatus、MOCK 和 evidence refs。

### 4.10 多语言与扩展展示

主导航、扫描流程和 Finding 详情按 capability、hypothesis family、security property 与 entry protocol 组织，不按 Java/Spring/Python/某框架复制页面。ProgramNode 和 RuntimeObservation 先显示中立字段；语言/框架 namespaced extension 由可选 renderer 补充。

未知 language、node kind、entry protocol 或 extension 不能导致解析整页失败。界面必须保留 stable ID、producer、位置、evidence、coverage、stop reason 和受限原始属性的通用降级视图，并明确标记“当前无专用渲染器”。前端不得把未知枚举归类为已覆盖、低风险或空结果。

## 5. 模型服务与 AI 审计

模型服务页固定展示六个角色：`PRE_ANALYSIS`、`AUTH_ANALYSIS`、`DYNAMIC_VERIFICATION`、`PATH_EXPLORATION`、`VULNERABILITY_TRIAGE`、`REPORT_GENERATION`。每个角色可绑定 Provider/模型并编辑中文、English 提示词；任务创建时显示不可变快照版本。

界面必须提示：自定义提示词不能改变服务端工具白名单、安全策略、预算或验证等级。目标角色提示词还应表达：

- AUTH 先查询代码，再提出多个机制不同的 PoC，并在有界轮次中补证和修订；
- PATH 只为明确 coverage gap 发起 `sandbox_probe`，说明入口、轨、目标、输入和停止条件；
- TRIAGE 可用 `sandbox_probe` 复现或证伪，但必须保留结构化 root cause、反证与 evidence refs。

AI 审计页展示服务端持久化的 Provider 元数据、白名单工具决策、结果摘要和错误诊断。隐藏 chain-of-thought 不展示或还原。Provider 显式返回并被服务端保存的 `MODEL_THINKING` 摘录必须标为“不可信审计元数据”，与事实证据分栏，且不得进入工具或状态升级路径。

## 6. 状态呈现

| 状态 | UI 文案要求 |
|------|-------------|
| `STATIC_INFERRED` | 静态推测；未运行 |
| `DYNAMIC_SUSPECTED` | 动态疑似；闭环不足 |
| `DYNAMIC_CONFIRMED` | 动态确认；展示 H3 与 MOCK/身份前置条件 |
| `VERIFIED` | 已验证；必须显示强化沙箱和重放证据；当前不应出现 |
| `UNREACHED` | 未覆盖；显示身份、预算、启动、超时或依赖原因 |

超时不能只显示“失败”，至少区分 `AUTH_CHALLENGE`、`BUSINESS_TIMEOUT`、`COLD_START`、`ENTRY_NOT_HIT`、`IDENTITY_UNAVAILABLE` 和预算耗尽。状态不得只靠颜色表达。

## 7. 安全与隐私

- 制品名、代码、配置、SQL、响应、模型文本和 Markdown 都按不可信内容转义。
- 前端不保存 Provider 原始凭据，不直接访问 SQLite、对象存储、Worker 或模型接口。
- 本地调试 token 会进入浏览器 bundle，界面必须标注 loopback 开发用途；不得描述成生产会话。
- CSP 只允许同源与精确 loopback Control Plane；其他部署通过模板精确生成，禁止 `connect-src *`。
- 动态执行、replay、真实连接和破坏性策略需要显示授权范围、依赖模式、沙箱能力和审计标识。
- 所有页面都要校验 project/artifact/scan 作用域，切换工作区后清除旧选择和缓存。
- 下载物保留原始验证状态和 MOCK 标识，不因导出格式改变结论。

## 8. 当前技术形态

当前实现使用 React 19、TypeScript、Vite、普通 CSS 和轻量 SVG，本地 view state 驱动。开发模式是 `5173` Vite 与 `18080` Control Plane 两个 loopback 服务。`VITE_DEMO_MODE=true` 才启用 Demo；未设置时使用真实 API。

TanStack Query、React Router、Tailwind、React Flow/Cytoscape、Monaco、ECharts 和 Tauri 都属于容量或交付需求出现后的候选演进，不是当前依赖或已交付能力。Java 托管前端静态资源、`jlink/jpackage` Desktop Core 和企业私有化分层同样属于目标打包形态。

## 9. 页面验收

1. 新用户可从工作区完成上传、显式授权、组合审计，并看到固定阶段时间线。
2. 报告默认打开，且可切换到关联 PathRun、finding、证据和对照视图。
3. 同一状态在列表、详情、时间线、图谱和下载物中语义一致。
4. SSE 断线重连后不重复计数，终态通过 GET 补偿。
5. Demo、真实 API 错误、Worker 不可用和策略阻断不会被显示为成功。
6. 键盘、缩放、窄屏和长文本下无重叠；颜色不是状态唯一信号。
7. 低权限或错误作用域请求不能读取原始制品、凭据、未脱敏轨迹或其他项目数据。
8. 非 source-sink finding 可以通过 guard/state/config/typestate/concurrency 关系完整展示，不出现伪造的 `entry-unbound` 或 `sink-none`。
9. 用户可以从任一 coverage gap 跳到未解析节点、停止原因和建议 Provider/实验。
10. 最终报告菜单的每个子页都有明确 loading、empty、error、partial、unknown 和 unauthorized 状态，且不回退 Demo 成功。
11. Entry Parameter Exploration 能展示 0-n 参数空间、empty-input rationale、实验 readiness 和下游观测；无投影 probe 只进入诊断或 coverage gap。
12. Dynamic Diagnostics 能解释启动失败、端口误判、依赖替身、探针 JVM 和 trace 投影问题；这些失败不会出现在漏洞主列表。
13. `UNKNOWN/-1/MOCK` PathRun 在结果页默认降噪，除非用户主动进入诊断或 PathRun 失败筛选。
14. ResultsShell 在桌面和窄屏下保持 scan 上下文、子导航、主内容和 EvidenceInspector 不重叠；长 SQL、stack trace、entry、路径和模型错误可读。
15. 下载页准确说明 Markdown、HTML、JSON 的用途和差异；导出物保留原始 verification status、provenance、MOCK 和 evidence refs。

实际完成度和缺口只在 [MVP Backlog](MVP_BACKLOG.md) 维护，本文不记录逐次实现历史。

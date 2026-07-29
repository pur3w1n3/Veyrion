# 溯脉 · Veyrion 产品需求文档

> 本文定义产品为何存在、服务谁、必须提供什么能力以及如何验收。执行顺序以 [AUDIT_FLOW](AUDIT_FLOW.md) 为准，PathRun 与状态门禁以 [PATH_EXPERIMENT_MODEL](PATH_EXPERIMENT_MODEL.md) 为准，当前完成度以 [MVP Backlog](MVP_BACKLOG.md) 为准。

## 1. 产品定位

Veyrion 面向用户明确授权的闭源 JVM 制品，通过静态事实、受控动态实验和 AI 辅助研判，建立入口、鉴权、路径、依赖副作用、sink 和攻击链之间的可引用证据。

当前产品是个人本地版、Spring Boot 可执行 JAR 优先的路径调试型安全验证工具。它不是生产攻击平台，也不承诺任意语言、任意框架、100% 路径覆盖、企业 SSO 或完整多租户。

核心术语：

| 术语 | 含义 |
|------|------|
| Entry | 可由外部协议或框架触发的入口 |
| Identity Track | `UNAUTH`、`USER`、`ADMIN`、`AUTH_BYPASS` 等合成身份轨 |
| PathRun | 一次入口、身份轨、输入和运行结果的不可变实验记录 |
| PathTrace | PathRun 内的有序运行时路径：入口、参数绑定、方法 hop、guard、sink/effect、依赖调用、退出原因 |
| World Pack | 沙箱内的业务世界材料：profile、环境变量、license/文件、schema/seed、依赖替身和缺口 |
| Runtime Posture | 动态执行姿态：UNAUTH、COVERAGE_POSTURE、FORCED_REACHABILITY、BYPASS |
| Probe | 服务端固定策略下的一次有界动态尝试 |
| Evidence | 带来源、作用域、摘要和引用的事实、观察或推断 |
| Finding | 由证据、前置条件、根因和状态组成的安全结论 |

## 2. 目标与非目标

### 2.1 产品目标

1. 从制品中召回入口、鉴权点、依赖和高风险 sink，并保留静态位置证据。
2. 对入口建立参数、身份、业务状态和依赖假设，生成可审查的实验计划。
3. 在授权沙箱中按身份轨执行有界实验，记录 HTTP、Agent、JDBC 和停止原因。
4. 让 AI 以受控工具查询代码和证据，提出、修订、复现或证伪候选路径。
5. 将静态事实、动态观察、MOCK 和模型推断分层，服务端独占验证状态升级权。
6. 让用户从最终报告回到 PathRun、证据、对照账本和重放计划。
7. 通过 ArtifactPackager、LanguageAnalyzer、FrameworkAdapter、AnalysisPack 和 RuntimeAdapter 分别扩展制品、语言、框架、风险域与运行时。
8. 以 Security IR / Evidence Graph 保真保存程序、配置、控制、数据、状态和运行时关系，不把静态路径压成文本摘要。
9. 让数据流、鉴权/所有权、状态机、typestate/API misuse、配置/依赖、并发和资源生命周期检测器并行产生结构化假设。
10. 对每个入口族、漏洞族和分析器展示覆盖率、未解析区域和停止原因，而不是承诺“未发现即安全”。
11. 保持一个语言无关的 Control Plane、证据模型、流水线和 GUI；新增语言不得复制授权、状态机、存储或报告逻辑。
12. 将动态能力建设为 Docker 内动态路径调试器：即使最终因数据库、License、文件、状态或依赖不可达失败，也要保留失败前真实经过的业务路径、参数流、sink/effect 触发和最终阻断原因。

### 2.2 非目标

- 未经授权攻击真实生产系统；
- 让模型直接执行 shell、访问外网、宿主路径或改变沙箱策略；
- 把模型文本、MOCK 命中或静态调用事实当成已验证漏洞；
- 在当前版本提供生产级多租户、SSO、跨租户调度或任意语言；
- 用单一百分比或风险分数掩盖未覆盖路径和证据缺口。
- 承诺所有接口一定完整跑通或一定返回 2xx；产品只能承诺输出最深可达路径、已触发 effect 和阻断原因。

## 3. 用户画像与场景

以下是用户画像，不是实现中的权限枚举：

- 本地安全研究者：对已授权的 JAR/WAR 做静态理解和沙箱验证。
- 独立开发者：检查内部服务、插件和遗留系统的高风险调用链。
- 受托测试人员：在明确范围内生成可复现、可审计的证据。
- 只读审阅者：检查报告与脱敏证据，不改变策略或运行动态任务。

实现权限以 `VIEWER / ANALYST / OPERATOR / ADMINISTRATOR` 为兼容枚举；当前只提供本地作用域，不构成企业 RBAC 承诺。

典型场景：系统分别发现文件上传、路径读取和命令执行候选后，使用静态与动态证据将它们串成潜在攻击链，同时明确每条边所需身份、业务状态、依赖模式和未验证环节。

## 4. 核心用户流程

1. 创建项目，确认制品授权范围、网络策略、动态能力和数据保留边界。
2. 上传 JAR/WAR/CLASS；系统校验格式、大小和摘要，生成不可变制品身份。
3. 执行静态扫描，产出入口、鉴权、调用、依赖、sink 和有界污点候选。
4. 前置 AI 解释业务对象、优先级和实验计划，但不改写静态 FACT。
5. 鉴权 AI 查询真实代码，枚举鉴权链并生成多个机制不同的 PoC 或不可行证据。
6. 服务端编译 TracePlan、World Pack 与 entry × 0-n 参数实验计划，在 Docker 沙箱中按 UNAUTH、COVERAGE_POSTURE、FORCED_REACHABILITY 和 BYPASS 姿态做动态路径调试。
7. 用户在报告、PathRun、finding、证据和对照视图间审阅、重放、确认或驳回。
8. 导出不同用途的制品，并在新制品版本上复用计划进行回归。

模型不能跳过、重排或自行启动阶段；确定性流程和状态机由服务端控制。

## 5. 功能需求

### 5.1 制品与静态事实

- 支持 JAR、WAR、CLASS 的有界导入；当前动态主路径只承诺 Spring Boot 可执行 JAR。
- 每次扫描绑定项目、制品摘要、策略和 schema 版本；后续证据不得跨作用域混用。
- 识别框架入口、请求参数、鉴权注解、方法调用、依赖和敏感 sink。
- 静态调用图、污点和入口召回必须报告预算、不完整性与停止原因。
- 反射、代理、JNI、制品外 classpath 和运行时注册无法解析时必须诚实标记。

目标静态核心必须建立完整但有界的 Artifact Universe：应用 class、Boot 内嵌依赖、配置、资源、`web.xml`、多版本 class 和生成代码分别标识；每个未展开制品和未解析调用生成 coverage gap。

Security IR / Evidence Graph 至少包含：

- `ProgramNode`、`EntrySurface`、`TrustBoundary/Source`、`SensitiveEffect`；
- `Guard/AuthBarrier`、`Sanitizer/Validator`、`ConfigurationFact`；
- `StateTransition`、`ResourceLifecycle`、`RuntimeObservation`；
- `Call`、`Control`、`Data`、`Alias`、`GuardedBy`、`StateBefore/After`、`HappensBefore` 等关系。

每个节点和边都要携带证据、分析器版本、置信度、覆盖状态与 stop reason。已知 source/sink 规则只是 `DataflowDetector` 的输入，不是产品唯一发现模型。

### 5.1.1 漏洞假设类型

检测器统一输出 `SecurityHypothesis`，而不是直接生成漏洞：

| 类型 | 目标问题 |
|------|----------|
| Dataflow | 不可信数据是否到达敏感 effect，净化是否充分 |
| Guard / Ownership | 鉴权、租户、对象所有权或审批 guard 是否支配敏感操作 |
| State / Sequence | 跨请求顺序、重复提交、额度或状态转换是否违反不变量 |
| Typestate / API Misuse | API 调用顺序、密码学、TLS、序列化或资源生命周期是否错误 |
| Configuration / Dependency | 配置、框架安全选项或依赖版本是否形成风险 |
| Concurrency / Resource | TOCTOU、竞态、锁、线程、连接、内存或磁盘预算是否可被滥用 |
| Composition | 多个低级事实是否通过共享身份、资源或状态组成攻击链 |

假设可以没有传统 source 或 sink，但必须声明安全属性、适用作用域、支持/反对证据、覆盖缺口和建议实验。

### 5.2 依赖与动态实验

外部依赖按以下顺序处理：规则替身、用户快照、授权录制回放、受控真实连接。当前本地版默认使用断网替身，不承诺真实连接。

每个依赖结果必须记录 `provenance`、`dependencyMode`、请求摘要、响应摘要、预算和限制。替身让路径成立只证明代码逻辑可继续，不证明生产数据、配置或影响真实存在。

动态实验必须：

- 绑定明确的 entry、identity track、objective、输入、预算和 stop condition；
- 绑定 `tracePlanId`、`postureKind`、World Pack 策略、expected/counter signal 和退出原因；
- 只在服务端固定策略和用户授权下进入 Worker；
- 记录 HTTP、入口命中、参数绑定、PathTrace、Sensor Agent 事件、JDBC/依赖事件和超时/退出分类；
- 在数据库、Redis、文件、License、业务状态或外部服务不可达时，保留失败前已经观察到的业务方法、参数流和 sink/effect；
- 在 Worker 不可用、排队超时、失败或证据投影失败时形成显式终态；
- 绝不回退到宿主机直接执行被测制品。

动态姿态要求：

- `UNAUTH` 默认对每个入口有界执行，用于标注鉴权墙和意外过闸。
- `COVERAGE_POSTURE` 默认启用，通过标准框架边界尽量注入扫描身份进入业务逻辑；结果必须标 `SCAN_AUTH_POSTURE`，不得写成匿名可利用。
- `FORCED_REACHABILITY` 默认启用但仅限 Docker 沙箱，只能对已识别 auth/role/permission/license/feature guard 强达；结果必须标 `INSTRUMENTATION_REACHABILITY`，不能单独升 `DYNAMIC_CONFIRMED` 或 `VERIFIED`。
- `BYPASS` 只在 UNAUTH 意外过闸或 AUTH_ANALYSIS 产出 PoC 时执行，用于确认绕过候选。
- Agent 只能作为 Sensor 记录路径，不得继续扩展逐点鉴权/License/中间件 fail-open 作为主路线。

### 5.3 AI 角色合同

六个角色的权威顺序、工具和输出门禁见 [AUDIT_FLOW](AUDIT_FLOW.md)。产品层必须保证：

- `PRE_ANALYSIS` 只补充业务解释和计划；模型字段标 `MODEL_SUPPLEMENT` 或 `INFERENCE`。
- `AUTH_ANALYSIS` 必须用真实代码查询查看 Filter、Interceptor、安全注解、JWT/session/API key、skip URL、租户和角色分支。工具至少支持方法切片、caller/callee、CFG、guard 与 dataflow slice；鉴权面存在时应生成至少 3 个结构不同的 PoC，不足时逐条给出代码证据，并在“查代码、草拟、补证、修订”中有界迭代。
- `DYNAMIC_VERIFICATION` 可用 `sandbox_probe` 验证 AUTH 交接的 PoC。
- `PATH_EXPLORATION` 可为明确 coverage gap 调用 `sandbox_probe`；新事实必须成功投影为 PathRun。
- `VULNERABILITY_TRIAGE` 可用 `sandbox_probe` 复现或证伪，输出必须保留 root cause、CWE、affected component、attack path、counterevidence、fix suggestion 和 evidence refs。
- `REPORT_GENERATION` 只汇总证据、反证、限制和建议，不升级状态。

AI 不承担基础召回。PRE/AUTH/PATH/TRIAGE 只能查询 Evidence Graph 和受限代码切片、创建 `SecurityHypothesis` 或 `ExperimentPlan`、解释冲突和提出 PoC；任何 AI 补充都必须经确定性解析器/检测器或动态证据支持后才能转为事实。

自定义提示词不能改变工具白名单、网络、挂载、UID、预算、授权或验证状态。这些是目标产品合同；未完成的服务端门禁必须在 Backlog 标为缺口。

### 5.4 任务控制与恢复

- 阶段、probe、replay 和用户操作使用独立身份与幂等键。
- 任务支持取消、重试和重启恢复；旧 attempt 的迟到回调不能推进新阶段。
- 已提交事实和轨迹追加保存，不原地覆盖；派生投影可以重建。
- SSE 是通知通道，不是事实来源；最终状态通过幂等查询获取。

### 5.5 结果审阅与导出

- 最终报告为结果页默认视图，PathRun、发现、证据与对照账本为可切换视图。
- 用户可以确认、驳回、标记误报、请求复测和记录理由；人工操作不伪造技术验证状态。
- 当前导出物分别为最终报告 Markdown、发现摘要 HTML 和扫描快照 JSON，不宣传为同一报告的等价格式。
- 所有下载保留原始状态、MOCK、合成身份、限制和 evidence refs。
- Finding 不强制绑定传统 sink。它必须绑定一个已审计的 `hypothesisId`、安全属性和证据；数据流型 finding 再附 source/effect，状态型、配置型或并发型 finding 使用对应关系和实验引用。

## 6. 证据与结果合同

证据分层：

| 层级 | 允许来源 |
|------|----------|
| `FACT` | 制品、字节码、配置或服务端直接确认 |
| `RUNTIME_OBSERVED` | 授权沙箱中的运行时观察 |
| `MOCK` / `RULE_GENERATED` | 替身或规则生成材料 |
| `INFERENCE` | 静态分析或模型推断 |

验证状态：

| 状态 | 最小语义 |
|------|----------|
| `STATIC_INFERRED` | 静态候选，未完成动态闭环 |
| `DYNAMIC_SUSPECTED` | 运行时观察到关键点，但证据链不足 |
| `DYNAMIC_CONFIRMED` | 服务端 H3 门禁通过；仍显示 MOCK 与合成身份 |
| `VERIFIED` | 强化隔离、可重放和发布门禁均通过；当前关闭 |
| `UNREACHED` | 受身份、启动、预算、超时或依赖限制未覆盖 |

动态结论必须绑定 PathRun。静态 finding、静态入口和未执行候选可以没有 PathRun，但必须绑定 scan/entry/evidence 并说明限制或停止原因。

PathRun 若包含 PathTrace，即使最终 HTTP 500 或依赖不可达，也可作为“已到达某业务点/已触发某 effect”的动态证据。报告必须同时展示 posture、World Pack、MOCK、强达和依赖不可达限制。

SQL `DYNAMIC_CONFIRMED` 至少要求同一 PathRun 中存在恶意片段进入实际 JDBC/替身语句、入口到 SQL 间无过滤或参数化阻断证据，以及可重放引用。它不等于生产实库已证实。`VERIFIED` 还要求强化沙箱 attestation、原始制品和运行画像、完整证据链、实际副作用摘要与可重复结果。

模型、规则、MOCK、前端或人工确认都不能单独提升验证状态。

## 7. 安全与隐私

- 扫描、AI 出站和动态执行分别获得明确授权，并写入审计。
- 制品、模型输出和前端输入都是不可信数据，不能改变权限、工具或策略。
- 默认断网、资源受限、固定命令/挂载/UID/预算；危险 payload 使用无害标记或 dry-run。
- Provider 凭据只由后端管理。发送给模型的上下文最小化、脱敏且绑定作用域。
- 隐藏 chain-of-thought 不保存；Provider 显式可见 thinking 摘录如被保存，必须截断、脱敏、标记为审计元数据并受保留策略管理。
- 当前 `TRUSTED_DOCKER` 只适合受信本地调试。恶意制品生产执行必须等待独立 Linux gVisor/Kata 发布门禁。

私有化、多租户、密钥轮换、删除证明、企业 SSO 和商业数据保留策略属于未来上线门槛，不是当前已实现能力。

## 8. 非功能需求

- 可追溯：每个结论可回到制品摘要、扫描、入口、PathRun、工具版本和 evidence refs。
- 可恢复：重启、取消、重试和 Worker 故障不会丢失已提交证据或错误推进阶段。
- 可重放：相同制品、策略、计划、身份轨和输入生成独立 attempt，并保留差异。
- 可解释：证据不足时只标推测或未覆盖，不用自然语言填补事实缺口。
- 有界：每个扫描和 probe 声明时间、并发、路径、状态、存储和模型预算；耗尽时给出 stop reason。
- 可扩展：制品、语言分析、框架语义、风险域、运行时、依赖替身和 Agent 协议使用版本化接口。
- 技术中立：公共 API、Security IR、Hypothesis、Coverage 和 RuntimeObservation 不强制依赖 JVM、Spring、HTTP 或 source/sink 专属字段；语言特有信息使用 namespaced extension。
- 可隔离：新语言 Analyzer 默认进程外运行，无 Control Plane 数据库、授权、动态 Worker 或验证状态权限。
- 可审计：关键自动化测试必须实际执行非零断言；零测试的构建成功不能作为验收证据。
- 覆盖诚实：输出入口召回、依赖展开、调用解析、source/effect model、检测器执行和动态实验的 coverage matrix；unknown、unresolved 和 truncated 必须可查询。
- 可度量：每个受支持漏洞族在基准样例、变异样例和规则保留集上记录 recall、precision、有效实验率和未覆盖原因。

## 9. 验收场景

1. 数据库不可连接时，替身让代码继续运行，报告同时显示具体 SQL/字段、`MOCK` 和未验证边界。
2. 管理员路径通过合成身份可达时，报告保留管理员前置条件，不写成匿名可利用。
3. AUTH 查询真实代码，产生多个机制不同的候选；重复 payload 变体或无 evidence refs 的结果被拒绝或降级。
4. PATH 针对 coverage gap 发起 probe，只有成功终态、完成投影且生成 PathRun 才计为有效尝试。
5. TRIAGE 的 root cause、反证和顶层 evidence refs 在 finding 与报告中完整保留。
6. 同任务多入口产生不同 SQL 时，请求级关联不会把 SQL 复制到错误 PathRun。
7. 无 Worker、BLOCKED、取消、重试和迟到回调形成正确终态，不错误推进流水线。
8. 制品内提示注入文本无法获得额外工具、网络、宿主路径或验证状态。
9. `TRUSTED_DOCKER` 结果最高按服务端门禁标记，不能产生 `VERIFIED`。
10. 自研 wrapper 间接调用已知危险能力时，method summary 能把 wrapper 识别为 `SensitiveEffect`，而不要求手工加入固定 sink 表。
11. 消息消费者、Servlet/Filter 或运行时注册入口未被当前 Provider 支持时，coverage matrix 明确标为 `UNRESOLVED/UNREACHED`，不能从扫描成功推导为安全。
12. IDOR/对象所有权候选通过 guard dominance 和不同身份/对象的差分实验产生，不需要伪装成传统 sink。
13. 跨请求重复提交或状态绕过通过 State/Sequence hypothesis 与可重放序列验证，不依赖单请求污点路径。
14. 密码学/TLS/API misuse、危险配置和依赖风险由专用 detector 产生；AI 只能解释已生成证据。
15. 从扫描持久化后查询到的 call/data/control path 与原始 BytecodeFactIndex 一致，不允许从 sink 文本重建空步骤路径。
16. Test Analyzer 提交错误 scope/digest/schema、缺块、超预算或迟到结果时，Control Plane 拒绝发布部分 Security IR，并保留明确终态。
17. 第二语言静态切片复用同一 Artifact Universe、Security IR、Hypothesis、coverage matrix、证据查询和 GUI，不新增平行流水线或语言专属 Finding。
18. GUI 遇到未知语言节点、入口协议或 namespaced extension 时仍能展示通用 evidence、coverage 和 stop reason，不因硬编码枚举导致扫描不可读。
19. 对 `GET /code?code=...` 类入口，若参数进入 Controller、Service、Util 并触发表达式执行，随后数据库不可达，PathTrace 必须保留参数流、表达式 effect 和 DB 退出原因；报告不得因 HTTP 500 丢弃前置 effect。
20. 对需要鉴权的接口，UNAUTH 轨标注鉴权墙；COVERAGE_POSTURE 或 FORCED_REACHABILITY 轨进入业务时必须标 posture/provenance，不能写成匿名可利用。
21. FORCED_REACHABILITY 默认只在 Docker 沙箱内运行；尝试在宿主、无 Docker Worker 或由 AI/前端改变强达策略时必须拒绝。

当前实现是否满足上述场景，只能依据 [MVP Backlog](MVP_BACKLOG.md) 中的审计与测试证据判断。

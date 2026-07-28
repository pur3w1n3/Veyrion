# 可扩展分析架构（多语言演进）

本文定义目标扩展合同。当前 `FrameworkAdapter` 只能贡献框架提示，`AnalysisPack` 只能贡献少量实验模板，尚未满足本合同；完成度见 [MVP Backlog](MVP_BACKLOG.md)。Spring Boot JAR、WAR、自研框架和未来语言必须沿同一 Security IR / Evidence Graph 扩展，不能另起流水线。动态适配只能进入用户授权的沙箱。

## 1. 目标

当前闭源 JVM 制品形态（JAR/WAR/CLASS）与框架写法差异很大，未来不同语言的语法、模块、调用、运行时和依赖模型差异更大。平台不能把「Spring Boot JAR + `@PreAuthorize`」写死为唯一路径，也不能为每种语言复制一套控制面和审计流水线。

因此采用：

```text
中立事实模型（稳定）
  + ArtifactPackager / LanguageAnalyzer / FrameworkAdapter
  + AnalysisPack / RuntimeAdapter（正交增强）
  + 动态运行与证据分层（可证伪）
```

技术路线和进程边界由 [ADR-0001](adr/0001-polyglot-control-plane-and-workers.md) 固定。Java/React 控制面保持稳定，新语言解析器默认进程外运行。

## 2. 中立事实模型

控制面与 GUI 只依赖下列概念（与制品形态、框架名无关）：

| 对象 | 含义 |
|------|------|
| `ArtifactSurface` | 可读字节视图：class、依赖、配置、`web.xml`、资源 |
| `EntrySurface` | 外部可达面候选（HTTP/RPC/消息/任务/WebSocket 等） |
| `TrustBoundary` | 参数、身份、消息、文件、DB、配置和环境等 source/origin |
| `SensitiveEffect` | 系统能力或业务副作用，不限于固定 API sink |
| `Guard` | 鉴权、租户、对象所有权、状态、额度和审批条件 |
| `Sanitizer/Validator` | 净化、编码、参数化、规范化和拒绝分支 |
| `StateTransition` | 业务/安全状态前后关系 |
| `Evidence` | `FACT` / `RUNTIME_OBSERVED` / `MOCK` / `INFERENCE` 等 |
| `SecurityHypothesis` | 检测器产生的可支持、证伪或标证据不足的安全假设 |
| `CoverageGap` | 未展开、未解析、unknown、truncated 与预算停止原因 |

现有 `@RequestMapping`、`@PreAuth`、`AUTH_GAP` 只是某一 FrameworkAdapter 往该模型填充的一种输出。

## 3. 五条正交扩展轴

### 3.1 ArtifactPackager（制品适配器）

解决“如何识别、展开和寻址制品”，不负责语言语义和运行命令：

| ArtifactPackager | 输出 |
|------------------|------|
| Executable Spring Boot JAR | manifest、`BOOT-INF/classes`、嵌套依赖、配置和资源 |
| WAR | `WEB-INF/classes`、library、`web.xml` 和容器要求 |
| 库式 JAR / CLASS | class 与依赖/入口不完整 gap |
| 源码归档/未来制品 | 文件、模块、依赖清单、语言候选和不支持格式 gap |

Packager 只产生 Artifact Universe 节点、摘要、scope 和 gap。它不假设所有制品都能运行，也不共享“一定 `java -jar`”。

### 3.2 LanguageAnalyzer（语言语义前端）

解决“如何把某种语言的程序语义降为中立 Security IR”：

- 解析语法/字节码、模块、符号、类型、调用、CFG、数据/别名和异常边；
- 输出稳定 ProgramNode/edge、source location、analyzer version、coverage 和 stop reason；
- 语言特有事实放入 namespaced extension，中立检测器不直接依赖任意 extension；
- 默认作为进程外 Analyzer，通过摘要、scope、预算和分块协议提交结果；
- 不访问 Control Plane 数据库、授权、模型工具或动态 Worker。

当前 ASM 解析器是 JVM `LanguageAnalyzer` 的快速索引/fallback 基线，尚未形成进程外通用 Analyzer 合同。

### 3.3 FrameworkAdapter（Provider 组合器）

解决“某框架需要哪些 Provider”；可多适配器并行，结果按稳定 IR ID 合并：

1. Spring MVC + Security：默认基线；Blade 等框架只贡献可选 HINT。
2. Servlet / `web.xml` / Filter：WAR 与大量自研框架的公约数。
3. 结构推断：识别请求对象、参数读取、鉴权调用与 sink 的结构关系。

FrameworkAdapter 不能只返回关键词。目标接口组合 `EntryProvider`、`TrustBoundaryProvider`、`EffectModelProvider`、`GuardModelProvider`、`SanitizerModelProvider` 和 `MethodSummaryProvider`。同一节点多命中时合并证据，冲突标 `contradicted`；无适配器命中时保留 `unknown`。

### 3.4 AnalysisPack（分析包）

按风险域组合 detector、method summary、dynamic probe 与 report mapping，例如：

- AuthCoverage / Ownership / Tenant Isolation；
- Injection / Deserialization / SSRF；
- State/Sequence / Typestate / Crypto/API Misuse；
- Configuration / Dependency / Concurrency / Resource。

AnalysisPack 必须能注册版本化 `DetectorProvider` 和 `DynamicProbeProvider`，但不能改变工具权限、Worker 能力或验证状态。AI 与 checklist 只作候选来源。

### 3.5 RuntimeAdapter（运行时适配器）

解决“如何在授权沙箱中启动和观察某种运行时”：

- JVM、Node、Python 或其他运行时分别声明 capability、版本、镜像/运行时摘要和 observation kinds；
- 固定命令模板、挂载、UID、网络和预算由服务端 Run Profile 生成；
- runtime hook/agent 只产生 RuntimeObservation，不是授权或不可篡改边界；
- 未通过独立 sandbox/release attestation 的 RuntimeAdapter 最高保持目标门禁允许的非 `VERIFIED` 状态；
- 新语言可以先交付静态 Analyzer，不能为追求对称性自动获得动态能力。

### 3.6 目标 Provider SPI

| Provider | 输出 |
|----------|------|
| `ArtifactProvider` | Artifact Universe 节点与未展开 gap |
| `EntryProvider` | EntrySurface 与注册证据 |
| `TrustBoundaryProvider` | source/origin 与信任边界 |
| `EffectModelProvider` | primitive/custom SensitiveEffect |
| `GuardModelProvider` | guard、ownership、tenant 与状态条件 |
| `SanitizerModelProvider` | sanitizer/validator 语义 |
| `MethodSummaryProvider` | framework/dependency 方法摘要 |
| `DetectorProvider` | SecurityHypothesis |
| `DynamicProbeProvider` | server-gated ExperimentPlan |

Provider 输出必须 schema-versioned、带 analyzer version/coverage/stop reason，并通过统一去重和 scope 校验。插件不得直接写 Finding 或验证状态。

## 4. AuthCoverage 判断框架

鉴权不是「缺注解 = 漏洞」。对每个入口维护覆盖矩阵：

| 层 | 问题 | 示例证据 |
|----|------|----------|
| 声明层 | 入口/类/包是否声明鉴权 | `@PreAuth`、`@PreAuthorize`、matcher |
| 管道层 | Filter/Interceptor/网关是否覆盖路径 | `web.xml` Filter、Blade secure |
| 代码层 | handler 内自写校验 / AuthUtil | 调用点、启发式 |
| 运行层 | 匿名/弱身份探针结果 | 401/403/200 + Agent 轨迹 |
| 语义层 | 敏感 sink 是否在屏障之后 | 路径/轨迹顺序 |

每层取值：`present | absent | unknown | contradicted`，并挂证据引用。
`AUTH_GAP` 仅表示「声明层 absent 且管道/代码仍 unknown」一类信号，状态最高 `STATIC_INFERRED`，不得无重放升 `VERIFIED` 或 `DYNAMIC_CONFIRMED`。鉴权覆盖与**平台合成身份**、多轨 PathRun 实验见 [PATH_EXPERIMENT_MODEL.md](PATH_EXPERIMENT_MODEL.md)；AuthCoverage AnalysisPack 为合成材料与轨选择提供 FACT，AI `AUTH_ANALYSIS` 只解释与编排，不改写 FACT。

能力诚实分档：

- **A 契约识别**：常见框架表面
- **B 结构推断**：不认框架名，认请求/校验/sink 形状
- **C 运行证实**：静态不清则预算内刺激

自研框架通常 A 弱、B+C 强。

## 5. 动态与依赖替身

- 依赖替身插件化：`JdbcMock`、`RedisRespMock`、`MysqlClassicMock` 等按需启用；主机侧替身引擎不偷偷放开 Docker 外连。当前实现是有界协议子集，不等同于完整 Redis/MySQL 兼容性。
- 探针计划绑定不可变 scan；超预算入口记 `UNREACHED`，不静默丢弃。
- 轨迹与结论：`MOCK` / `DYNAMIC_SUSPECTED` / `DYNAMIC_CONFIRMED` / `INFERENCE`；`VERIFIED` 仅在强化沙箱可重放门禁之后；SQL 恶意片段无过滤入库由服务端升 `DYNAMIC_CONFIRMED`。
- 动态事件统一投影 Entry、Guard、Effect、State、Dependency 与 Exception，使用稳定 IR ID 对齐静态节点。
- DynamicProbeProvider 只把 `SecurityHypothesis` 编译为实验形状，网络、命令、挂载、UID、预算和授权仍由服务端固定。

## 6. 扩展顺序

1. 保真持久化现有 BytecodeFactIndex、coverage、unresolved facts 与 runtime observation。
2. 建立 Security IR、SecurityHypothesis 和版本化 Provider SPI。
3. 建立 Analyzer/Runtime 协议和 contract test，在当前 Java 工程内先形成 transport/domain/adapter 端口。
4. 将 Executable JAR、JVM facts、Spring MVC、固定 sink 表和 AuthCoverage 迁成默认 ArtifactPackager、LanguageAnalyzer、FrameworkAdapter 与 AnalysisPack，并验证兼容投影等价。
5. 增加 Servlet/Filter/WebFlux/消息入口、Guard/Ownership detector 和 JVM method summary。
6. 使用 Test Analyzer 验证错误 scope/digest/schema、部分分块、超预算与迟到结果 fail-closed。
7. 接入第二语言静态 LanguageAnalyzer，要求同一 Control Plane、Security IR、coverage matrix 和 GUI，不复制流水线。
8. 第二语言静态合同稳定后再独立评估 RuntimeAdapter；未完成 attestation 时不开放动态验证。

## 7. 明确不做

- 不承诺静态完整覆盖一切自研鉴权或非常规 MVC。
- 不做「一个万能框架解析器」。
- 不在 Control Plane 进程内堆入所有语言工具链或第三方 Analyzer 插件。
- 不为新语言复制控制面、数据库、流水线、权限和 GUI。
- 不把适配器数量等同于结论真实性；没有运行层就只能推测。
- 不在无重放证据时输出 `VERIFIED`。
- 不允许插件绕过 Security IR 直接写 Finding、工具权限或验证状态。
- 不把“匹配到 FrameworkAdapter/AnalysisPack”当成漏洞召回或验证成功。

## 8. 验收口径

扩展验收以“新增 ArtifactPackager/LanguageAnalyzer/FrameworkAdapter/AnalysisPack 后，Artifact Universe/Security IR/coverage matrix 出现对应节点、关系和 gap；detector 在基准、变异和保留集上达到声明召回率；通过独立审计的 RuntimeAdapter 能用断网实验支持或反证假设”为准。第二语言必须复用同一控制面和 GUI，并通过 Analyzer 协议的 scope/digest/budget/终态负例。适配器、规则和插件数量不能替代召回率、误报与证据门禁测试。

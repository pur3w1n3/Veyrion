# 可扩展分析架构（JAR 先行）

状态：已确认产品方向（2026-07-26）。本文件描述中立事实模型与插件边界；**当前实现仍以可执行 Spring Boot JAR + Spring/Blade 适配为主**，WAR/自研框架按同一骨架增强，而不是另起一套流水线。产品面向个人本地使用，不包含完整多租户/RBAC 或真实供应商生产互操作；任何动态适配都必须通过用户授权的沙箱，不能退回宿主机执行。

## 1. 目标

闭源 JVM 制品形态（JAR/WAR/CLASS）与框架写法差异很大：标准 Spring MVC、Blade 注解、Servlet/`web.xml`、自写 Filter，乃至非常规 Dispatcher。平台不能把「Spring Boot JAR + `@PreAuthorize`」写死为唯一路径，又不能承诺静态规则一次覆盖所有自研鉴权。

因此采用：

```text
中立事实模型（稳定）
  + Packager / FrameworkAdapter / AnalysisPack（可插拔增强）
  + 动态运行与证据分层（可证伪）
```

## 2. 中立事实模型

控制面与 GUI 只依赖下列概念（与制品形态、框架名无关）：

| 对象 | 含义 |
|------|------|
| `ArtifactSurface` | 可读字节视图：class、配置、`web.xml`、资源 |
| `EntryCandidate` | 外部可达面候选（HTTP/RPC/消息/…） |
| `AuthBarrierHint` | 可能挡请求的点（注解、Filter、自写校验、安全配置） |
| `IdentitySurface` | 身份材料从哪来（Header/Cookie/Session/JWT/自定义） |
| `SinkCandidate` | 敏感副作用候选 |
| `Evidence` | `FACT` / `RUNTIME_OBSERVED` / `MOCK` / `INFERENCE` 等 |
| `CoverageJudgment` | 对入口的**覆盖分层结论**，不是漏洞终局判决 |

现有 `@RequestMapping`、`@PreAuth`、`AUTH_GAP` 只是某一 FrameworkAdapter 往该模型填充的一种输出。

## 3. 三条正交扩展轴

### 3.1 Packager（制品适配器）

解决「怎么打开、怎么跑」：

| Packager | 静态 | 动态（演进） |
|----------|------|--------------|
| Executable Spring Boot JAR | `BOOT-INF` class | 现有 `TRUSTED_DOCKER` + `java -jar`（**已落地**） |
| WAR | `WEB-INF` + `web.xml` | 后续嵌入式容器或专用 runtime |
| 库式 JAR / CLASS | API/类面 | 可能仅静态 + harness |

共享：预算、断网、Agent 事件契约、`DYNAMIC_SUSPECTED`、依赖 mock 接口——**不**共享「一定 `java -jar`」。

### 3.2 FrameworkAdapter（框架适配器）

解决「怎么发现入口与鉴权屏障」；可多适配器并行，结果合并去重：

1. Spring MVC + Security / Blade secure（**JAR 切片已部分落地**；MVP-2 已抽出 `FrameworkAdapter` SPI：`SpringMvcAdapter` / `SpringBladeAdapter` / `FrameworkAdapterRegistry`，探针高价值信号改查注册表，`FrameworkAdapterAcceptanceTest` 可注入 TestOnlyAdapter）
2. Servlet / `web.xml` / Filter（WAR 与大量自研的公约数）— **未做**
3. 结构推断：方法签名吃 `HttpServletRequest`、靠近 `getParameter`→sink 的调用形状 — **未做**

合并规则：同路由多命中则合并证据；冲突标 `contradicted`；无适配器命中时允许大量 `unknown`（合法，不是失败）。

### 3.3 AnalysisPack（分析包）

按风险域挂载，例如：

- **AuthCoverage**（优先）：见第 4 节
- Injection / Deser / SSRF 等后续包

AI 与 checklist 只作候选目录，不能改工具权限或单独升 `VERIFIED`。

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

## 6. JAR 先行落地顺序

1. 抽出中立模型与 AuthCoverage 矩阵语义（文档本文件；代码逐步对齐）。
2. 将现有 Spring/Blade 规则视为第一个 FrameworkAdapter 输出。
3. ExecutableJar Packager + 多入口探针 + JDBC/Redis/MySQL 协议替身（JAR 切片已落地，均受预算和 `MOCK` provenance 约束）。
4. 下一步：Servlet/Filter 适配器 → WAR 静态视图 → WAR LaunchPlan。
5. 再下一步：结构推断 B 档与合成身份探针。

## 7. 明确不做

- 不承诺静态完整覆盖一切自研鉴权或非常规 MVC。
- 不做「一个万能框架解析器」。
- 不把适配器数量等同于结论真实性；没有运行层就只能推测。
- 不在无重放证据时输出 `VERIFIED`。

## 8. 对外可宣传口径

> 在预算内尽量填满入口的鉴权覆盖矩阵，并标明哪一层仍是 unknown；对能跑的制品用断网动态去支持或反证。全面覆盖是连续增强的切片，不是一次 PR。

# ADR-0002: JVM 静态分析内核（轻量 kernel + 自研加深）

- Status: `ACCEPTED`（根 Agent 2026-07-28：继续轻量 kernel + 加深自研；暂不引入 Soot/WALA；完整引擎须进程外独立 ADR）
- Date: 2026-07-28
- Owners: root Agent (accepted); implementation Agents for deepen slices
- Related: P1-04、P0-11、Universe Boot lib 一层展开、P2 STATE/CONCURRENCY、[EXTENSIBLE_ANALYSIS](../EXTENSIBLE_ANALYSIS.md)、[ADR-0001](0001-polyglot-control-plane-and-workers.md)

## Context

当前 JVM 垂直切片使用自研有界 classfile 解析（constant-pool / 注解 / 指令扫描 / 参数起源流）产出 `BytecodeFactIndex`、制品内 CHA 调用图和有界 `TaintPath`。`analysis.kernel` 已提供可序列化 CFG、MethodSummary bottom-up 与 field/return/sanitizer 钩子；`code_query` `CFG_VIEW` 消费 `CfgBuilder`。

成熟引擎（Soot、WALA、SpotBugs 数据流等）能提供真正 SSA、points-to 与 IFDS/IDE，但会：

- 显著扩大 Control Plane 依赖面与启动成本；
- 引入完整 classpath/类型解析假设，与“制品内有界、fail-closed coverage”基线冲突；
- 与 ADR-0001 的进程外 LanguageAnalyzer 边界重叠，容易把重型分析重新塞回控制面。

根审计已将轻量 kernel 标为声明范围内 `AUDITED`。本 ADR 明确：**在引入进程外重型引擎之前，产品路径是继续加深自研轻量 kernel，暂不改引 Soot/WALA。**

## Decision

1. **暂不引入 Soot / WALA / 其他重型静态引擎依赖**到 Control Plane。完整 SSA/points-to/IFDS 留给后续**进程外** JVM Analyzer 选型（独立 ADR）。
2. **ACCEPTED 实施路径 = 继续轻量 `analysis.kernel` + 加深自研**，在有界预算与 coverage honesty 下提升召回：
   - MethodSummary / Sanitizer：从 IR 调用边、sink/guard/sanitizer 启发式填充，默认对命中方法非空（provenance=`KERNEL_INFERENCE` / `INFERENCE`）；
   - `code_query` `METHOD_VIEW`：增加有界伪反编译文本行（由 bci / 合成 opcode 标签 / evidence 拼装，**不**读宿主任意文件）；
   - Artifact Universe：`BOOT-INF/lib`（及 `WEB-INF/lib`）**有界展开一层**（可选 jar 内 class 计数上限），截断时显式 `CoverageGap`；
   - 保留现有 classfile 快速索引作为 fallback；内核只消费已产出事实。
3. **`code_query` `CFG_VIEW` 继续优先消费 `CfgBuilder`**；无法构建时回退 bci gap/`basicBlocks`。
4. 内核输出不得补写 FACT 或提升验证状态；必须保留 coverage / stop reason。

## Alternatives

### 立即嵌入 Soot 或 WALA

分析能力更强，但依赖重、classpath 语义与沙箱/信任边界不清，且与进程外 Analyzer 路线重复。**拒绝（本阶段）**。

### 引入 ASM tree/analysis API 替换自研解析

可降低自维护指令表成本；可作为后续小步 ADR，**非本决策**。

### 仅写文档不落地加深

无法让 METHOD_VIEW / Universe / MethodSummary 消费真实合同。**拒绝**。

## Consequences

正面影响：

- 根可批 ACCEPTED 而不扩大 Maven 依赖面；
- MethodSummary/Sanitizer、伪反编译切片、Boot lib 一层展开有明确加深合同；
- 为进程外成熟引擎预留同一序列化形状替换点。

成本与限制：

- 非真正 SSA / IFDS；分支、异常边、容器别名、异步/反射仍不完整；
- 伪反编译是有界证据投影，不是完整反编译器；
- Boot lib 只展开一层；嵌套 jar 内的 jar / 超预算 class 仍为 gap；
- MethodSummary bottom-up 与名称启发式可误报/漏报，需 fixture + holdout 度量。

## Security

- 内核只读已持久化/已解析事实，不加载被测类、不执行字节码、不读宿主任意路径。
- 输出不得改变工具 allowlist、沙箱、授权或验证状态。
- AI / 前端不能把内核推断写成 FACT。

## Compatibility

- 不改公共 `/api/v1` 必填字段；`METHOD_VIEW` 可附加 `pseudoDecompile` / `pseudoSourceLines`；`CFG_VIEW` 保留既有字段。
- 不改 SQLite schema。
- Universe `DependencySummary.expanded` 在一层展开成功（含有界截断）时可为 `true`；截断 gap 显式。

## Migration

1. 本 PROPOSED 更新 + Backlog §8.2 加深项。
2. 落地 MethodSummary/Sanitizer 启发式、METHOD_VIEW 伪反编译、Boot lib 一层展开、P2 recall gate。
3. `AcceptanceTestRunner` PASS。
4. 本 ADR 已由根 Agent 标为 `ACCEPTED`；完整引擎接入需独立 ADR 与进程外合同。

## Validation

- `StaticAnalysisKernelAcceptanceTest`：MethodSummary/Sanitizer 启发式非空、budget/stopReason、CFG_VIEW。
- `ArtifactUniverseAcceptanceTest`：Boot lib 一层展开 + 截断 gap。
- `code_query` METHOD_VIEW：伪反编译行有界且不读宿主文件。
- `P2DetectorEntryAcceptanceTest` + baselines：STATE/CONCURRENCY 正负/holdout + `DetectorRecallGate`。
- `AcceptanceTestRunner` PASS。
- Backlog：ADR-0002 写 `ACCEPTED`；加深项与 P2 声明范围按证据更新。

# Veyrion 架构迁移路线图（Migration Roadmap v1.0）

> 审查基准：代码实测 2026-07-27  
> 对齐目标：`docs/参考架构.md` — 发现（Discover）→ 验证（Verify）→ 规划（Plan）→ 迭代（Iterate）  
> 核心原则：保留现有证据分层 / PathRun / ContrastLedger / 沙箱闸门，填充闭环缺口，不推倒重来

---

## 一、当前能力精确对照（代码实测）

### 1.1 已有强项（保留不动）

| 模块 | 实现状态 | 关键设计价值 |
|------|---------|------------|
| 六角色 AI 流水线 | ✅ `AuditPipelineCoordinator`（245行，状态机清晰） | 确定性推进，不可被模型跳过 |
| PathRun 一等公民 | ✅ `scanId+entryId+track+attemptId` 四元主键 | 实验可追溯、可重放 |
| ContrastLedger | ✅ STATIC_ONLY/MATCHED/PARTIAL/DYNAMIC_ONLY 状态机 | 确定性引擎，不占 AI 角色 |
| 证据分层 | ✅ FACT/RUNTIME_OBSERVED/MOCK/INFERENCE 四层 | 模型不能单独升 VERIFIED |
| 沙箱闸门 | ✅ `--network none` + `TRUSTED_DOCKER` + 工具 allowlist | 服务端不可被模型改写 |
| 污点分析 | ✅ 有界跨方法 TaintPath（有 budget/stopReason） | 诚实边界标注，不虚报 |
| 身份合成 | ✅ Blade HS256/alg:none + 自动密钥猜测 | JWT 密钥从 JAR 自动提取 |
| SQLite 持久化 | ✅ V001–V014，幂等键+恢复机制 | 重启可继续，不丢失进度 |

### 1.2 关键缺口（代码实测确认）

| 参考架构需求 | 当前代码状态 | 缺口严重度 |
|------------|------------|----------|
| Branch Coverage 采集 | `LocalArtifactWorkerLoop`：无任何 JVM coverage | 🔴 最高——闭环断层 |
| DFG 图结构 | `InterproceduralTaintAnalyzer`：仅线性 TaintPath 列表，无图查询接口 | 🔴 高 |
| Candidate Ranking | `PreAnalysisService`：SinkCatalog 按发现顺序，无排序接口 | 🟡 中 |
| 分支约束提取 | `ClassFileMetadataParser.scanFlow()`：遇分支 `clearStack()` 丢精度 | 🟡 中 |
| 覆盖率驱动迭代 | `ContrastLedger`：无 snapshotId / 多轮 diff | 🟡 中 |
| Fuzz 策略类型化 | `sandbox_probe`：参数输入无 sink-aware 策略 | 🟡 中 |
| Root Cause 结构化 | REPORT_GENERATION：叙述式文本，无 AttackStep 结构 | 🟡 中 |
| 多语言支持 | `ClassFileMetadataParser`：JVM 专用，无 IR 抽象 | 🟢 低（远期） |
| FrameworkAdapter SPI | 规则散落：`containsHighValueSignal()` 等硬编码 | 🟡 中 |

---

## 二、AI 角色现状与调整方向

### 2.1 当前六角色职责

```
PRE_ANALYSIS        → 前置建模：读静态 Fact，补充入口 (MODEL_SUPPLEMENT)
AUTH_ANALYSIS       → 鉴权模型：生成 bypassPoCs (Authorization/JWT/query/body)
DYNAMIC_VERIFICATION → 消费 AUTH_BYPASS_FEASIBILITY，调用 sandbox_probe
PATH_EXPLORATION    → 消费 PathRun + ContrastLedger，生成 nextExperiments
VULNERABILITY_TRIAGE → 证据约束研判，不可单独升验证级
REPORT_GENERATION   → Markdown 报告，强制 ContrastLedger 入账
```

### 2.2 调整后角色映射（对照参考架构）

```
参考架构 Agent          → Veyrion 角色调整方向
────────────────────────────────────────────────────
Static Agent           → PRE_ANALYSIS（增加 TaintGraph + RankedSinkCatalog 注入）
Runtime Agent          → [确定性引擎，非 AI 角色] Agent trace + CoverageJoiner
Fuzz Agent             → DYNAMIC_VERIFICATION（增加 fuzz_strategy_get 工具）
Planner Agent          → PATH_EXPLORATION（增加 COVERAGE_GAP_FACTS 注入）
Verification Agent     → VULNERABILITY_TRIAGE（增加 Root Cause 结构化输出）
Report Agent           → REPORT_GENERATION（增加 AttackPath + LedgerDiff）
```

### 2.3 角色调整细节

**PRE_ANALYSIS（扩展）**

当前：读取静态入口/依赖/权限/sink，补充 MODEL_SUPPLEMENT  
调整后新增注入段：
- `RANKED_SINK_CATALOG`：按 score 排序的 sink 列表（CandidateRanker 输出）
- `TAINT_GRAPH_SUMMARY`：TaintGraph 节点/边数统计 + 高风险路径摘要
- `BRANCH_CONSTRAINT_FACTS`：已提取的参数约束（maxLen/enum/等值）

新增工具权限：`code_query kind=TAINT_GRAPH`（读取 TaintGraph 子图）

**AUTH_ANALYSIS（调整）**

当前：生成 bypassPoCs，洪水后续跑确认  
调整后新增注入段：
- `FRAMEWORK_ADAPTER_CONTEXT`：FrameworkAdapter 匹配结果（如"检测到 SpringBlade，默认 key 已提取"）
- `PARAMETER_CONSTRAINT_HINTS`：参数类型/约束（辅助生成更精确的auth header）

变化：`bypassPoCs.authorizationHeader` 字段允许携带从 ParameterConstraint 推导的 token claim

**DYNAMIC_VERIFICATION（扩展为 Fuzz Agent）**

当前：消费 `AUTH_BYPASS_FEASIBILITY`，强制调用 `sandbox_probe`  
调整后新增工具：`fuzz_strategy_get(sinkId, sinkCategory)`  
新增注入段：`FUZZ_STRATEGY_CONTEXT`（sink 类型化探针模板）  
新增输出字段：`selectedProbes: [FuzzProbe{name, input, expectedSignal}]`

示例（SQL Injection）：
```
fuzz_strategy_get → SQL
→ benign_input: "normal_value"
→ meta_char_probe: "'"
→ union_probe: "' UNION SELECT 1,2,3--"
→ error_probe: "1 AND 1=CONVERT(int,'a')--"
```

**PATH_EXPLORATION（升级为 Planner Agent）**

当前：消费 PathRun + ContrastLedger，生成 nextExperiments（无结构化 coverage 指导）  
调整后新增注入段：`COVERAGE_GAP_FACTS`（未命中分支 + TaintPath 对应关系）

```
COVERAGE_GAP_FACTS 格式：
[
  {
    "taintPathId": "tp-001",
    "uncoveredStep": "UserController#getUser → UserRepository#findById",
    "branchCondition": "role == 'ADMIN'（从 BranchConstraint 推导）",
    "suggestedTrack": "ADMIN",
    "suggestedInput": "userId=1 with ADMIN JWT"
  }
]
```

AI 对每条 gap 生成 `nextExperiment`（已有结构），服务端 `ExperimentPlanValidator` 校验

**VULNERABILITY_TRIAGE（扩展 Root Cause）**

当前：围绕 PathRun 研判，无入口命中不得宣称漏洞  
调整后新增输出结构：
```json
{
  "rootCause": {
    "attackSteps": [
      {"layer": "HTTP", "label": "POST /api/user/query", "evidence": "entry:xxx"},
      {"layer": "param", "label": "username 参数无过滤", "evidence": "tp-001:step-2"},
      {"layer": "sink", "label": "PreparedStatement 退化为拼接", "evidence": "sql-event:xxx"}
    ],
    "rootCauseStatement": "缺少参数化查询，外部输入直接拼入 SQL 语句",
    "affectedComponent": "UserRepository#findByUsername",
    "cweId": "CWE-89",
    "fixSuggestion": "改用 PreparedStatement 参数占位符"
  }
}
```

服务端 schema 校验 `rootCause` 结构（不允许 INFERENCE 标注跳过 evidence 引用）

**REPORT_GENERATION（增加多轮 diff + AttackPath 可视化）**

当前：Markdown 报告，强制 ContrastLedger 入账  
调整后新增段：
- `## 攻击路径` → 自动从 `attackSteps[]` 生成 Mermaid flowchart
- `## 迭代对比` → LedgerDiff 摘要（新命中/回退/覆盖率变化）
- `## 修复建议` → fixSuggestion + CWE 映射

---

## 三、MVP 开发周期

### MVP-1：Branch Coverage + Candidate Ranking（V0.2）
**目标**：打通「覆盖率 → AI 规划 → 覆盖率提升」最小闭环  
**预期工时**：2–3 周

#### 改动清单

**A. JVM Branch Coverage 采集（`agent/` 模块）**

新增文件：`agent/src/.../instrumentation/BranchCoverageInstrumentation.java`
```
职责：在每个分支指令（ifeq/ifne/iflt/.../tableswitch/lookupswitch）前插桩
实现：Byte Buddy MethodVisitor，记录 classname#methodDesc#branchIdx → hit
格式：每次 HTTP 请求前 reset bitset，请求结束 flush 到 JSONL
event type: BRANCH_COVERAGE
payload: {classname, methodDesc, branchMap: {"0": true, "1": false, ...}}
```

新增文件：`agent/src/.../CoverageEventSerializer.java`
```
将 branch hit bitset 序列化为 JSONL coverage event
与现有 trace 共用 AgentJsonlTraceConverter 管道，无需改现有 trace 格式
```

改动：`ExternalArtifactTaskExecutor.java`
```
启动命令加入：-Dveyrion.coverage.enabled=true
trace 处理时识别 BRANCH_COVERAGE event，路由给 CoverageJoiner
```

**B. 静态-动态 Coverage Join（`analysis/contrast/` 模块）**

新增文件：`analysis/contrast/TaintPathCoverageJoiner.java`
```java
// 输入：TaintPath 列表（静态）+ PathRunDto.branchHitMap（动态）
// join 逻辑：
//   若 TaintPath.steps 中 callerClass+methodDesc 在 branchHitMap 中有命中
//   → TaintPath.dynamicStatus = DYNAMIC_REACHED
//   否则保持 STATIC_ONLY
// 输出：TaintPath 状态升级列表，写回 ContrastLedger
```

改动：`ContrastLedger.java`
```
新增字段：snapshotId: String（per-scan per-round UUID）
新增字段：roundIndex: int
ContrastStatus 枚举新增：DYNAMIC_REACHED（介于 STATIC_ONLY 和 MATCHED 之间）
```

改动：`ApiDtos.PathRunDto`
```
新增字段：branchHitMap: Map<String, List<Integer>>
  key = "classname#methodDesc", value = 命中的 branchIdx 列表
```

**C. Candidate Ranking（`analysis/` 模块）**

新增文件：`analysis/CandidateRanker.java`
```
输入：SinkCatalog + TaintPaths + PermissionMatrix + ContrastLedger（可选）
排序维度（加分规则）：
  confidence（已有基准：0.95/0.78/0.72/0.62）
  + 0.15：有直接 TaintPath 覆盖
  + 0.10：高风险类别（JNDI/RCE/DESERIALIZATION/SQLi）
  + 0.05：AUTH_GAP（无鉴权注解）
  + 0.20：dynamicReached（有 branch hit，动态轮才有）
输出：List<RankedSinkView(sinkId, rank, score, rankReason[])>
```

改动：`ControlPlaneStore.ScanRecord` + dashboard API
```
新增：rankedSinks 字段（dashboard 和 PRE_ANALYSIS prompt 注入）
```

改动：PRE_ANALYSIS prompt 模板（`role_bindings.promptZh/promptEn`）
```
新增注入段：RANKED_SINK_CATALOG
格式：rank | sinkId | category | score | reasons
最多注入前 20 条（预算控制）
```

**数据库迁移**：`V016__branch_hit_map_and_contrast_ledger_snapshots.sql`（**非**原稿草稿名 `V015__branch_coverage_and_ranking.sql`）
```sql
-- PathRun 增加 branch_hit_map_json 列
ALTER TABLE path_runs ADD COLUMN branch_hit_map_json TEXT;
-- ContrastLedger snapshot 表
CREATE TABLE contrast_ledger_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    round_index INTEGER NOT NULL,
    ...
);
```

#### MVP-1 验收标准
- [x] 单入口执行后，`PathRunDto.branchHitMap` 非空（投影 + merge；live JAR 仍可选）
- [x] 对应 TaintPath `dynamicStatus` 升级为 `DYNAMIC_REACHED`
- [x] Dashboard `rankedSinks` 按 score 排序，rankReason 可读
- [x] 有覆盖观测后 `ContrastLedger.roundIndex>=1`，snapshotId 稳定派生
- [x] `AcceptanceTest`：`BranchCoverageAcceptanceTest`（合成 fixture；live `VEYRION_TEST_ARTIFACT_JAR` 可选）

**版本注记**：本 MVP 使用 **V016**（`branch_hit_map_json` + `contrast_ledger_snapshots`）；**V015** 已专用于 schemaVersion 护栏（Step 1）。

---

### MVP-2：参数约束深化 + AI 路径规划闭环（V0.3）
**目标**：PATH_EXPLORATION 基于 coverage gap 提出有效的下一轮实验  
**预期工时**：2–3 周

#### 改动清单

**A. 分支约束提取（`analysis/ClassFileMetadataParser.java` 补丁）**

不重写分析器，新增后处理层：

新增文件：`analysis/BranchConstraintHarvester.java`
```
输入：ClassMetadata（已有）中的 InvocationFlowFact 列表
识别模式（callee-side 匹配，无需 CFG 重建）：
  INVOKEVIRTUAL String.equals(Object) + 字面量参数 → {param, EQUALS, "literal"}
  INVOKEVIRTUAL String.length() + IF_ICMP_GT → {param, MAX_LEN, n}
  GETSTATIC EnumClass.values() → {param, ENUM, EnumClass}
  INVOKEVIRTUAL Integer.parseInt / Long.parseLong → {param, TYPE, integer}
输出：List<ParameterConstraint(paramIndex, constraintType, literal)>
```

改动：`Entrypoint` 模型（`model/Entrypoint.java`）
```java
// parameters 字段从 List<String> 升级为 List<ParameterSpec>
record ParameterSpec(
    String name,
    String type,           // string/integer/boolean/enum
    List<ParameterConstraint> constraints,
    String origin          // ANNOTATION | FLOW_FRAME | INFERRED
) {}
```

改动：`PreAnalysisService.discoverAnnotatedEntries()`
```
在构建 Entrypoint 时调用 BranchConstraintHarvester.harvest(classMetadata, methodIdx)
将约束列表填入 ParameterSpec
```

改动：`ENTRY_SUMMARY` prompt 注入段
```
每个参数从 "name=username" 扩展为：
  "username: type=string, maxLen=32 [BranchConstraint:strlen], required=true [annotation]"
  "role: type=enum, values=[admin,user,guest] [BranchConstraint:enum]"
```

**B. Coverage Gap 注入 PATH_EXPLORATION**

新增文件：`analysis/CoverageGapProjector.java`
```
输入：TaintPaths + ContrastLedger（当前轮）+ 已有 PathRuns
输出：List<CoverageGap>
CoverageGap: {
    taintPathId, uncoveredStep（callerClass#method → calleeClass#method）,
    branchCondition（从 ParameterConstraint 推导，如 "role == 'ADMIN'"）,
    suggestedTrack, suggestedInput, confidence
}
最多输出 16 条（预算控制）
```

改动：PATH_EXPLORATION prompt 模板
```
新增注入段：COVERAGE_GAP_FACTS
要求 AI 对每条 gap 生成 nextExperiment，格式对齐现有 ExperimentPlan 结构
服务端 ExperimentPlanValidator 校验：参数名在入口列表中，值不超过 maxLen
```

**C. FrameworkAdapter SPI**

新增目录：`analysis/framework/`

新增文件：`analysis/framework/FrameworkAdapter.java`（接口）
```java
public interface FrameworkAdapter {
    String id();
    boolean matches(Path artifactPath, List<String> routes);
    Set<String> highValueRouteSignals();
    Set<String> highValueClassSignals();
    boolean preferBladeAuthHeader(SyntheticIdentityService.MaterialBundle materials);
    Optional<String> suggestJwtSecret(Path artifactPath);
    List<AuthBypassTechnique> defaultBypassTechniques();
}
```

新增文件：`analysis/framework/SpringBladeAdapter.java`
```
迁入 ControlPlaneServer.containsHighValueSignal() 中的 Blade 相关词表
迁入 ControlPlaneServer.materialsPreferBladeAuth() 逻辑
```

新增文件：`analysis/framework/SpringMvcAdapter.java`
```
通用 Spring MVC 支持（非 Blade 框架的默认 Adapter）
```

新增文件：`analysis/framework/FrameworkAdapterRegistry.java`
```java
// 注册表，matches() 联合所有 Adapter 信号
public static List<FrameworkAdapter> matching(Path artifactPath, List<String> routes) {...}
```

改动：`ControlPlaneServer.containsHighValueSignal()` → 改为查询 `FrameworkAdapterRegistry`  
改动：`ControlPlaneServer.materialsPreferBladeAuth()` → 删除，移入 `SpringBladeAdapter`

**数据库迁移**：无独立 SQL（原稿草稿名 `V016__parameter_spec.sql` **未采用**；V016 已用于 MVP-1 分支覆盖）
```sql
-- 已有 scan 的 entries 中 parameters 字段做兼容读（旧格式 List<String> 仍可解析）
-- 无需 schema 变更，通过 ParameterSpec.origin=LEGACY 标记旧数据
```

#### MVP-2 验收标准
- [x] BranchConstraintHarvester 产出 maxLen / equals 约束（合成 flow hints；Blade live 可选）
- [x] PATH_EXPLORATION 注入 `COVERAGE_GAP_FACTS`（STATIC_ONLY → CoverageGap）
- [ ] 第二轮执行使用 CoverageGap 生成的 suggestedInput，对应分支 branchHitMap 命中（**live 可选，未宣称完成**）
- [x] 新增 `FrameworkAdapterAcceptanceTest`：TestOnlyAdapter 可注入

**版本注记**：参数规格兼容读，无需独立 SQL；下一库版本为 MVP-3 的 **V017**。

---

### MVP-3：TaintGraph + 多轮迭代对比（V0.4）
**目标**：TaintPath 升级为可查询图；ContrastLedger 支持多轮 diff  
**预期工时**：2 周

#### 改动清单

**A. TaintGraph（DataFlow Graph）投影**

新增文件：`analysis/TaintGraphProjector.java`
```java
// 输入：List<TaintPath>（已有）
// 投影逻辑：
//   for each TaintPath.steps:
//     提取 (callerClass#method, calleeClass#method, argumentIdx) → TaintEdge
//   合并相同节点 → 形成 DAG
// 输出：TaintGraph{nodes: [TaintNode], edges: [TaintEdge]}
// 约 100 行，纯投影，不改 InterproceduralTaintAnalyzer
```

```java
record TaintNode(
    String id,           // classname#methodDesc#kind
    NodeKind kind,       // SOURCE | TRANSFORM | SINK
    String classname,
    String methodDesc,
    int paramIdx         // -1 if not param-related
) {}

record TaintEdge(
    String from,         // TaintNode.id
    String to,
    EdgeKind edgeKind,   // DIRECT | CHA | UNRESOLVED（复用 BytecodeFactIndex）
    String callSite      // callerClass#method:lineNum
) {}
```

改动：`BytecodeFactIndex`
```java
// 新增 taintGraph() 方法，返回 TaintGraph（懒加载投影）
public TaintGraph taintGraph() {
    if (cachedGraph == null) {
        cachedGraph = TaintGraphProjector.project(this.interproceduralTaintPaths());
    }
    return cachedGraph;
}
```

**B. code_query 工具扩展**

改动：`ai/tool/CanonicalToolContracts.java` + `ControlPlaneToolDataSource.java`
```java
// 新增 code_query kind=TAINT_GRAPH
// 参数：entryId（可选）、sinkId（可选）、nodeId（可选）
// 返回：TaintGraph 子图（JSON 格式）
// 预算：最多返回 50 nodes + 100 edges（防止 prompt 爆炸）
```

PATH_EXPLORATION 工具白名单新增：`code_query(kind=TAINT_GRAPH)`

**C. ContrastLedger 多轮 diff**

改动：`ContrastLedger.java`
```java
// 已在 MVP-1 新增 snapshotId / roundIndex
// 本 MVP 新增字段：
record StaticContrastRow(
    ...,
    int firstSeenRound,      // 第几轮首次发现
    int lastHitRound,        // 最近被动态命中的轮次
    int hitCount             // 累计命中次数（跨轮）
) {}
```

新增文件：`analysis/contrast/LedgerDiff.java`
```java
// 输入：Ledger(roundN), Ledger(roundN-1)
// 输出：LedgerDiffResult
record LedgerDiffResult(
    List<String> newlyMatched,        // STATIC_ONLY → MATCHED/DYNAMIC_REACHED
    List<String> regressions,         // 上轮命中本轮未命中
    int unchangedCount,
    float coverageDelta               // 命中 TaintPath 比例变化
) {}
```

改动：REPORT_GENERATION prompt 注入段 `CONTRAST_LEDGER`
```
新增子段：LEDGER_DIFF_SUMMARY（当 roundIndex > 0 时注入）
格式：
  本轮新命中：3 条 TaintPath（列出 taintPathId）
  回退：1 条（列出 rowId + stopReason）
  覆盖率变化：+12%（从 45% → 57%）
```

**D. 动态结果回写静态 TaintPath**

新增文件：`analysis/DynamicFeedbackApplier.java`
```java
// 执行时机：AuditPipelineCoordinator.onDynamicTaskFinished() 之后
// 逻辑：
for (PathRun run : currentRoundPathRuns) {
    if (run.entryHit && run.parameterBound && run.sqlEvents.hasFragments()) {
        // 找到对应 TaintPath（通过 entrypointRef + sink 匹配）
        // 升级 TaintPath.status → DYNAMIC_SUSPECTED
    }
    if (DynamicConfirmedGate.check(run)) {
        // 升级 → DYNAMIC_CONFIRMED（服务端执行，模型不可改）
    }
}
// 持久化：scan.evidence 新增 DYNAMIC_TAINT_UPDATE 证据
```

改动：`ControlPlaneStore.ScanRecord`
```java
// scan.evidence 类型枚举新增：DYNAMIC_TAINT_UPDATE
// evidence.summary：例如 "TaintPath tp-001 状态升级：STATIC_INFERRED → DYNAMIC_SUSPECTED"
```

**数据库迁移**：`V017__taint_graph_and_ledger_diff.sql`
```sql
-- contrast_ledger_snapshots 表新增字段
ALTER TABLE contrast_ledger_snapshots
ADD COLUMN first_seen_round INTEGER,
ADD COLUMN last_hit_round INTEGER,
ADD COLUMN hit_count INTEGER DEFAULT 0;

-- taint_graph 缓存表（可选，性能优化）
CREATE TABLE taint_graphs (
    scan_id TEXT PRIMARY KEY,
    graph_json TEXT NOT NULL,  -- TaintGraph 序列化
    created_at TEXT NOT NULL
);
```

#### MVP-3 验收标准
- [x] `code_query kind=TAINT_GRAPH entryId=X` 返回包含至少 3 个 nodes 的子图（合成；`TaintGraphAcceptanceTest`）
- [x] 两轮执行后 LedgerDiff.newlyMatched 非空（合成 prior/current ledger）
- [x] DynamicFeedbackApplier 对至少一条 TaintPath 成功升级状态（evidence 可查；dashboard 触发 append）
- [x] Dashboard 显示 LedgerDiff 摘要（后端 `ledgerDiff` 字段；前端 ResultsPage 已接入）

**版本注记**：本 MVP 使用 **V017**（ledger hit 列 + `taint_graphs`）。

---

### MVP-4：Fuzz 策略生成 + 约束识别（V0.5）
**目标**：AI 生成针对性 payload 策略；Magic Number 识别  
**预期工时**：2 周

#### 改动清单

**A. Sink 类型化 Fuzz 策略**

新增文件：`analysis/fuzz/FuzzStrategyRegistry.java`
```java
// 根据 sink.category 返回策略模板
public static FuzzStrategy forSink(String category) {
    return switch (category) {
        case "SQL" -> sqlStrategy();
        case "JNDI" -> jndiStrategy();
        case "DESERIALIZATION" -> deserializationStrategy();
        case "SSRF" -> ssrfStrategy();
        case "PATH_TRAVERSAL" -> pathTraversalStrategy();
        case "COMMAND" -> commandStrategy();
        default -> genericStrategy();
    };
}

record FuzzStrategy(
    String sinkCategory,
    List<ProbeTemplate> probeTemplates
) {}

record ProbeTemplate(
    String name,              // "benign" | "meta_char" | "union" | ...
    String inputHint,         // AI 参考的输入提示
    String expectedSignal     // "SQL_ERROR" | "TIMEOUT" | "DNS_QUERY"
) {}
```

示例策略：
```java
private static FuzzStrategy sqlStrategy() {
    return new FuzzStrategy("SQL", List.of(
        new ProbeTemplate("benign", "normal_value", "200_OK"),
        new ProbeTemplate("meta_char", "'", "SQL_ERROR_OR_500"),
        new ProbeTemplate("union", "' UNION SELECT 1,2,3--", "STRUCTURE_DIFF"),
        new ProbeTemplate("error", "1 AND CONVERT(int,'a')", "SQL_ERROR_DETAIL")
    ));
}
```

**B. fuzz_strategy_get 工具**

改动：`ai/tool/CanonicalToolContracts.java`
```java
// 新增工具：fuzz_strategy_get
// 参数：sinkId（必填）, sinkCategory（可选，未提供则从 sink 查）
// 返回：FuzzStrategy（JSON 格式）
```

DYNAMIC_VERIFICATION 工具白名单新增：`fuzz_strategy_get`

改动：DYNAMIC_VERIFICATION prompt 模板
```
新增注入段：FUZZ_STRATEGY_CONTEXT
指导：调用 fuzz_strategy_get 获取策略模板，根据入口参数生成 candidateInputs
输出要求：selectedProbes 字段（对应 ProbeTemplate.name）
```

**C. 约束识别（AI 端，无 Z3）**

改动：DYNAMIC_VERIFICATION prompt 模板
```
新增注入段：BRANCH_CONSTRAINT_FACTS（复用 MVP-2 已有的 ParameterConstraint）
AI 负责：
  - 等值约束（if x == "magic"）→ candidateInputs 加入 literal
  - 范围约束（length < 32）→ candidateInputs 加入边界值（0, 31, 32, 33, -1, MAX_INT）
  - 类型约束（parseInt）→ candidateInputs 加入整数格式
输出：structuredConstraintHints（服务端验证后注入 ExperimentPlan）
```

**D. SqlDiffProbe 扩展（已有基础，增强）**

改动：`worker/SqlDiffProbe.java`
```java
// 现有：benign vs META_MARKER 差分
// 扩展：支持 FuzzStrategy 的多探针模式
// 输入：List<ProbeTemplate>（从 ExperimentPlan.metadata 读取）
// 对每个 template：生成 input → 执行 → 记录 SQL 文本 + 响应
// 输出：SqlDiffResult（扩展字段：probeResults: Map<probeName, SqlEvent>）
```

**数据库迁移**：`V018__fuzz_strategy.sql`
```sql
-- experiment_plans 表新增 fuzz_strategy_json 列
ALTER TABLE experiment_plans ADD COLUMN fuzz_strategy_json TEXT;
```

#### MVP-4 验收标准
- [x] `fuzz_strategy_get(sinkId=sql-001)` 返回包含至少 3 种 ProbeTemplate 的策略（`FuzzStrategyAcceptanceTest` + tool registry）
- [ ] DYNAMIC_VERIFICATION 使用 fuzz 策略生成的 candidateInputs 触发 SQL 结构差分（**live 可选，未宣称完成**）
- [ ] BRANCH_CONSTRAINT_FACTS 中的 magic literal 命中对应分支（branchHitMap 更新；**live 可选，未宣称完成**）
- [ ] SqlDiffProbe 对 union/error 探针产出不同的 SqlEvent（**live 可选，未宣称完成**）

**版本注记**：本 MVP 使用 **V018**（`fuzz_strategy_json`）。

---

### MVP-5：Root Cause + 报告完整化（V1.0）
**目标**：REPORT_GENERATION 输出攻击路径 + Root Cause + 修复建议  
**预期工时**：2 周

#### 改动清单

**A. Root Cause 结构化**

改动：`ai/AiContracts.java`
```java
// VULNERABILITY_TRIAGE 输出新增结构
record RootCauseAnalysis(
    List<AttackStep> attackPath,
    String rootCauseStatement,
    String affectedComponent,      // classname#methodDesc
    String cweId,                   // "CWE-89" | null
    String fixSuggestion
) {}

record AttackStep(
    String layer,                   // "HTTP" | "param" | "transform" | "sink"
    String label,                   // 人类可读标签
    List<String> evidenceRefs       // 必须引用 evidence/pathrun
) {}
```

改动：VULNERABILITY_TRIAGE prompt 模板
```
新增输出要求：rootCause 字段（JSON schema 严格校验）
要求：attackPath 每个 step 必须有 evidenceRefs（服务端校验）
提供：ROOT_CAUSE_TEMPLATE 段（示例格式）
```

**B. CWE 映射（静态规则）**

新增文件：`analysis/CweMapper.java`
```java
// sink.category → CWE 映射
public static String cweMappingFor(String category) {
    return switch (category) {
        case "SQL" -> "CWE-89";
        case "JNDI" -> "CWE-90";
        case "COMMAND" -> "CWE-78";
        case "PATH_TRAVERSAL" -> "CWE-22";
        case "DESERIALIZATION" -> "CWE-502";
        case "SSRF" -> "CWE-918";
        default -> null;
    };
}
```

VULNERABILITY_TRIAGE prompt 注入段新增：CWE_MAPPING_HINTS（预填充建议 CWE）

**C. 报告 Mermaid 攻击路径**

改动：REPORT_GENERATION prompt 模板
```
新增段：## 攻击路径（Attack Path）
要求：从 RootCauseAnalysis.attackPath 生成 Mermaid flowchart
格式：
  ```mermaid
  flowchart LR
      A[HTTP POST /api/user] --> B[username 参数]
      B --> C[PreparedStatement 拼接]
      C --> D[SQL 注入]
  ```
```

**D. 多轮 diff 报告段**

改动：REPORT_GENERATION prompt 模板
```
新增段：## 迭代对比（Iteration Summary）
  注入：LedgerDiff（MVP-3 已有）
  要求：表格化展示新命中/回退/覆盖率变化
```

**数据库迁移**：`V019__root_cause.sql`
```sql
-- findings 表新增 root_cause_json 列
ALTER TABLE findings ADD COLUMN root_cause_json TEXT;
```

#### MVP-5 验收标准
- [x] Report 模板要求 Mermaid 攻击路径（至少 3 步）；`RootCauseAnalysis.toMermaid` 合成验收
- [x] AttackStep.evidenceRefs 服务端构造校验（空 refs 拒绝）
- [x] 修复建议有对应 CWE 标注（CweMapper 覆盖至少 5 种 category）
- [x] 报告注入 LEDGER_DIFF_SUMMARY / 迭代对比段（prompt）；端到端六角色 live 仍可选

**版本注记**：本 MVP 使用 **V019**（`root_cause_json`）。

---

### MVP-6：VERIFIED 门禁 + 强化隔离（V1.x）
**目标**：gVisor/Kata 通过逃逸测试后开启 VERIFIED  
**优先级**：P2（JAR 主脊验证稳定后）  
**预期工时**：3–4 周

#### 改动清单

**A. 强化隔离运行时**

前置条件：`sandbox-pack` 引入 gVisor/Kata runtime

改动：`WorkerCapability` 枚举
```java
// 新增：HARDENED_GVISOR | HARDENED_KATA
// TRUSTED_DOCKER 保持（仅开发用）
```

改动：`verification/VerifiedStatusGate.java`
```java
// 移除 TRUSTED_DOCKER 的 VERIFIED 强制关闭
// 新增 gVisor/Kata attestation 检查：
public static Decision forHardenedRuntime(WorkerCapability capability) {
    if (capability == HARDENED_GVISOR || capability == HARDENED_KATA) {
        // 检查：最近 30 天内逃逸测试通过（从 attestation 文件读取）
        if (attestationValid()) {
            return Decision.allow();
        }
    }
    return Decision.deny("HARDENED_RUNTIME_NOT_VERIFIED");
}
```

**B. 重放稳定性门禁**

改动：`verification/ReplayEvidenceGate.java`
```java
// 同一 ExperimentPlan 重放两次，要求：
//   - 同样的 entryHit / parameterBound
//   - 同样的 sqlEvents（SQL 文本一致）
//   - httpStatus 一致（允许误差：2xx 内变化可接受）
// 通过后允许 DYNAMIC_CONFIRMED → VERIFIED
```

**C. VERIFIED 专用持久化**

新增表：`verified_findings`（与 `findings` 分离）
```sql
CREATE TABLE verified_findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    root_cause_json TEXT NOT NULL,
    replay_evidence_refs TEXT NOT NULL,  -- 两次重放的 PathRun IDs
    verified_at TEXT NOT NULL,
    attestation_ref TEXT NOT NULL        -- gVisor/Kata 逃逸测试报告引用
);
```

#### MVP-6 验收标准
- [ ] gVisor runtime 通过逃逸测试套件（网络/DNS/metadata/宿主挂载/Docker socket/只读根/非 root）— **未做**
- [ ] VERIFIED 门禁对 HARDENED_GVISOR 开启（VerifiedStatusGate.allowed() = true）— **刻意保持关闭**（`VERIFIED_GATE_NOT_OPEN`）
- [x] ReplayEvidenceGate + EscapeSuiteAttestation 脚手架接入 VerifiedStatusGate（仍 fail-closed）
- [x] Dashboard 暴露 `verifiedFindings` 数组（当前恒为空，直至门禁真实开启）

**版本注记**：本 MVP 使用 **V020**（`verified_findings`）。诚实限制：无逃逸套件 attestation 前不得宣称 VERIFIED 生产可用。

---

## 四、多语言支持策略

### 4.1 当前 JVM 专用边界

`ClassFileMetadataParser`（853 行）是手写 classfile 字节码解析器，完全 JVM 专用。  
`InterproceduralTaintAnalyzer` 依赖 JVM invokevirtual/invokespecial/invokestatic 指令。  
`ArtifactType` 枚举只有 JAR / WAR / CLASS。

在 JAR 主脊未商业验证前，**不做多语言**。以下是验证后的迁移路径。

### 4.2 多语言架构设计（远期 V2+）

核心思路：**控制面不变，分析引擎可替换**

```
Control Plane（Java）        ← 不变：项目管理/AI流水线/沙箱闸门/证据分层
    │
    ├── JVM Packager          ← 当前已有：JAR/WAR/CLASS
    │     └── ClassFileMetadataParser（JVM 专用）
    │
    ├── Python Packager       ← V2 新增
    │     └── PythonAstAnalyzer（AST + call graph，基于 ast/libcst）
    │
    ├── Node.js Packager      ← V2 新增
    │     └── NodeAstAnalyzer（基于 @babel/parser AST）
    │
    └── [Future] PHP/Go/Rust Packager
```

**统一中立事实模型（Language-Neutral Facts）**

所有语言的分析结果统一输出为中立事实，Control Plane 只消费此模型：

```java
// 已有接口方向，逐步对齐
record NeutralEntrypoint(
    String id, String protocol, String method, String route,
    String declaringClass,      // 对 Python 是 module.class, 对 Node 是 file:function
    List<ParameterSpec> parameters,
    VerificationStatus status,
    double confidence
) {}

record NeutralSink(
    String id, String category,
    String symbol,              // 对 Python: module.function, 对 Node: require('child_process').exec
    SinkSource source,
    double confidence
) {}

record NeutralTaintPath(
    String id,
    List<NeutralTaintStep> steps,   // source → transform → sink
    String status
) {}
```

### 4.3 Python 支持（V2 第一候选）

**选型理由**：Python FastAPI/Django 在 SRC/闭源审计场景常见；AST 模块成熟。

**新增 Packager 骨架**：

```
artifact/packager/PythonPackager.java
    职责：识别 .py / .pyc / wheel / sdist，提取入口
    
analysis/python/PythonAstAnalyzer.java
    实现：调用 subprocess → python3 -m veyrion_static_helper（独立 Python 进程）
    Python helper 输出 JSON（NeutralEntrypoint + NeutralSink + NeutralTaintPath 格式）
    Java 侧 JSON 反序列化 → 接入现有 PreAnalysisService 下游
```

Python static helper（独立 Python 包，不入 Java 主仓）：
```python
# veyrion_static_helper/
#   __main__.py  ← CLI 入口
#   entry_recovery.py   ← FastAPI/Django/Flask 路由解析
#   taint_analyzer.py   ← AST 级污点传播（source → sink）
#   sink_registry.py    ← 常见危险函数（eval/exec/subprocess/os.system/...）
#   output_schema.py    ← 输出 NeutralTaintPath JSON
```

**动态分析适配**：
- Python 进程用 `sys.settrace` 或 `coverage.py` 采集 branch coverage
- trace 格式统一为 JSONL（与 JVM agent 一致）
- HTTP 探针逻辑完全复用（与语言无关）

### 4.4 Node.js 支持（V2 第二候选）

```
analysis/node/NodeAstAnalyzer.java
    调用：node veyrion_static_helper.js（独立 Node 进程）
    Node helper：@babel/parser AST → 入口/sink/taint path → JSON
    
分析重点：
    express.Router().get/post → 入口
    child_process.exec/spawn → RCE sink
    eval() / Function() → 代码注入
    require('fs').readFile → 路径穿越
    mongoose/sequelize query → NoSQL/SQL 注入
    
动态覆盖率：V8 coverage API（node --coverage）
```

### 4.5 多语言迁移顺序与决策门禁

```
阶段 0（当前）：JVM JAR 主脊
    门禁：SpringBlade 单入口 live 过闸 + SQL/HTTP 对照可重复演示

阶段 1（V2 准备）：LanguagePackager SPI 抽象
    门禁：JVM Packager 通过 PackagerAcceptanceTest（行为不变）

阶段 2：Python Packager + helper
    门禁：Python FastAPI 真实制品通过 PRE_ANALYSIS + AUTH_ANALYSIS

阶段 3：Node.js Packager + helper
    门禁：Express 真实制品入口召回率 > 80%

注意：每个语言的动态执行仍走同一 TRUSTED_DOCKER 沙箱
      区别只在语言运行时镜像（python3 / node 替代 java -jar）
      `sandbox-pack` 需要对应运行时的 Dockerfile
```

---

## 五、ControlPlaneServer 拆分（工程债）

### 5.1 问题

`ControlPlaneServer.java` 当前 4388 行，承担：HTTP 路由 + 业务逻辑 + 探针计划 + Auth 材料生成 + Dashboard 聚合 + DTO 序列化。与功能开发并行时变更冲突严重。

### 5.2 目标结构

```
control/
  ControlPlaneServer.java          ← 保留：HTTP 服务生命周期 + CORS + 鉴权 + 路由分发
  routing/RouteTable.java          ← 声明式路由注册（取代 if-else 链）
  handler/
    ProjectHandler.java            ← /projects/* CRUD（约 200 行）
    ArtifactHandler.java           ← 上传 + 路径登记（约 150 行）
    ScanHandler.java               ← 扫描生命周期（约 200 行）
    DynamicTaskHandler.java        ← dynamic-tasks + focus-probe + experiment-card（约 300 行）
    AiJobHandler.java              ← /ai-jobs + audit-runs（约 200 行）
    SecurityConfigHandler.java     ← /operators + /providers + /role-assignments（约 200 行）
    DashboardHandler.java          ← /dashboard + /scans/*/paths + SSE（约 200 行）
  service/
    ProbePlanService.java          ← 探针计划构建（从 Server 分离，独立可测）
    DashboardService.java          ← Dashboard 聚合逻辑（从 dashboard() 分离）
  dto/DtoMapper.java               ← 所有 xxxMap() 静态方法集中
```

### 5.3 迁移顺序（与 MVP 并行，按优先级）

| 步骤 | 时机 | 内容 | 验收 |
|------|------|------|------|
| Step 1 | MVP-1 前 | 提取 `ProbePlanService`（影响面最小）✅ + V015 schemaVersion | 现有 AcceptanceTest 全绿 |
| Step 2 | MVP-2 中 | 提取 `FrameworkAdapterRegistry`（MVP-2 A 已要求）✅ | FrameworkAdapterAcceptanceTest |
| Step 3 | MVP-3 后 | `RouteTable` + `ControlPlaneRouteActions` ✅（Server 仍大；细粒度 Handler 拆分后续） | ControlPlaneAcceptanceTest |
| Step 4 | MVP-4 后 | `DashboardService` ✅ | dashboard ledgerDiff / rankedSinks |

**ProbePlanService 优先原因**：  
`buildProbePlan()` 5 个重载 + `buildFocusedAiPocPlan()` + `expandProbesByIdentityTracksDetailed()` 约 400 行，且 MVP-4 fuzz 策略注入需要在此处扩展——先分离再扩展，避免在 4388 行文件中继续堆代码。

```java
// 提取后的 ProbePlanService 接口（核心）
public sealed interface PlanRequest permits FloodRequest, FocusedPocRequest {}

public record FloodRequest(
    String preferredEntryId,
    String taskIdHint,
    List<String> candidateInputs,
    int maxRequests
) implements PlanRequest {}

public record FocusedPocRequest(
    String entryId,
    String techniqueId,
    String authorizationHeader,
    String bladeAuthHeader,
    List<String> candidateInputs,
    int maxRequests,
    FuzzStrategy fuzzStrategy      // MVP-4 新增，可为 null
) implements PlanRequest {}

// 服务方法
public ProbePlan build(ScanRecord scan, PlanRequest request, Path artifactPath) { ... }
```

---

## 六、payload_json schemaVersion 补强 ✅（V015）

现状（已修复）：`experiment_plans` / `path_runs` JSON 写入带 `schemaVersion`；读取有版本护栏。`worker_tasks` 列 `schema_version` 读取要求 `>= 1`。

**V015 迁移（SQL）**：

```sql
-- V015__add_schema_version.sql
UPDATE experiment_plans
SET payload_json = json_set(payload_json, '$.schemaVersion', 1)
WHERE json_extract(payload_json, '$.schemaVersion') IS NULL;

UPDATE worker_tasks
SET spec_json = json_set(spec_json, '$.schemaVersion', 1)
WHERE json_extract(spec_json, '$.schemaVersion') IS NULL;
```

**读取端护栏（Java）**：
```java
ExperimentPlan plan = JSON.readValue(stored.payloadJson(), ExperimentPlan.class);
if (plan.schemaVersion() == null || plan.schemaVersion() < 1) {
    throw new PersistenceException(
        "experiment_plan " + stored.planId() + " 缺少 schemaVersion，请运行 V015 迁移");
}
```

---

## 七、完整开发周期时间线

| 周期 | 版本 | 核心交付 | 工时估算 | 关键验收标准 |
|------|------|---------|----------|------------|
| **MVP-1** | V0.2 / V016 | Branch Coverage + CandidateRanker + ContrastLedger snapshotId ✅ | 2–3 周 | TaintPath 状态升级；rankedSinks 可见 |
| **MVP-2** | V0.3 | BranchConstraintHarvester + CoverageGap + FrameworkAdapter SPI ✅ | 2–3 周 | 第二轮命中率提升；FrameworkAdapterTest |
| **Step 1** | V0.3 | ProbePlanService 分离（工程债）✅ + V015 schemaVersion | 0.5 周 | AcceptanceTest 全绿 |
| **MVP-3** | V0.4 / V017 | TaintGraph + LedgerDiff + DynamicFeedbackApplier ✅ | 2 周 | TaintGraph 可查；两轮 diff 可见 |
| **Step 2** | V0.4 | FrameworkAdapterRegistry 独立（MVP-2 已做）✅ | 0.5 周 | 无硬编码 Blade 词表 |
| **MVP-4** | V0.5 / V018 | FuzzStrategyRegistry + fuzz_strategy_get ✅（live SqlDiff 可选） | 2 周 | SQL 差分多探针触发 |
| **Step 3** | V0.5 | RouteTable + ControlPlaneRouteActions 拆分 ✅（Server 仍大） | 1 周 | 路由声明式分发 |
| **MVP-5** | V1.0 / V019 | RootCause + Mermaid + CWE + LedgerDiff 报告段 ✅ | 2 周 | 报告端到端完整 |
| **Step 4** | V1.0 | DashboardService 分离 ✅ | 0.5 周 | rankedSinks / ledgerDiff 聚合 |
| **MVP-6** | V1.x / V020 | VERIFIED 门禁脚手架 ✅（逃逸套件未过；门禁仍关闭） | 3–4 周 | 逃逸测试通过（待） |
| **V2.0** | V2 | LanguagePackager SPI + Python Packager | 4–6 周（验证后决策） | Python FastAPI 入口召回 > 80% |

---

## 八、与现有文档的对应关系

| 本文条目 | 对应现有文档 |
|---------|------------|
| MVP-1 Coverage | TECHNICAL_ARCHITECTURE.md §3.6（branchHitMap / rankedSinks 已注记） |
| MVP-2 FrameworkAdapter | EXTENSIBLE_ANALYSIS.md — FrameworkAdapter 轴（SPI 已落地） |
| MVP-3 TaintGraph | TECHNICAL_ARCHITECTURE.md §15（TaintGraph / LedgerDiff 已注记） |
| MVP-4 Fuzz 策略 | PATH_EXPERIMENT_MODEL.md §6 实验计划（ProbeTemplate 扩展） |
| MVP-5 Root Cause | AUDIT_FLOW.md §8 报告生成（新增 attackSteps 约束） |
| MVP-6 VERIFIED | TECHNICAL_ARCHITECTURE.md §13（门禁脚手架已注记；仍 fail-closed） |
| 多语言策略 | EXTENSIBLE_ANALYSIS.md — Packager 轴（Python/Node 实现路径） |
| Server 拆分 | ARCHITECTURE_REVIEW_REPORT.md §4 推荐重构 #2/#3 |

> 本文档是当前代码实测后的**具体落地**，优先级高于 ARCHITECTURE_REVIEW_REPORT.md 中的通用建议。  
> 每个 MVP 开始前应更新 `PROJECT_MEMORY.md` 对应决策条目。

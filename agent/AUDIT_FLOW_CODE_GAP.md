# AUDIT_FLOW 产品模型 vs 当前代码执行差距

> **基准**：`docs/AUDIT_FLOW.md`（产品模型文档，commit `f21ba11` 起恢复为对齐前原文；**不得**再改写该文档以迁就代码）。
> **对照**：当前控制面 / Worker / Sensor Agent 实现（以 `AuditPipelineCoordinator`、`AiJobOrchestrator`、`ProbePlanService`、Agent 模块为准）。
> **状态源**：实现进度与验收证据只在 [MVP_BACKLOG.md](../docs/MVP_BACKLOG.md)；本文只做差距对照，不改模型文档。

---

## 1. 模型侧阶段与 Mermaid 主张（摘要）

模型 mermaid 主张的主链：

```text
Artifact Universe → Security IR / Evidence Graph
  → 并行 Detectors → SecurityHypothesis Pool
  → TracePlan Compiler → World Pack Plan
  → ① PRE_ANALYSIS → ② AUTH_ANALYSIS
  → {沙箱?} → ExperimentPlan → Docker Sandbox + Sensor Agent
  → 三轨(+BYPASS) → PathTrace 投影
  → IR2: Evidence Graph delta + 受影响 Detector 重算
  → ContrastLedger → ②′ AUTH_ANALYSIS 续跑
  → ③ DYNAMIC_VERIFICATION → ④ PATH_EXPLORATION
  → {有可验证 hypothesis?} → Experiment Planner + sandbox_probe → 回 OBS
  → ⑤ VULNERABILITY_TRIAGE
  → {需复现?} → family experiment + sandbox_probe → 回 OBS
  → Family 门禁（仅 SQL H3 → DYNAMIC_CONFIRMED）→ ⑥ REPORT → VERIFIED fail-closed
```

六个固定 AI 角色：`PRE_ANALYSIS` · `AUTH_ANALYSIS`（含动态后续跑）· `DYNAMIC_VERIFICATION` · `PATH_EXPLORATION` · `VULNERABILITY_TRIAGE` · `REPORT_GENERATION`。

确定性引擎（不占 AI 席位）：Artifact Universe、Security IR、detectors、Hypothesis Pool、Experiment Planner、PathRun 投影、ContrastLedger。

Agent / FORCED 切片在模型中对应：「Docker Sandbox + Framework Boundary + Sensor Agent」+ 三轨中的 `FORCED_REACHABILITY`（Docker-only、已识别 guard、`INSTRUMENTATION_REACHABILITY`）。

---

## 2. 代码侧实际阶段机

编排权威：`AuditPipelineCoordinator.PipelineStage`（八阶段 + `COMPLETE`）：

```text
POST …/audit-runs
  → createOrReplayScan          [确定性静态：PreAnalysisService / detectors]
  → PRE_ANALYSIS                [AI]
  → AUTH_ANALYSIS               [AI]
  → DYNAMIC_OBSERVATION         [Worker / TRUSTED_DOCKER，非 AI]
  → AUTH_BYPASS_CONFIRM         [AI，角色仍为 AUTH_ANALYSIS]
  → DYNAMIC_VERIFICATION        [AI]
  → PATH_EXPLORATION            [AI]
  → VULNERABILITY_TRIAGE        [AI]
  → REPORT_GENERATION           [AI]
  → COMPLETE
```

推进为**线性 CAS cursor**（`advanceAfterJob` / `advanceAfterDynamic`）：PATH 完成后固定进 TRIAGE，TRIAGE 完成后固定进 REPORT；**没有** mermaid 中的 `HG` / `TP` 分支回 `OBS` 阶段。

六个 `AgentRole` 与模型一致；`AUTH_BYPASS_CONFIRM` 是显式 pipeline 阶段名，角色仍映射 `AUTH_ANALYSIS`。

---

## 3. 吻合（模型 ↔ 代码）

| 模型主张 | 代码证据 |
|----------|----------|
| 六 AI 角色固定，不能由模型改阶段/沙箱/验证等级 | `AgentRole`；`AuditPipelineCoordinator` 注释与 CAS cursor |
| 静态先于 AI：Artifact / IR / detectors → hypothesis | `ControlPlaneServer.createOrReplayScan` + `PreAnalysisService`；`DetectorRegistry.analyzeAll`；`SecurityHypothesisProjector` |
| 沙箱不可用则动态禁用、保留静态 | Worker / capability 路径；无宿主回退（ADR-0004） |
| 动态三轨 + BYPASS 按候选 | `ProbePlanService` / posture compilers；`PATH_EXPERIMENT_MODEL` 实现侧 |
| FORCED Docker-only、标 `INSTRUMENTATION_REACHABILITY` | Agent `FrameworkBoundaryAdapter.ForceRewriteMode`；投影侧 provenance |
| 动态后 AUTH 二次确认；零动态鉴权证据不得确认绕过 | `AuthBypassFeasibility.evaluateBypassConfirmation` → 无证据时 `INSUFFICIENT_EVIDENCE` / 仅 `HYPOTHESIS` |
| DYNAMIC 用 `sandbox_probe`，模型不能改命令/网络/UID/挂载/预算 | `AiJobOrchestrator` 工具闸门 + 服务端 enqueue |
| TRIAGE：FORCED 不作匿名 exploit；仅 SQL H3 可 `DYNAMIC_CONFIRMED` | 提示词约束 + `DynamicConfirmedGate`（DATAFLOW/H3） |
| REPORT 后 VERIFIED fail-closed；`TRUSTED_DOCKER` 永不 VERIFIED | `VerifiedStatusGate` |
| PathTrace → Evidence Graph **delta 合并** | `PathTraceEvidenceGraphDelta` + `ControlPlaneStore.applyPathTraceEvidenceGraphDelta` |
| ContrastLedger 对照假设 | `ContrastLedger`；REPORT 强制 `enforceReport` |
| 超时分类标签供 GUI/AI 引用，不得单独升确认/VERIFIED | PathRun 超时分类（与模型「超时分类展示」一致） |

---

## 4. 漂移（模型说 X，代码做 Y）

### 4.1 阶段命名与粒度

| 模型 | 代码 |
|------|------|
| 「沙箱动态观察」无独立阶段枚举名；画在 ExperimentPlan→Sandbox→OBS | 显式 `PipelineStage.DYNAMIC_OBSERVATION`（非 AI） |
| 「鉴权绕过确认」= `AUTH_ANALYSIS` **续跑/二次任务** | 显式 `PipelineStage.AUTH_BYPASS_CONFIRM`，角色仍 `AUTH_ANALYSIS` |
| mermaid：TracePlan / World Pack **在** PRE_ANALYSIS **之前** | 静态扫描与 detectors 在 AI 前；**入口×参数×posture 的 ExperimentPlan / ProbePlan 主要在动态入队时**由 `ProbePlanService` 编译，不是 PRE 前完整闭环 |
| World Pack：profile / env / license / schema / seed / stubs | `WorldPackPlanner` 以 `MOCK_CONTINUE` / `OBSERVE_FAIL` 与 dependency stubs 为主；业务种子 / license / schema 仍弱 |

### 4.2 Mermaid IR2「delta + Detector 重算」

| 模型 | 代码 |
|------|------|
| `OBS → IR2[Evidence Graph delta + 受影响 Detector 重算] → ContrastLedger` | **有** PathTrace → Evidence Graph **节点合并**（`PathTraceEvidenceGraphDelta`） |
| 受影响 Detector **全量/增量重算**后进入对照 | **无** PathRun 后的 `DetectorRegistry.analyzeAll` 闭环；仅有 `ObservationKindRef` 类「最小重算提示」记录 |
| 反馈主路径是 IR 重算 | 实际主反馈是 **ContrastLedger / FindingRuntimeEnricher / DynamicFeedbackApplier**（有界证据回写，不重跑 detector 套件） |

### 4.3 PATH / TRIAGE「回 OBS」闭环

| 模型 mermaid | 代码 |
|--------------|------|
| PATH：`HG -- 是 --> sandbox_probe → 新 PathRun → OBS`（再 IR2…） | `sandbox_probe` 在 **当前 AI job 内**入队有界探针；`DYNAMIC_VERIFICATION` 后 `waitForDynamicIdleThenPath`；**不**把 cursor 拨回 `DYNAMIC_OBSERVATION` |
| PATH 无 hypothesis 则跳过进 TRIAGE | Coordinator **顺序推进** PATH→TRIAGE；「跳过」最多是研判策略，不是阶段分支 |
| TRIAGE：`TP -- 是 --> family experiment → OBS` | TRIAGE 可调 `sandbox_probe`，完成后 `releaseRetainedSandbox` 并进 REPORT；**无**阶段级回环 |

### 4.4 AUTH 绕过确认触发条件

| 模型契约 §4 | 代码 |
|-------------|------|
| **仅在**消费到 `AUTH_CHALLENGE` / 过闸等 PathRun 后才进入确认续跑 | Coordinator 在 `DYNAMIC_OBSERVATION` 结束后**总是** `beginRoleStage(AUTH_BYPASS_CONFIRM)` |
| 零动态证据不得确认绕过 | 硬门禁在 `evaluateBypassConfirmation`（结论降级），但 **确认阶段仍会跑一轮 AI** |

### 4.5 PATH 契约中的「detector 重算后才下一轮」

| 模型 §6 | 代码 |
|---------|------|
| 新观察成功投影并触发受影响 detector 重算后才进入下一轮 | 投影 + Contrast / enrichment；**无** detector 重算门闩；多轮主要靠 AI tool 循环与服务端 re-ask，不是 IR 闭环 |
| `ObservationKindRef` / incremental subjects | 存在「最小重算提示」记录，**主路径未驱动** `DetectorRegistry.analyzeAll` |

### 4.6 Stage 0「detector ≠ Finding」字面

| 模型 §0 | 代码 |
|---------|------|
| 检测器输出是 `SecurityHypothesis` 与 coverage gap，**不是 Finding** | 同时经 `SecurityHypothesisProjector.mergeFindingsWithDetectorHypotheses` 产出 `FindingDto`（常为 `STATIC_INFERRED`） |
| 并行 Dataflow / Guard / State / Typestate / … | `DetectorRegistry.defaults()` **无独立 Dataflow detector**；taint/dataflow 主要靠 projector + bytecode sink 路径 |

### 4.7 沙箱不可用与延迟组链

| 模型 | 代码 |
|------|------|
| 沙箱否 → `DYNAMIC_DISABLED`，保留静态结果并继续可用叙事 | Worker 不可用常走 reclaim / `WORKER_UNAVAILABLE`；动态 task **非 COMPLETED 时 pipeline 可能 disarm**，不保证后续 AI 阶段按「仅静态」完整续跑 |
| TRIAGE「延迟组链」为服务端确定性门禁（PATH_EXPERIMENT_MODEL §3.2） | 多为 **prompt + `FindingBindings` / `nextExperiments` 闸门**；未见独立「绕过确认 + COVERAGE sink → 利用链」装配状态机 |

---

## 5. 模型有、代码弱/缺（MISSING_IN_CODE）

1. **IR2 闭环**：Evidence Graph delta 后「受影响 Detector 重算」——delta 合并存在，**重算引擎缺失**（PARTIAL）。
2. **阶段级 PATH/TRIAGE ↔ OBS 实验闭环**：mermaid 双回环；代码为线性八阶段 + job 内探针。
3. **TracePlan / World Pack 作为 PRE 前完整确定性编译产物**：部件存在（`TracePlanCompiler`、`WorldPackPlanner`、`ProbePlanService`），编排顺序与完整度未达 mermaid。
4. **完整 World Pack**（license / schema / seed / 真实业务状态）：仍 MOCK/stub 语义为主。
5. **Hypothesis Pool 作为一等运行时对象被 Experiment Planner 持续驱动**：有 hypothesis 投影与 nextExperiments 过滤，但不是 mermaid 级「池 → 计划 → 观测 → 重算」状态机。
6. **Typestate / 完整 dataflow detector 套件**：`DetectorRegistry.defaults()` 覆盖 guard/ownership/config/JWT/依赖/资源/状态/并发等；模型列举的完整 dataflow/typestate/API misuse 深度仍依赖轻量 `analysis.kernel` + sink 投影，非完整 IFDS/SSA。
7. **`DYNAMIC_DISABLED` 后静态-only 完整续跑保证**：与 disarm / 非 COMPLETED 动态终态行为不完全同构。

---

## 6. 代码有、模型未写或未点名（EXTRA_IN_CODE / 模型侧缺口）

> 下列是实现侧能力；**不**要求改写 `AUDIT_FLOW.md`，仅记录「模型未描述 / 代码已落地」。

| 代码能力 | 说明 |
|----------|------|
| `PipelineStage` 八阶段枚举 + `AUTH_BYPASS_CONFIRM` / `DYNAMIC_OBSERVATION` 显式名 | 模型用角色续跑 +「沙箱动态观察」叙述 |
| `GuardSurfaceCatalog` → `forcedGuardTypeNames` allowlist；`GUARD_CATALOG_TRUNCATED` | 模型只写「已识别 guard」 |
| `ForceRewriteMode`（`FILTER_CONTINUE_CHAIN` / `ACCESS_ALLOWED_TRUE` / `INTERCEPTOR_PREHANDLE_TRUE` / `METHOD_SECURITY_FAIL_OPEN`） | 模型未点名枚举；Agent README 有 |
| `ProbeParameterHeuristics.preferHonestQuery` 等参数启发式 | 模型写「0-n 参数 / 禁止盲发」，未点名启发式类 |
| `FindingBindings`（`PRIMARY` / `RISK_POINT`）+ REPORT 分区强制 | 模型 REPORT 节要求分开展示静态/动态/反证/未覆盖，但未点名 bindings 合同 |
| `FindingRuntimeEnricher` 读时 enrichment | 模型未点名；是 IR2 重算的弱替代之一 |
| `ContrastLedger.enforceReport` / `EVENT_INCOMPLETE` / `MAX_FORCED_STATIC_ONLY` | 模型有 ContrastLedger，未写 REPORT 强制 enforce |
| `DYNAMIC_POC_ATTEMPT_REQUIRED` / 自动入队焦点探针 | DYNAMIC 零 `sandbox_probe` 时的服务端补写（`AiJobOrchestrator`） |
| 高信号 detector hyp → Finding（`STATIC_INFERRED`） | 与模型「detector≠Finding」字面冲突；见 §4.6 |
| `VerifiedStatusGate` scaffolding（如 `VERIFIED_GATE_NOT_OPEN`） | 模型只写 fail-closed / TRUSTED_DOCKER 永不 VERIFIED |
| 手工 `POST …/scans` 仅静态；`POST …/dynamic-tasks` 可单独入队 | 模型聚焦完整审计流水线 |
| Agent 模块独立文档与 ADR-0004 红线细节 | 模型仅一行指向 Sandbox+Sensor |

---

## 7. AI 角色对照

| # | 模型角色 | 代码 `AgentRole` / 阶段 | 差距 |
|---|----------|-------------------------|------|
| ① | PRE_ANALYSIS | `PRE_ANALYSIS` | 吻合；补充入口须 `MODEL_SUPPLEMENT` 由提示词/服务端约束 |
| ② | AUTH_ANALYSIS | `AUTH_ANALYSIS` + 阶段 `AUTH_BYPASS_CONFIRM` | 角色吻合；阶段是否「有证据才启动」见 §4.4 |
| ③ | DYNAMIC_VERIFICATION | 同名阶段 | 吻合；PoC 零探测时服务端可 re-ask / 自动入队 |
| ④ | PATH_EXPLORATION | 同名；可 `sandbox_probe` | 无阶段回 OBS / 无 detector 重算门闩 |
| ⑤ | VULNERABILITY_TRIAGE | 同名；延迟组链在提示词 + FindingBindings | 无 family 实验阶段回环；缺确定性组链状态机（§4.7） |
| ⑥ | REPORT_GENERATION | 同名 + ContrastLedger / FindingBindings enforce | bindings 为代码增补 |

---

## 8. FORCED / Agent 切片对照

| 模型 | Agent / 控制面 |
|------|----------------|
| Docker Sandbox + Framework Boundary + Sensor | `TRUSTED_DOCKER` + `-javaagent` + `FrameworkBoundaryAdapter` |
| FORCED 仅限已识别鉴权/权限/License/feature guard | `forcedGuardTypeNames`（`GuardSurfaceCatalog`）优先；空则启发式 |
| 标 `INSTRUMENTATION_REACHABILITY` | 控制面投影；Agent 事件侧 `AGENT_INSTRUMENTED` / 不升 VERIFIED |
| 禁止短接 sanitizer / 不作 Bypass Zoo | ADR-0004 + `ForceRewriteMode` 白名单形态 |
| 位于 AUTH 与绕过确认之间 | 代码：`DYNAMIC_OBSERVATION` 夹在首次 `AUTH_ANALYSIS` 与 `AUTH_BYPASS_CONFIRM` 之间 |

细节见 [agent/README.md](README.md)；**产品阶段语义以 AUDIT_FLOW 模型为准，执行顺序以代码阶段机为准，差距以本文为准。**

---

## 9. 顶层差距清单（优先阅读）

1. **IR2 Detector 重算未闭环**：有 Evidence Graph delta 合并，无受影响 detector 重算；Contrast/Enrichment 是弱替代。
2. **无 PATH/TRIAGE → OBS 阶段回环**：mermaid 双闭环 vs 线性八阶段 + job 内 `sandbox_probe`。
3. **TracePlan / World Pack 编排位置与完整度偏移**：模型放在 PRE 前；代码侧重动态入队时 ProbePlan，World Pack 仍 MOCK 向。
4. **AUTH 确认阶段总是调度**：模型「有证据才续跑」vs 代码「总是 `AUTH_BYPASS_CONFIRM`，门禁只降结论」。
5. **Stage 0 输出形态**：模型「detector≠Finding」vs 代码同时投影 `FindingDto`；无独立 Dataflow detector。
6. **模型未收录的代码合同**：`GuardSurfaceCatalog` / `ForceRewriteMode` / `FindingBindings` / `FindingRuntimeEnricher` / `DYNAMIC_POC_ATTEMPT_REQUIRED` —— 实现已有，产品模型文档保持原样，差距记在此。

---

## 10. 维护约定

- **不要**为「对齐代码」修改 `docs/AUDIT_FLOW.md`。
- 代码演进后更新**本文**与 `MVP_BACKLOG` 证据；若产品决策要改模型，由根 Agent / 产品所有者显式修订 AUDIT_FLOW，而非静默对齐。
- Agent README 只描述 Sensor / FORCED 切片，并链接本文作为与产品模型的差距入口。

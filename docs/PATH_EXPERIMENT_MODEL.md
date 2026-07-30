# 路径实验模型（合同摘要）

> 动态姿态、验证状态与门禁的**规范摘要**。执行顺序与阶段机见 [AUDIT_PIPELINE_ASBUILT.md](AUDIT_PIPELINE_ASBUILT.md)；Sensor 见 [AGENT_SENSOR_FLOW.md](AGENT_SENSOR_FLOW.md)。  
> ADR：[0004](adr/0004-sandbox-posture-vs-agent-bypass.md)。

## 1. 验证状态

| 状态 | 含义 |
|------|------|
| `STATIC_INFERRED` | 仅静态图/注解/配置信号 |
| `DYNAMIC_SUSPECTED` | 运行时观测到达关键点，闭环未充分 |
| `DYNAMIC_CONFIRMED` | 服务端 H3 门禁（当前仅 SQL DATAFLOW）；≠ 生产实库 |
| `VERIFIED` | 强化沙箱 + 更严重放；**本阶段关闭** |
| `UNREACHED` | 身份/预算/启动/World Pack/依赖等原因未完成 |

模型输出不能单独升级任一状态。`httpStatus=-1`、`UNKNOWN`、空 PathRun、仅 MOCK 前置条件不得单独产生 `DYNAMIC_SUSPECTED`。

## 2. 四用途姿态

| 用途 | postureKind | 默认 | 结论边界 |
|------|-------------|------|----------|
| 撞墙 | `UNAUTH` | 是 | 401/403 不是漏洞；记 `authRequirement` |
| 标准流通 | `COVERAGE_POSTURE` | 是 | 扫描身份可达 ≠ 匿名利用 |
| 强达 | `FORCED_REACHABILITY` | Docker-only | 必须 `INSTRUMENTATION_REACHABILITY`；不单独升 CONFIRMED/VERIFIED |
| 绕过 | `BYPASS` | 有候选时 | 可与流通/强达 sink **证据组链** |

已识别 guard：`GuardSurfaceCatalog` → `forcedGuardRefs` / agent allowlist。禁止默认强达 sanitizer、SQL 参数化、文件类型、业务状态机不变量。

## 3. 延迟组链（产品合同）

| 证据组合 | 允许结论 |
|----------|----------|
| 绕过确认 + COVERAGE/强达轨敏感 effect | 利用链假设（双侧 evidence refs） |
| 仅 COVERAGE effect | 鉴权门控风险；永不报匿名 RCE |
| 仅 FORCED effect | 强达路径风险材料 |
| 仅静态 | 不得单独发明漏洞 |
| AUTH_CHALLENGE 无 effect | `UNREACHED` / 对照事实 |

**as-built 注**：服务端硬状态机尚未完整实现组链装配；TRIAGE/REPORT 以提示词 + `FindingBindings` 为主（见 [OPEN_GAPS.md](OPEN_GAPS.md) P0-G）。

## 4. SQL H3（DYNAMIC_CONFIRMED）

- Family：DATAFLOW / SQL  
- 同 PathRun `correlationId` + marker SQL 正负  
- MOCK provenance / 错误归属 / 字符串巧合 → 不升  
- 实现：`DynamicConfirmedGate`

## 5. PathTrace 事件种类（规范）

`ENTRY` · `PARAMETER` · `METHOD_HOP` · `GUARD` · `EFFECT` · `DEPENDENCY` · `EXCEPTION` · `EXIT`  
预算截断必须可见（`TRACE_TRUNCATED` / `TRACE_BUDGET_EXHAUSTED`）。依赖不可达时保留失败前 effect，退出原因写依赖缺口。

## 6. 超时分类（PathRun）

`BUSINESS_TIMEOUT` · `COLD_START` · `ENGINE_BUSY` · `TRANSPORT_ERROR`  
AI 只能引用标签，不得单独写成 CONFIRMED/VERIFIED。

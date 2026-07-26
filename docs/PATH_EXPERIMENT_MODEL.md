# 路径实验模型（Path Experiment Model）

本文档是路径调试型审计的**单一事实源**：PathRun、身份轨、实验计划、超时分类、SQL D1–D3 与 `DYNAMIC_CONFIRMED` 门禁。实现与其它文档若冲突，以本文为准；变更须同步 [AUDIT_FLOW.md](AUDIT_FLOW.md)、[PRD.md](PRD.md) 与 [PROJECT_MEMORY.md](../PROJECT_MEMORY.md)。

## 1. 产品定位

溯脉对每个入口做**可对照代码的路径实验**（类似人工 debug）：

1. 弄清鉴权方式与可合成身份；
2. 按未授权 / 普通用户 / 管理员 / 绕过候选轨执行实验计划；
3. 将 HTTP、Agent、SQL 观测对齐到 PathRun；
4. 再谈漏洞分级。

AI 负责编排实验与写笔记，不能改变沙箱权限、网络策略、挂载或单独升级验证状态。

## 2. 验证状态全集

| 状态 | 含义 |
|------|------|
| `STATIC_INFERRED` | 仅静态图/注解/配置信号 |
| `DYNAMIC_SUSPECTED` | 运行时观测到达关键点或 SQL 差分疑似，闭环未充分 |
| `DYNAMIC_CONFIRMED` | 动态调试证明恶意片段进入实际发往 DB 的语句，且中途无过滤/参数化阻断（见 §7） |
| `VERIFIED` | 强化沙箱 + 更严可重放门禁；本阶段 SQL 命中**不**直接升此级 |
| `UNREACHED` | 预算、身份不可用、冷启动失败等原因未完成实验 |

模型输出不能单独升级上述任一状态。

## 3. 身份轨（Identity Track）

| 轨 | 码 | 说明 |
|----|-----|------|
| 未授权 | `UNAUTH` | 不携带合成凭据 |
| 普通用户 | `USER` | 平台合成低权限身份 |
| 管理员 | `ADMIN` | 平台合成管理员身份 |
| 绕过候选 | `BYPASS_CANDIDATE` | 针对鉴权分析点名的绕过假设做验证 |

- 身份材料默认**平台合成**（从制品推断 JWT 密钥等），provenance 必须为 `MOCK` 或 `RULE_GENERATED`，报告展示前置条件。
- 合成失败 → 该轨 `IDENTITY_UNAVAILABLE`，不得假装已执行。
- **预算（T2+T3）**：高价值入口默认四轨；其余入口 `UNAUTH` +（合成成功则）`ADMIN`；每入口实际轨集合由 `AUTH_ANALYSIS` 指定，服务端强制总预算上限。

高价值启发式（服务端可扩展）：上传 / deploy / token / exec / admin 路由、静态敏感 sink 命中、或 `AUTH_ANALYSIS` 显式标注。

## 4. PathRun（一等公民）

键：`scanId + entryId + track + attemptId`。

最小字段：

- `entrypointRef`（`entry:*`）
- `track`（§3）
- `experimentPlanId`（若有）
- 请求摘要（method、content-type、参数名、身份轨；敏感值脱敏）
- `outcomeClass`（§5 超时/失败枚举）
- HTTP 状态或传输结果
- `entryHit` / `parameterBound`（布尔或 unknown）
- 调用/Agent 事件摘要引用
- `sqlEvents[]`（§6）
- `stopReason` / 证据引用列表

GUI、动态验证、路径探索与漏洞研判围绕 PathRun 组织；`AUTH_GAP` 仅为次级静态信号，不得作为结果主列表。

## 5. 超时与失败分类（最小必选）

由探针或 Agent 打标；AI 只能引用，不得发明新码。

| 码 | 含义 |
|----|------|
| `COLD_START` | 应用尚未就绪 / 冷启动窗口内 |
| `AUTH_CHALLENGE` | 401/403/登录重定向/显式鉴权拒绝 |
| `REACHED_NO_BIND` | HTTP 进入入口，但参数未绑定或业务未继续 |
| `BUSINESS_TIMEOUT` | 进程已就绪，单次业务请求超时 |
| `ENGINE_BUSY` | 部署/工作流/引擎处理中 |
| `DEPENDENCY_MOCK_GAP` | MOCK/缺表/缺数据导致的业务失败（非注入证明） |
| `TRANSPORT_ERROR` | 连接重置、协议错误等 |
| `PROBE_BUDGET` | 预算用尽 |
| `UNKNOWN` | 无法归入以上时 |

面向 GUI / AI 的解释边界：

- `BUSINESS_TIMEOUT`：应用进程已就绪，单个业务请求在读响应阶段耗尽预算；这说明入口可能进入了业务逻辑或阻塞等待依赖，但不能单独证明漏洞或绕过。
- `COLD_START`：连接失败、拒绝或冷启动窗口内不可达；优先解释为应用未监听或尚未完成启动，不应当被写成业务入口已执行。
- `ENGINE_BUSY`：平台、工作流或应用引擎返回忙碌 / 锁定 / 限流 / 5xx 且不像依赖替身缺口；GUI 可提示稍后重试或收窄实验。
- `TRANSPORT_ERROR`：连接重置、协议错误、EOF 等传输层异常；它不同于业务读超时，也不同于冷启动拒绝。
- `AUTH_CHALLENGE`：401/403/登录跳转或明确鉴权拒绝；只有与其它身份轨形成对照时，才可用于鉴权绕过分析。

任何超时或失败分类都**不能**单独触发 `DYNAMIC_CONFIRMED`；`DYNAMIC_CONFIRMED` 仍只来自 §7 的 SQL H3 服务端门禁，且模型不得单独升级。

## 6. 实验计划与鉴权绕过 PoC（AI 生成，服务端闸门）

所有权：**M** — AI 角色研判并**撰写结构化 PoC**；服务端校验 schema/预算/安全后由动态阶段执行并追踪。

每入口 × 轨建议字段：

- `method`、`contentType`
- 必填参数名与有界取值提示
- `authRequired` / 建议轨
- 成功判据：HTTP（如 2xx）+ JSON 字段路径，和/或 Agent 事件类型
- 预算内最大尝试次数

鉴权绕过可行性（`bypassPoCs` / `bypassCandidates`）额外字段：

- `entryRef`（`entry:<scanEntryId>`）
- `techniqueId`（标签，可为 `ALG_NONE` / `CUSTOM_POC` 等）
- `track`、`rationale`、`evidenceRefs`、`confidence`
- **AI 撰写的** `authorizationHeader` / `bladeAuthHeader` / `query` / `bodyHint`（可含 JWT、alg-none、自定义 claims）

交接契约：`AUTH_ANALYSIS`（及研判）→ 服务端 schema 校验并写入 conclusion → `DYNAMIC_VERIFICATION` 用户提示注入 `AUTH_BYPASS_FEASIBILITY` → `sandbox_probe` 携带 AI auth 材料执行 → PathRun/Agent 观测。已知 technique 合成器仅作**无 header 时的回退**，不是唯一路径。若扫描有 JWT/AUTH_GAP/鉴权标注入口而 AUTH 仍空 `bypassPoCs`，服务端发 `AUTH_BYPASS_POC_REQUIRED` 强制补写一轮；仍空则填充标明 `RULE_GENERATED` 的草案供 DYNAMIC 尝试（不升验证级）。

服务端必须拒绝：非 `entry:*`、超长/非法字符头、破坏性 payload、试图改变 `NetworkPolicy.DENY` / 挂载 / UID / 命令。不得由模型单独升级 `DYNAMIC_CONFIRMED` / `VERIFIED`。

## 7. SQL 观测 D1–D3 与 DYNAMIC_CONFIRMED

| 级 | 承诺 |
|----|------|
| **D1** | JDBC/驱动或协议替身层记录 SQL 文本、参数摘要、读写类型，挂到 PathRun；最高可为观测事实 |
| **D2** | 同入口良性输入 vs 元字符探针差分；输入影响 SQL 结构 → 最高 `DYNAMIC_SUSPECTED` |
| **D3** | 可重放实验卡齐套（身份轨、输入、SQL 前后对比、停止条件）；默认仍不升 `VERIFIED` |

**H3 / `DYNAMIC_CONFIRMED` 服务端门禁**（模型不能单独升级）：

1. 存在绑定同一 PathRun 的动态调试轨迹；
2. 实际发往数据库（含 MOCK JDBC/协议替身）的语句文本中出现与探针对应的恶意片段；
3. 从入口参数到该 SQL 的路径上无过滤、无参数化阻断的证据（Agent/插桩记录）；
4. 实验可重放引用齐全。

`DYNAMIC_CONFIRMED` ≠ 生产实库已证实；报告必须标注 `MOCK` 依赖与合成身份前置条件。`VERIFIED` 仍留给强化隔离沙箱与更严门禁。

## 8. 与流水线的关系

见 [AUDIT_FLOW.md](AUDIT_FLOW.md)。摘要：

```text
静态事实 → PRE_ANALYSIS → AUTH_ANALYSIS
  → DYNAMIC_OBSERVATION（按轨；非 AI）
  → AUTH_ANALYSIS 绕过确认（需动态 401/过闸证据）
  → DYNAMIC_VERIFICATION → PATH_EXPLORATION
  → VULNERABILITY_TRIAGE → REPORT_GENERATION
```

## 9. 非目标

- LLM 单独升级任何验证状态；
- 自动攻击真实生产数据库；
- 将 `DYNAMIC_CONFIRMED` 宣传为生产已证实；
- 破坏性 payload、内存马、外带网络。

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

## 6. 实验计划（AI 生成，服务端闸门）

所有权：**M** — AI 角色生成；服务端校验预算与安全后执行。

每入口 × 轨建议字段：

- `method`、`contentType`
- 必填参数名与有界取值提示
- `authRequired` / 建议轨
- 成功判据：HTTP（如 2xx）+ JSON 字段路径，和/或 Agent 事件类型
- 预算内最大尝试次数

服务端必须拒绝：非 allowlist content-type、超预算、非 `entry:*`、破坏性 payload、试图改变 `NetworkPolicy.DENY` / 挂载 / UID。

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

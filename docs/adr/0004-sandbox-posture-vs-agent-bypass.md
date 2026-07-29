# ADR-0004: 动态路径调试器优先于 Agent 逐点绕过

- Status: `PROPOSED`
- Date: 2026-07-29
- Owners: root Agent / human architecture owner
- Related: [DYNAMIC_SANDBOX_POSTURE_REDESIGN.md](../DYNAMIC_SANDBOX_POSTURE_REDESIGN.md)、MVP_BACKLOG P0-21、PATH_EXPERIMENT_MODEL §3、PROJECT_MEMORY §2.1–§2.2

## Context

动态目标不是“所有接口必须 2xx”，而是：在授权 Docker 沙箱中对每个可识别入口做有界路径调试，尽最大努力记录失败前真实经过的业务路径、参数流、sink/effect 触发和最终阻断原因。即使数据库、License、文件、状态或依赖不可达，也要保留此前 Controller/Service/Util/Repository/Guard/Effect 证据，并反馈给 AI 做路径探索、漏洞研判和报告。

当前实现倾向用请求头 JWT mint + Agent 内依赖/组件 fail-open（JDBC mock、Quartz 等）缓解启动与墙。产品指出：这无法稳定覆盖 Filter/License，也不能保证业务流通，且「每来一种墙就加插桩」不可扩展。强达路径可以作为默认探索轨，但必须限定在 Docker 沙箱、服务端固定策略和独立 provenance 下，不能散落成 Agent Bypass Zoo。

## Decision

（提案，待架构组 ACCEPTED 后生效）

1. 动态能力重构为 **TracePlan + ExperimentPlan + Runtime Posture + World Pack + Sensor Agent + PathTrace**。
2. 默认执行三轨：
   - `UNAUTH`：真实撞墙并标注 `authRequirement`。
   - `COVERAGE_POSTURE`：标准框架边界注入扫描身份，尽量进入业务。
   - `FORCED_REACHABILITY`：默认开启、仅 Docker 沙箱内，对已识别 auth/role/permission/license/feature guard 强达，以观察下游路径。
3. **Agent** 收敛为 Sensor：记录 entry、参数、方法 hop、guard、effect、dependency、exception 和 exit；新增鉴权/License/中间件 fail-open 特例视为反模式。
4. **World Pack** 负责 profile/env/license/files/schema/seed/dependency stubs；依赖不可达时输出 `WORLD_GAP` / `DEPENDENCY_UNAVAILABLE`，并保留失败前路径。
5. `FORCED_REACHABILITY` 只能由服务端固定策略启用，不能绕过 sanitizer、SQL 参数化、文件类型校验、金额/审批/状态机不变量；其结果必须标 `INSTRUMENTATION_REACHABILITY`，不能单独升 `DYNAMIC_CONFIRMED` / `VERIFIED`。
6. JWT/Blade mint 降为可选 `IdentityMaterial` 来源，不再叙述为覆盖全部鉴权形态的主策略。

细节、As-Is/To-Be 对照与待拍板问题见设计简报，不在本 ADR 重复实现清单。

## Alternatives

| 方案 | 结果 |
|------|------|
| 继续扩展 Agent Bypass Zoo | 拒绝作为主路线（不可扩展、证据语义混乱） |
| 仅加强 JWT mint / IdentityProvider SPI | 不足：Filter/License/世界状态仍堵 |
| 默认所有 if/校验都 return true | 拒绝：会绕过 sanitizer 和业务不变量，产生无意义假阳性 |
| 默认 Docker-only 强达已识别鉴权/License guard | 接受为提案主路线，但必须独立 provenance 和门禁 |
| TracePlan + World Pack + Sensor Agent（本决策） | 提案主路线 |

## Consequences

- 控制面/沙箱启动需增加 posture、worldPack、tracePlan、pathTrace 和 provenance 字段；GUI/Diagnostics 需展示 Posture/World/Forced gaps。
- 现有 Quartz、JDBC、Redis、MySQL 等特例需迁移到 World Pack 或 Sensor 语义；禁止继续扩展“弄通型 Agent 特例”。
- P0-21 文档需从「mint 特权覆盖轨」改写为「三轨路径调试」。
- 最终报告需按入口展示最深可达路径、参数流、sink/effect、退出原因和强达/MOCK 限制。

## Security

- 姿态与强达仅在授权断网 Docker 或后续 hardened sandbox 内启用；不得影响宿主。
- 强达轨默认开启，但必须由服务端固定策略限定 guard refs、预算和可改写范围；AI/前端不能提供策略。
- 结论强制 `postureKind` / `postureProvenance` / `forcedGuardRefs`；禁止仅凭 Posture 或强达升 `VERIFIED`。
- 沙箱失败仍不得回退宿主。

## Compatibility

- PathRun track 线码（`UNAUTH`/`USER`/`ADMIN`/`BYPASS_CANDIDATE`）可保留；用途语义对齐流通/撞墙/确认。
- 旧扫描无 Posture/World/Trace 字段时按「未流通 / 仅摘要 PathRun」解释，不得回填假阳性。
- 旧 SQL/JDBC/HTTP 摘要可以投影为简化 PathTrace，但必须标 legacy/incomplete。

## Migration

见设计简报 §6–§8。本 ADR `PROPOSED` 期间不得把 Posture、World Pack、FORCED_REACHABILITY 或 PathTrace 标为已验证生产能力。

## Validation

- 架构组评审通过后改为 `ACCEPTED`。
- 验收以改写后的 P0-21 + 至少一个“effect 已触发但 DB 不可达仍完整保留失败前路径”的样本为准，而非文档存在。

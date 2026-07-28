# ADR-0003: 生产 session / CSRF / SSO / 多租户 / 数据保留（暂缓）

- Status: `PROPOSED`
- Date: 2026-07-28
- Owners: implementation Agent (proposal only)
- Related: P2 production session、[ADR-0001](0001-polyglot-control-plane-and-workers.md)、[PROJECT_MEMORY](../../PROJECT_MEMORY.md)

## Context

当前产品是个人本地版：loopback REST/SSE、本地 PAT、单节点 SQLite。P2 Backlog 列出生产 session、CSRF、SSO、多租户隔离和数据保留策略，但这些能力会改变信任边界、认证模型、租户数据隔离和保留/删除合同。

在产品范围仍明确为本地个人垂直切片时，提前实现半成品 session/SSO 容易：

- 用浏览器 cookie / CSRF token 冒充已完成生产鉴权；
- 在单租户存储上叠加伪多租户字段却无隔离证明；
- 让 GUI 或文档暗示“企业可用”，而门禁与审计并未闭合。

## Decision

1. **暂不启用**生产 session、CSRF、SSO/OIDC、多租户隔离和数据保留策略执行路径。
2. 在代码中仅保留 fail-closed 脚手架：`ProductionFeatures.DISABLED == true`，且 `SESSION_AUTH` / `CSRF_PROTECTION` / `SSO_OIDC` / `MULTI_TENANT_ISOLATION` / `DATA_RETENTION_POLICY` 恒为 `false`。
3. 现有本地 PAT + loopback 边界保持为唯一可用认证/授权路径，直到本 ADR 被 `ACCEPTED` 且有独立审计证据。
4. 任何试图在未接受 ADR 前打开上述开关的代码路径必须失败关闭。

## Alternatives

### 立即实现 cookie session + CSRF

可改善浏览器凭据形态，但会扩大攻击面与状态机复杂度，且当前无远程部署需求触发。[DEVELOPMENT_PLAYBOOK](../DEVELOPMENT_PLAYBOOK.md) 要求可观测触发条件后才选型。**暂缓**。

### 引入外部 IdP / SSO

超出个人本地版范围；会牵涉密钥托管、回调、租户映射。**暂缓**。

### 仅写文档不做 fail-closed 旗标

无法阻止后续任务误开半成品能力。**拒绝**。

## Consequences

正面影响：

- 产品边界诚实；本地 PAT 语义不被伪生产层掩盖；
- 后续升级有明确 ADR 与旗标门禁。

成本与限制：

- 远程访问、多用户并发写、企业 SSO 仍不可用；
- 脚手架类存在不等于能力交付（Backlog 标 `SCAFFOLDING`）。

## Security

- 未启用时不得签发生产 session cookie，不得接受 CSRF token 作为授权依据。
- SSO / 多租户字段不得参与授权或扫描隔离，直到实现与测试闭合。
- 数据保留策略未启用前不得静默删除用户证据；删除若存在必须显式、可审计且 fail-closed。

## Compatibility

- `/api/v1` 本地 PAT 行为不变。
- 不修改已应用 SQLite migration；未来 session/tenancy 表只追加新迁移。

## Migration

1. 保持 `ProductionFeatures` 全关与验收测试断言。
2. 产品范围升级时由根 Agent 将本 ADR 改为 `ACCEPTED`，再分任务实现 session → CSRF →（可选）SSO → 租户隔离 → 保留策略。
3. 每一项独立审计后才可从 `SCAFFOLDING` 升为 `PARTIAL` / `AUDITED`。

## Validation

- `ProductionFeaturesAcceptanceTest`（或等价门禁）断言所有旗标为 false / `DISABLED`。
- 不存在默认开启 session/SSO/多租户的配置路径。
- Backlog P2 对应项保持 `SCAFFOLDING`，不得标已验证或生产可用。

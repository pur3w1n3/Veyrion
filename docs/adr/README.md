# Architecture Decision Records

ADR 记录影响多个模块、公共合同或长期迁移方向的架构决定。实现状态不写入 ADR，仍以 [MVP Backlog](../MVP_BACKLOG.md) 为准。

## 状态

- `PROPOSED`：允许讨论和原型，不得作为既定架构实施。
- `ACCEPTED`：后续任务必须遵守，可分阶段迁移。
- `SUPERSEDED`：被新 ADR 替代，保留历史引用。
- `REJECTED`：不实施，记录拒绝原因。

## 何时必须写 ADR

- 新增/替换前后端框架、数据库、队列、RPC、静态分析引擎；
- 改变公共 API、Security IR、Worker/Analyzer 协议或兼容策略；
- 新增语言、运行时、插件执行方式或信任边界；
- 改变 AI 角色、工具权限、沙箱、验证门禁或证据语义；
- 改变单节点/本地产品边界或引入跨模块反向依赖。

## 模板

```markdown
# ADR-NNNN: 标题

- Status: PROPOSED
- Date: YYYY-MM-DD
- Owners: root Agent / human owner
- Related: backlog IDs and documents

## Context
## Decision
## Alternatives
## Consequences
## Security
## Compatibility
## Migration
## Validation
```

ADR 只决定方向，不以接口名、空实现或文档存在冒充交付完成。普通实施 Agent 不得自行把自己创建的 ADR 从 `PROPOSED` 改为 `ACCEPTED`。

## Index

| ADR | Status | Decision |
|-----|--------|----------|
| [0001](0001-polyglot-control-plane-and-workers.md) | `ACCEPTED` | 保留 Java/React 控制面，以语言无关合同连接进程外 Analyzer 和 Runtime Adapter |
| [0002](0002-jvm-static-analysis-kernel.md) | `ACCEPTED` | JVM CFG/MethodSummary 轻量内核 + 自研加深；暂缓 Soot/WALA；完整引擎须进程外独立 ADR |
| [0003](0003-production-session-deferred.md) | `PROPOSED` | 生产 session/CSRF/SSO/多租户/数据保留暂缓；`ProductionFeatures` 恒 fail-closed |


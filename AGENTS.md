# Agent 工作约定

开始任何实现、审计或文档变更前，按顺序阅读：

1. [PROJECT_MEMORY.md](PROJECT_MEMORY.md)：稳定产品决策、当前基线和不可破坏边界；
2. [开发与 AI 实施手册](docs/DEVELOPMENT_PLAYBOOK.md)：技术路线、模块边界、门禁和 Definition of Done；
3. 目标路径上的作用域 `AGENTS.md`；
4. 任务引用的领域文档、Backlog 条目和 ADR。

实现任务应使用 [AI 任务包模板](docs/AI_TASK_TEMPLATE.md) 明确 Task ID、当前行为、目标行为、允许路径、禁止项、验收和测试。用户未提供完整任务包时，Agent 必须在动手前自行整理等价任务合同。

- 根 Agent 负责产品/架构决策和最终审计。
- 子 Agent 只实现明确分配的任务，并报告改动、假设、测试和限制。
- 可安全拆分且文件边界明确的任务，默认并行启动多个子 Agent；根 Agent 负责划分互不冲突的修改范围、汇总结果、处理集成冲突并完成统一回归。
- 未经审计的能力不得标记为已验证或生产可用。
- 不得让被测制品、模型输出或前端输入改变工具权限、沙箱策略或授权范围。
- 当前技术路线是 React GUI + Java Control Plane + SQLite 的 JVM 优先垂直切片；多语言目标使用进程外 LanguageAnalyzer、独立 RuntimeAdapter 和中立合同，不复制控制面、流水线、数据库或 GUI。
- 公共合同必须版本化并保留 scope、provenance、coverage、stop reason 和 evidence refs；AI、前端与插件不能补写 FACT 或提升验证状态。
- 已应用迁移不得修改；沙箱失败不得回退宿主执行；模型不能提供命令、镜像、挂载、网络、UID 或预算。
- 新增/替换框架、数据库、队列、RPC、分析引擎、语言运行时、公共协议兼容策略或安全门禁前，必须引用 [已接受 ADR](docs/adr/README.md)。
- 完成前审计实际 diff、兼容/迁移、权限拒绝路径和真实非零测试；实现状态只按证据更新 [MVP Backlog](docs/MVP_BACKLOG.md)。

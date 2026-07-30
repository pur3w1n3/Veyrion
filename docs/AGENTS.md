# 文档实施约束

本文件适用于 `docs`，并继承根目录规则。

- 日常主读路径：as-built（[CURRENT_SYSTEM](CURRENT_SYSTEM.md) 等）；产品意图与代码分轨，见 [AUDIT_FLOW.md](AUDIT_FLOW.md)。
- 每个能力明确标注 current、target 或 audited gap；设计文档存在不代表实现存在。
- 开放差距维护 [OPEN_GAPS.md](OPEN_GAPS.md)；[MVP Backlog](MVP_BACKLOG.md) 保留开放工作与基线一页。
- [开发手册](DEVELOPMENT_PLAYBOOK.md) 维护工程流程。
- 不复制大段领域内容到 PROJECT_MEMORY，不维护实现流水账。
- ADR 状态只能由根 Agent/产品所有者决定；普通实施 Agent 只能新增 `PROPOSED`。
- 删除或改名文档时检查 Markdown 链接；`docs/` 可能 gitignore，仍以磁盘一致性为准。
- 文档任务不得顺便修改源码、测试或生成物；未跟踪用户文件保持不动。

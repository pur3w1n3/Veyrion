# 文档实施约束

本文件适用于 `docs`，并继承根目录规则。

- 每个能力明确标注 current、target 或 audited gap；设计文档存在不代表实现存在。
- [MVP Backlog](MVP_BACKLOG.md) 是唯一实现状态来源；[开发手册](DEVELOPMENT_PLAYBOOK.md) 维护工程流程。
- 不复制大段领域内容到 PROJECT_MEMORY，不维护实现流水账。
- ADR 状态只能由根 Agent/产品所有者决定；普通实施 Agent 只能新增 `PROPOSED`。
- 删除或改名文档时检查全部受跟踪 Markdown 链接，并执行 `git diff --check`。
- 文档任务不得顺便修改源码、测试或生成物；未跟踪用户文件保持不动。

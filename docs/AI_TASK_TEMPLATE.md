# Veyrion AI 实施任务包模板

> 将下面代码块完整填写后直接交给实施 AI。任务包负责缩小上下文和修改范围；根目录及作用域 `AGENTS.md`、安全边界和已接受 ADR 始终优先。开发流程见 [开发与 AI 实施手册](DEVELOPMENT_PLAYBOOK.md)。

## 1. 可直接使用的提示词

```text
你正在 E:\ai\Veyrion 实施一个有界任务。

强制阅读顺序：
1. 根 AGENTS.md；
2. PROJECT_MEMORY.md；
3. `docs/DEVELOPMENT_PLAYBOOK.md`；
4. 目标文件路径上生效的所有作用域 AGENTS.md；
5. 本任务列出的领域文档和 ADR。

工作规则：
- 先审计现有实现和 git 状态，再复述任务合同；不要凭文档假设代码已实现。
- 只修改 Allowed paths。发现必须修改其他路径时先说明原因和影响，不得静默扩展范围。
- Forbidden changes 不得以兼容、临时方案或测试便利为理由绕过。
- 若触发架构变更条件，停止实现并提交 ADR 草案/决策问题。
- 不得撤销或覆盖用户和其他 Agent 的已有改动；共享文件由根 Agent 集成。
- 实施最小垂直切片，完成测试、diff 审计和文档状态核对。
- 未经实际证据不得使用“已验证”“生产可用”“完整支持”等表述。
- 最终报告必须包含：改动、合同/迁移影响、实际测试、假设、限制、剩余风险。

Task ID: <BACKLOG-ID 或 ISSUE-ID>
Goal: <单一可验证目标>
Current audited behavior: <当前真实行为和证据位置>
Target behavior: <完成后的外部可观察行为>
Security invariant: <不可破坏的授权/沙箱/证据/状态规则>

Allowed paths:
- <path>

Forbidden changes:
- <明确禁止的文件、依赖、权限、迁移或重构>

Required reading:
- <领域文档或 ADR>

Acceptance criteria:
- <可执行断言 1>
- <可执行断言 2>

Required tests:
- <命令与必须执行的测试范围>

Compatibility/migration:
- <API/schema/database/event 兼容要求，或明确 N/A>

Out of scope:
- <相邻但本次不做的工作>

Deliverable report:
- changed files
- behavior and contract changes
- tests actually executed and result
- assumptions and limitations
- residual risks / follow-up backlog
```

## 2. 根 Agent 分派检查表

分派前必须确认：

- Task ID 对应 Backlog 或已接受 ADR，不是模糊的“优化一下”。
- 一个任务只有一个主要可观察目标。
- 当前行为来自代码/测试审计，并区分 current 与 target。
- Allowed paths 边界清晰；并行任务不共享文件，或共享文件明确由根 Agent 处理。
- Security invariant 写出 fail-closed 行为。
- Acceptance criteria 能由测试或确定性检查证明。
- Required tests 写明命令，不以“相关测试”代替。
- schema、迁移、事件、前端消费者和旧数据兼容已考虑。
- Out of scope 阻止顺手重构和提前实现后续阶段。

## 3. 任务拆分规则

适合独立分派：

- schema/contract 设计与 consumer fixture；
- 单一 adapter/detector/provider；
- 独立前端视图，前提是 API 合同已冻结；
- 单一迁移及 repository 行为；
- 文档或基准集审计。

不适合直接并行：

- 多个任务同时修改 `ControlPlaneServer`、`ApiDtos`、SQLite migration registry 或前端 `api.ts`；
- 合同尚未冻结时同时实现 producer 和多个 consumer；
- 一个任务改权限，另一个任务依赖新权限做动态执行；
- 多个 Agent 同时更新 PROJECT_MEMORY、MVP_BACKLOG 或同一 ADR。

共享合同由根 Agent 先定稿或指定唯一所有者。消费者可以在冻结的 schema/fixture 上并行实现。

## 4. 架构变更快速判定

以下任一答案为“是”，任务包必须引用已接受 ADR，否则只允许输出提案：

- 是否新增或替换框架、数据库、消息队列、RPC、分析引擎或核心依赖？
- 是否改变公共 API、Security IR、Worker/Analyzer 协议的兼容策略？
- 是否新增语言、运行时、插件代码执行或信任边界？
- 是否改变 AI 角色顺序、工具 allowlist、沙箱策略或验证状态门禁？
- 是否引入跨模块反向依赖，或绕过 repository/application/worker port？
- 是否把单节点、本地、受信调试能力描述为远程、多用户或生产能力？

## 5. 实施报告模板

```text
Task: <ID>
Status: COMPLETE | PARTIAL | BLOCKED

Changed:
- <file>: <behavior, not narration>

Contracts/migrations:
- <schema/API/DB/event impact or N/A>

Verification:
- <exact command>: <passed/failed, executed test/assertion count when available>

Assumptions:
- <assumption>

Limitations and residual risks:
- <not implemented, not covered, or environment limitation>

Backlog/document updates:
- <what status may be updated and evidence; do not self-promote without root audit>
```

## 6. 示例：有界后端任务

```text
Task ID: P0-03
Goal: 为同一 AI Job 内每次 sandbox_probe 建立独立 probeAttemptId，并保持相同调用重放幂等。
Current audited behavior: 工具调用复用 job 级幂等身份，不同 payload 发生冲突。
Target behavior: canonical tool call + payload hash 绑定独立 attempt；完全相同调用重放返回原 attempt。
Security invariant: 不扩大 PATH/TRIAGE allowlist，不允许模型提供命令、网络、挂载或预算。
Allowed paths:
- src/main/java/com/aq/jvmsentinel/ai/tool/
- src/main/java/com/aq/jvmsentinel/control/persistence/
- src/test/java/com/aq/jvmsentinel/ai/tool/
- src/main/resources/db/migration/<new-only>
Forbidden changes:
- 不修改已应用迁移
- 不改变 VERIFIED/DYNAMIC_CONFIRMED 门禁
- 不重构整个 ControlPlaneServer
Required reading:
- docs/PATH_EXPERIMENT_MODEL.md
- docs/TECHNICAL_ARCHITECTURE.md
- docs/adr/0001-polyglot-control-plane-and-workers.md
Acceptance criteria:
- 两个不同 payload 生成不同 attempt 并都可执行
- 相同 payload 重放复用原 attempt
- 跨 project/scan/job 引用被拒绝
Required tests:
- mvn test（必须确认非零执行）或任务指定的统一 acceptance runner
Compatibility/migration:
- 旧记录只读兼容；新增 SQL migration，不改 V001-V021
Out of scope:
- PATH/TRIAGE allowlist 扩展
- Analyzer 协议与多语言支持
```


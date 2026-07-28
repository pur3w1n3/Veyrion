# 前端实施约束

本文件适用于 `frontend`，并继承根目录规则。

## 必读

- [前端开发说明](README.md)
- [GUI 设计规范](../docs/GUI_DESIGN.md)
- [开发与 AI 实施手册](../docs/DEVELOPMENT_PLAYBOOK.md)

## 数据与架构

- 浏览器只访问版本化 `/api/v1`。API 调用必须经 `src/api.ts` 或经明确迁移任务建立的后继边界；组件不得直接 `fetch`、访问 SQLite、制品、Worker、Docker 或模型 Provider。
- 每个响应和 SSE 事件在边界处校验 schema、scope 和验证状态；SSE 只触发增量刷新，GET 是最终状态事实源。
- 页面按 capability、hypothesis family、security property、entry protocol 和通用 evidence 展示。不得在主流程增加按 Java/Spring/Python/某框架分叉的页面逻辑。
- 语言/框架特有内容使用可选 renderer；未知 kind/extension 必须可降级展示，不能导致整个扫描打不开。
- API 类型、运行时 parser 和 Demo fixture 必须保持同一合同；目标是 schema 生成或契约测试，禁止手写三份含义不同的 DTO。

## 安全与语义

- 前端不保存原始 Provider 凭据，不执行模型/制品文本，不使用不可信 `innerHTML`。
- 前端不能构造 Worker 命令、镜像、挂载、网络、UID、预算、工具 allowlist 或验证状态。
- `STATIC_INFERRED`、`DYNAMIC_SUSPECTED`、`DYNAMIC_CONFIRMED`、`VERIFIED`、`UNREACHED` 和 coverage unknown 必须按服务端值展示，不做本地升级。
- MOCK、RULE_GENERATED、INFERENCE 和 FACT/RUNTIME_OBSERVED 保持可区分；颜色不是唯一信号。

## 验证

- 至少执行 `npm run build`，并覆盖 schema parser 的正常、缺失、malformed、unknown kind 和旧版本场景。
- UI 修改检查 loading、empty、error、partial/unknown、长文本和窄屏；无后端时不得静默回退 Demo。
- 前端显示“已验证”“完整支持”前必须存在服务端合同和 Backlog 审计证据。


# 溯脉 · Veyrion GUI

本目录是与 Java Control Plane 解耦的 React、TypeScript、Vite 前端。浏览器只访问 `/api/v1`，不直接连接制品、SQLite、沙箱或模型供应商。

## 开发

```powershell
npm install
npm run dev
```

未设置 `VITE_DEMO_MODE` 或设置为 `false` 时使用真实 Control Plane；只有显式设为 `true` 才加载本地演示数据。真实 API 失败会显示错误，不会回退到 Demo。

```dotenv
VITE_DEMO_MODE=false
VITE_API_BASE_URL=http://127.0.0.1:18080/api/v1
VITE_PROJECT_ID=project-01
VITE_API_TOKEN=local-demo
```

`VITE_SCAN_ID` 可选。`VITE_API_TOKEN` 会进入浏览器 bundle，只适合 loopback 本地调试；生产级 HttpOnly session、CSRF 和 SSO 尚未实现。

## 前端边界

- `src/api.ts` 是后端访问边界。响应和 SSE 事件必须校验 schema、作用域和验证状态；SSE 只作增量提示，最终状态通过 GET 补偿。
- 创建类请求使用 `Idempotency-Key`。后端已对项目、制品、扫描、组合审计、动态任务、replay 和 AI probe 绑定提供 SQLite 跨重启幂等，不是旧的进程内幂等。
- 前端不保存原始 Provider 凭据，不执行模型文本，不用模型输出升级验证状态，不把不可信文本写入 `innerHTML`。
- CSP 默认只允许同源和 loopback Control Plane。部署到其他域名时必须精确生成 `connect-src`，不能放宽为 `*`。
- 统一展示 `STATIC_INFERRED`、`DYNAMIC_SUSPECTED`、`DYNAMIC_CONFIRMED`、`VERIFIED` 和 `UNREACHED`；颜色不能是唯一状态信号。
- 结果页默认展示最终 REPORT；PathRun、发现、证据和对照账本是可切换的证据视图。
- 当前三种下载是不同制品：最终报告 Markdown、发现摘要 HTML、扫描仪表盘快照 JSON。它们不是同一报告的等价格式。
- 隐藏 chain-of-thought 不展示。Provider 显式返回并由服务端持久化的有界 `MODEL_THINKING` 摘录只能作为审计元数据展示，不能当作事实或授权依据。
- 页面按 capability、hypothesis family、security property 和 entry protocol 展示；不能为 Java/Spring 或未来某语言复制主流程。
- 未知语言节点、入口协议和 namespaced extension 必须降级为通用 evidence/coverage 视图，不能让整个扫描不可读。
- API 类型、runtime parser 和 Demo fixture 应由同一 schema 生成或受 consumer contract 约束，避免三份手写 DTO 漂移。

页面、交互和安全验收见 [GUI 设计规范](../docs/GUI_DESIGN.md)；工程边界见 [开发手册](../docs/DEVELOPMENT_PLAYBOOK.md)；系统逻辑见 [CURRENT_SYSTEM](../docs/CURRENT_SYSTEM.md)；开放状态以 [MVP Backlog](../docs/MVP_BACKLOG.md) / [OPEN_GAPS](../docs/OPEN_GAPS.md) 为准。

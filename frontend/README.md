# 溯脉 · Veyrion GUI

这是与 Java Control Plane 解耦的 React/TypeScript/Vite GUI。界面可在显式 Demo 模式下使用本地演示数据，也可消费 `/api/v1` 版本化项目、制品、入口、扫描、证据 DTO 和 SSE 事件流。浏览器不会直接连接制品、数据库、沙箱或模型。

## 开发

```powershell
npm install
npm run dev
```

复制 `.env.example` 为 `.env.local` 后，只有将 `VITE_DEMO_MODE=true` 才会启用 Demo 数据；未设置或设置为 `false` 时使用真实 Control Plane，连接失败会显示错误而不会回退到 Mock。真实模式设置 `VITE_API_BASE_URL`、`VITE_PROJECT_ID`，当前本地 MVP 的写操作还需要 `VITE_API_TOKEN`（仅适合短期本地调试，构建时会进入浏览器 bundle）；生产级 HttpOnly 会话、CSRF 和 SSO 尚未在 Java Control Plane 实现，可选 `VITE_SCAN_ID`。

例如：

```dotenv
VITE_DEMO_MODE=false
VITE_API_BASE_URL=http://127.0.0.1:8080/api/v1
VITE_PROJECT_ID=project-01
VITE_API_TOKEN=local-demo
```

## 架构约束

- `src/api.ts` 是唯一的后端访问边界，包含 `createProject`、`registerArtifact`、`createScan`、`getEntries`、`getScan`、`getEvidence` 和 `subscribe`。所有响应和 SSE 事件都在运行时校验 `schemaVersion`、作用域和验证状态；事件只作增量提示，随后用 GET 补偿最终扫描状态。
- 变更请求会从 `idempotencyKey` 生成或复用 `Idempotency-Key` header，并从 JSON body 中剥离；Java MVP 对项目、制品和扫描创建按项目/键做内存幂等。
- 前端不保存原始凭据，不把模型文本当作 HTML 渲染，不直接访问存储层；REST 使用 `credentials: include` 兼容同源/本地跨端口 HttpOnly 会话，SSE 使用带凭据的 EventSource。
- `index.html` 的 CSP 仅允许同源和 loopback Control Plane；私有化部署到其他域名时必须由部署模板显式替换 `connect-src`，不能通过放宽为 `*` 解决。
- `VERIFIED`、`DYNAMIC_SUSPECTED`、`STATIC_INFERRED`、`UNREACHED` 状态在列表、时间线和图谱中统一表达。
- 详细页面与视觉规范见 [`../docs/GUI_DESIGN.md`](../docs/GUI_DESIGN.md)。

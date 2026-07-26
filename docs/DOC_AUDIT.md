# 三份设计文档审计摘要

产品正式名称：**溯脉 · Veyrion**（英文：**Veyrion**）。`com.aq.jvmsentinel` 包名、Maven artifactId、内部 service name 和 `/api/v1` 兼容路由保持不变；商标与域名仍需检索。

审阅范围：`PRD.md`、`TECHNICAL_ARCHITECTURE.md`、`MVP_BACKLOG.md`。

## 结论

## 产品边界修订（2026-07-26）

审计基线已按个人本地产品重新收敛：完整多租户/RBAC 和真实供应商生产互操作从当前范围移除，不得标记为缺失的 MVP 必做项，也不得在 UI/README 中暗示已具备。仍保留沙箱逃逸、越权和宿主机访问作为 P0 安全门槛；动态测试依赖用户显式授权的沙箱，沙箱失败必须禁用动态执行，不能降级到宿主机。

原文已经具备纵向闭环和清晰的产品方向，可以作为 MVP 基线；但商业化/可实施性仍需要明确运行边界、事实与推断的分层、恶意制品防护、发布闸门和可量化验收标准。本轮已直接补充这些内容。

## 已补充内容

- PRD：新增威胁模型和产品边界，明确制品/代码提示注入是不可信输入，Agent 工具调用必须受策略和审计约束；区分合成身份的代码可达性与真实环境可利用性；补充私有化/云端数据边界、可重放性、可解释性、任务幂等、MVP 资源预算和指标阈值要求。
- 技术架构：新增版本化任务事件契约、事实/推断/模拟三层数据模型、启动失败降级策略；补充容器隔离、多租户、出站网络/DNS 防护、容量和可观测性要求；补充 Agent Gateway 的 JSON Schema、工具权限和提示注入防护。
- MVP：明确单独 CLASS 默认只做静态分析，动态验收必须有完整 classpath/运行画像；把沙箱逃逸和策略绕过列为 M2 的 P0 发布门槛；补充指标首版建议阈值、里程碑依赖、发布闸门、兼容迁移/回滚和 MVP 出口标准。
- GUI：确认采用独立 React/TypeScript/Vite 前端，Java 仅提供版本化 API/事件流；补充路径探索器、攻击链画布、实时事件补偿和前端数据隔离规范，Tauri 作为后续桌面包装。

## 首条代码切片审计

- M0/M1 Java 切片通过 Java 17 编译和依赖无关验收主类；`mvn test` 在使用工作区本地 Maven 缓存时通过，但验收类本身不是 JUnit 用例，仍需显式执行 `AcceptanceTest`。
- 审计期间修正了制品大小/归档条目边界、路径真实化与注册后变更校验、配置脱敏和读取上限、JSON 控制字符转义、模型输入约束以及事件作用域上下文。
- 当前代码已提供受限动态执行、JVM Agent、JDBC/Redis/MySQL 替身、本地 SQLite Worker/trace 恢复和 V008 上传会话恢复，但普通 `TRUSTED_DOCKER` 不是强化沙箱，动态证据最多为 `DYNAMIC_SUSPECTED`，不能把替身或模型输出当作安全结论。
- 2026-07-26 曾在用户授权的 Docker Desktop Linux engine 中通过 `LocalDockerDynamicLoopAcceptanceTest`；覆盖固定 runtime digest、断网容器、只读制品挂载、loopback 探针、Agent trace 和五角色事件。rootfs/UID 兼容策略调整后需重新验收；该结果仍只属于受信内部 JAR 的开发验收。
- 事件上下文已加入项目/制品/扫描/任务作用域；Control Plane DTO 已补齐 `observedAt`、工具/模型版本和快照引用，但不可变对象存储仍未实现。
- 前端生产构建已通过，当前完整 `npm audit --audit-level=high` 无已知漏洞；真实 DTO/SSE 接入已完成 MVP slice，仍需在后续发布流程中持续锁定和升级依赖。

## Control Plane REST/SSE MVP 审计

Control Plane REST/SSE 已纳入当前 MVP slice：

- 路由统一使用 `/api/v1`，包括 health、projects、artifacts、entries、scans、paths、findings、evidence、attack-chains 和扫描 SSE events。
- 写操作要求 `X-Sentinel-Authorization` 或 `Authorization: Bearer`；扫描要求 body 显式 `authorized: true`，制品登记若显式传 `authorized=false` 则拒绝。认证令牌不等于制品授权。
- `Idempotency-Key` 只允许非空、无空白、最多 256 字符；项目/制品/扫描、audit-run、动态任务、finding replay 和 `sandbox_probe` job 绑定按作用域写入 SQLite，重启后按 payload hash 复用，冲突返回 409。
- `POST /api/v1/findings/{findingId}/replay` 已提供受控动态重放：请求体仅允许 `authorized:true`，必须有幂等键；服务端固定 `TRUSTED_DOCKER`、断网和制品挂载，返回任务状态而不直接升级 `VERIFIED`。候选输入由 `sandbox_probe` 服务端裁剪为入口参数提示（最多 8 次）。
- `GET /api/v1/scans/{id}/events` 支持 `Last-Event-ID`；SSE 事件包含 schema/context/status/evidence 字段，断线、窗口不足和终态后必须用幂等 GET 补偿。终态为 `ScanCompleted` 或 `TaskStopped`。
- `/api/v1/health` 明确返回 SQLite 持久化、`STATIC_METADATA_ONLY` 分析事实和动态能力边界；动态任务仍需用户授权沙箱，不能据此误认为已具备生产级隔离或 `VERIFIED`。

## 当前能力边界

已完成：Java 17 制品登记和有界 classfile 事实/制品内调用图、跨方法污点候选、Control Plane REST/SSE + SQLite、版本化 DTO、幂等键、SSE 终态/续接协议、React/TypeScript/Vite GUI、JVM Agent、断网 `TRUSTED_DOCKER`、批量探针、服务端受控 finding replay、JDBC/Redis/MySQL 协议替身及动态任务/trace 的单节点恢复。

未完成：gVisor/Kata 强化运行时及 P0 逃逸门禁、真实反编译器、完整 classpath/复杂分支对象流、协议替身的完整兼容性、生产级身份/会话鉴权、真实漏洞确认和 `VERIFIED` 重放门禁；完整多租户/RBAC 已明确不在当前产品范围。

前端默认 DEMO/MOCK 仅在 `VITE_DEMO_MODE=true` 时开启；真实模式必须关闭该开关并配置 `VITE_API_BASE_URL`、`VITE_PROJECT_ID`（可选 `VITE_SCAN_ID`）。真实模式失败不会自动回退到 Mock。当前本地 MVP 写操作需要 `VITE_API_TOKEN`；生产级 HttpOnly 会话、CSRF、SSO/RBAC 尚未在 Java Control Plane 实现。

最终验证命令：Java 使用 IntelliJ JBR 21 按 `--release 17` 编译，`mvn -Dmaven.repo.local=.m2 clean test` 通过，依赖无关 `AcceptanceTest` 和 `ControlPlaneAcceptanceTest` 均输出 `PASS`；前端 `npm run build` 和 `npm audit --audit-level=high`（0 vulnerabilities）通过。使用系统默认 Maven 缓存时，Surefire 可能因目录权限失败。

## 仍需由决策者确认的事项

1. 首版部署形态（本地单机、私有化服务或云端控制面）及是否允许任何云模型调用。
2. 安全验证 payload 的分级和审批人角色；默认只允许无害标记/模拟文件。
3. 基准样例规模、框架版本和真实制品样本，以便校准入口召回率、sink 到达率和攻击链有效率阈值。
4. 事件总线/任务队列和图谱存储的首版技术选型；建议先数据库任务表 + PostgreSQL/JSONB。

## 优先级审计意见

- V011 的持久化幂等键、流水线 stage recovery 和 probe plan 元数据已完成并通过重启验收；仍需保持单节点 SQLite、非分布式 exactly-once 的边界。任何 P0 沙箱隔离测试失败都不得进入外部试用。
- M1 的 WebSocket 适配器可以保留接口占位，但不应计入 HTTP MVP 验收。
- M4 的 AI 只能消费版本化证据并回退到静态规则/人工队列；GUI 不应自行生成漏洞结论。

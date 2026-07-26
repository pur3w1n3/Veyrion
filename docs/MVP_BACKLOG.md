# 溯脉 · Veyrion MVP 开发任务拆解

> 更新日期：2026-07-26  
> 权威决策与证据：[`PROJECT_MEMORY.md`](../PROJECT_MEMORY.md)（尤其 §51–§62）  
> 流程契约：[`AUDIT_FLOW.md`](AUDIT_FLOW.md) · 路径实验：[`PATH_EXPERIMENT_MODEL.md`](PATH_EXPERIMENT_MODEL.md)

产品正式名：**溯脉 · Veyrion**（英文：Veyrion）。`com.aq.jvmsentinel` 包名、Maven artifactId、内部 service name 与 `/api/v1` 路由保持兼容；商标/域名尚待法务检索。

本文档是 **MVP 活任务板**：记录已落地能力（带验证等级）、进行中缺口、以及朝愿景推进的待办。未经根 Agent 审计的能力不得标为已验证或生产可用。

---

## 1. 产品目标与诚实边界

### 1.1 愿景（长期）

```text
任意授权制品形态 / 语言
  → 全部可探入口被召回
  → AI 推导攻击路径并撰写可执行实验
  → 沙箱即「人工 debug」：入口 + 参数 → 底层真实形态（HTTP/SQL/文件/调用）
  → 证据门禁后的疑似 / 确认 / 已验证分层
```

### 1.2 当前诚实范围（MVP）

```text
Spring Boot 可执行 JAR（个人本地）
  → 注解入口召回 + 有界调用图/污点候选
  → 六角色流水线（含 AUTH_ANALYSIS）
  → 断网 TRUSTED_DOCKER：多轨洪水 + 焦点 PoC
  → JDBC / Redis / MySQL 协议 MOCK 替身
  → PathRun 一等公民；证据门禁 → 最多 DYNAMIC_SUSPECTED /（H3）DYNAMIC_CONFIRMED
  → VERIFIED 仅在强化沙箱 + 可重放门禁之后（尚未开放）
```

- **替身 ≠ 实库已证实**：`MOCK` / `RULE_GENERATED` 必须在报告中可见；`DYNAMIC_CONFIRMED` ≠ 生产实库已证实。
- **模型不能单独升级**任何验证状态；沙箱策略、网络、挂载、UID、预算不可被模型改写。
- **推荐垂直切片（当前主脊）**：`单入口人工 debug 闭环`（见 §4.0）——先把一条入口从鉴权假设做到 PathRun + SQL/HTTP 对照，再横向扩洪水与多制品。

### 1.3 验证等级图例

| 标记 | 含义 |
|------|------|
| **acceptance** | 相关 `*AcceptanceTest` / 合成 fixture 通过 |
| **live Docker** | 本机 `TRUSTED_DOCKER` + 授权制品真实跑通（仍非恶意强化隔离） |
| **partial** | 契约/代码已落地，但深度不足或未 live 复验 |
| **not started** | 未开工 |

---

## 2. 已完成项

### 2.1 静态入口与事实层

- [x] 有界 classfile 解析：Spring MVC mapping、参数注解、`PreAuthorize`/`Secured`/`RolesAllowed`、Blade `@PreAuth` 对齐权限前置条件（**acceptance**；真实制品召回率未做完整基准）
- [x] JWT / AUTH sink 规则；映射入口无鉴权注解 → 低置信度 `AUTH_GAP`（仅 `STATIC_INFERRED`）（**acceptance** + baldex 静态 smoke **partial/live**）
- [x] 制品内 `DIRECT`/`CHA`/`UNRESOLVED` 调用图；有界跨方法污点 `TaintPath`（**acceptance**；反射/代理/JNI 不伪装已解析）
- [x] 高信号 sink 目录（命令/反序列化/SSRF/SQL/文件等）；Boot loader 噪声抑制；入口–sink 精确绑定（**acceptance**）
- [x] 浏览器分块上传 → 内容寻址制品目录；路径登记为兼容高级路径（**acceptance**）

### 2.2 控制面 / 流水线 / 持久化

- [x] loopback Control Plane：`/api/v1` DTO、操作员 PAT、显式 `authorized`、幂等键（**acceptance**）
- [x] SQLite 单节点：项目/扫描/证据/AI job/事件；V007 Worker task/trace；V008 上传会话；V011 幂等绑定 + 流水线 cursor + probe plan；V013 PathRun（**acceptance**）
- [x] `audit-runs` 武装流水线；角色顺序见 [`AUDIT_FLOW.md`](AUDIT_FLOW.md)（含 `AUTH_ANALYSIS`）（**acceptance**；完整 live 依赖同进程生命周期）
- [x] 五/六角色有界 AI Job：工具白名单、脱敏事件、`INFERENCE` 边界；双语提示词 snapshot（**acceptance**；真实供应商互操作 **partial**）
- [x] finding replay → 固定 `TRUSTED_DOCKER` 任务，返回 `DYNAMIC_SUSPECTED`（**acceptance**）
- [x] 个人本地版范围收敛：完整多租户/SSO/跨租户调度**取消**为当前承诺（决策已记）

### 2.3 沙箱洪水与观测

- [x] `TRUSTED_DOCKER`：`--network none`、只读制品挂载、容器内 loopback HTTP、Agent JSONL、不可变 trace（**acceptance** + **live Docker** `aaaaa.jar` / baldex 批量探针）
- [x] 多入口预算探针（硬上限 512）、多身份轨扩展（UNAUTH 优先，再补 USER/ADMIN/BYPASS）（**acceptance** / **live Docker partial**）
- [x] 洪水 fail-closed：零 HTTP 事件不得冒充成功；双波超时；并发探针；wall clock 按波次估算（**acceptance**；需 `-RebuildRuntimeImage` 后 live）
- [x] in-JVM JDBC mock + Redis RESP + MySQL Classic 有界子集；事件 `MOCK`/`RULE_GENERATED`（**acceptance**；协议子集不全）
- [x] Agent 网络/DNS/JNDI 尝试事件（断网下区分「未尝试」vs「尝试被拒」）（**acceptance**）
- [x] PathRun 超时分类：`AUTH_CHALLENGE` / `BUSINESS_TIMEOUT` / `COLD_START` 等（**acceptance**）

### 2.4 PathRun 与观测去噪

- [x] PathRun 持久化（V013）；dashboard / `facts_search PATH_RUN` / `evidence_get pathrun:*`（**acceptance**）
- [x] `AUTH_GAP` 降级：主 findings 隐藏；`authGapFindingCount` vs `authGapSinkCount` 分口径（**acceptance**）
- [x] SQL meta 过滤：Redis/MySQL 握手 meta 不进 PathRun `sqlEvents`；仅真实截断 SQL（**acceptance**；语句级观测依赖 runtime 镜像重建）
- [x] `DynamicConfirmedGate` 忽略 `port=`/`sqlClass=` meta；H3 仍要求恶意语句文本（**acceptance**；live H3 命中样本尚少）

### 2.5 AUTH → DYNAMIC PoC 交接

- [x] AI 撰写结构化 `bypassPoCs` → 服务端 schema 闸门 → 注入 `AUTH_BYPASS_FEASIBILITY` → `sandbox_probe`（**acceptance** + live 管道 **partial**）
- [x] 鉴权面强制非空 PoC：re-ask → `RULE_GENERATED` 草案（`MISSING_AUTH` / `EMPTY_BEARER` / `ALG_NONE`）（**acceptance**）
- [x] DYNAMIC 非空可行性必须尝试探针：re-ask → 服务端 auto-enqueue 焦点探针（上限 3）（**acceptance**）
- [x] `MISSING_AUTH` 空 Authorization 合法；禁止假 Bearer；schema 允许 optional blank string（**acceptance**；同 scan live PathRun 需重启 CP 后再验）
- [x] `EntryRefResolver`：`entry:<scanEntryId>` / 唯一 `entry:METHOD:route`；失败回传 `failureCode`/`lifecycle`（**acceptance**）

### 2.6 GUI / 报告 / 工具契约

- [x] React/Vite 工作区首页、审计执行/过程/结果、模型服务、亮暗主题（**acceptance** + 本机冒烟）
- [x] 对话式审计过程：提示词 / 思考摘录 / 工具 / 输出（**live partial**）
- [x] Markdown 报告导出（`AI INFERENCE`，`skipHtml`）（**acceptance**）
- [x] 工具：`facts_search` / `evidence_get` / `plan_propose` / `sandbox_probe`（后两者带入口闸门）（**acceptance**）
- [x] PRE_ANALYSIS 注入有界 `SCAN_SUMMARY` / `ENTRY_SUMMARY`（**acceptance**）

**明确未宣称完成：** gVisor/Kata/OpenSandbox 生产门禁、`VERIFIED`、任意语言、完整参数绑定观测、SQL D2/D3 闭环、生产级 RBAC。

---

## 3. 进行中 / 部分完成

| 项 | 状态 | 说明 |
|----|------|------|
| JWT / 鉴权绕过动态确认 | **partial** | AUTH→DYNAMIC 管道与种子 PoC 已通；多数绕过仍停在 `DYNAMIC_SUSPECTED` / `AUTH_CHALLENGE`，未形成「过闸 + 业务命中」对照闭环 |
| Blade-Auth 与 Authorization 双通道 | **acceptance** | 计划/探针/工具独立双头；洪水合成默认只写 Authorization；live Auth-vs-Blade 轨差分待授权样例复验 |
| SQL D1 | **partial** | 语句级写入 PathRun 已修 meta 污染；无语句观测时允许空 SQL；live 深度依赖 runtime 镜像与业务真实发 SQL |
| SQL D2 / D3 | **D2 acceptance / D3 not done** | 投影侧 `SqlDiffProbe.compare` 已挂 PathRun 摘要（最高 `DYNAMIC_SUSPECTED`）；D3 实验卡未做；live D2 待复验 |
| `DYNAMIC_CONFIRMED`（H3） | **partial** | 门禁代码存在；缺少稳定 live 恶意片段命中样例与 GUI 主路径演示 |
| `parameterBound` / 入口命中深度 | **acceptance / live partial** | 投影/探针诚实填写 entryHit 与 unknown/false；Spring handler 可证 true；live baldex 对照待做 |
| 多身份轨洪水质量 | **partial** | 预算分配已修；不可用身份发 `IDENTITY_UNAVAILABLE` 未达路径；合成过闸率仍参差 |
| AUTH 绕过确认续跑（P3） | **acceptance** | 流水线二次 AUTH + `bypassConfirmation` 证据门禁（HYPOTHESIS / DYNAMIC_CONTRAST / INSUFFICIENT_EVIDENCE）；live 深度仍可加深 |
| WAR / 非 Boot JAR / CLASS 动态 | **partial** | CLASS 仅静态；WAR 动态非当前主验收对象 |
| 真实反编译隔离 Worker | **partial** | 契约存在，未捆绑/未作为默认路径 |
| OpenSandbox / gVisor / Kata | **not verified** | 不得宣称已验收；Windows 本地仅 `TRUSTED_DOCKER` |
| 多语言 / 非 JVM | **not started** | — |
| VERIFIED 重放门禁 | **not started** | 强化隔离 + 双次重放齐套前禁止开放 |

### M-A / M-B / M-C / M-D 状态映射

| 里程碑 | 原目标 | 当前状态 |
|--------|--------|----------|
| **M-A** PathRun 契约与呈现 | DTO、超时枚举、GUI 按入口×轨、`AUTH_GAP` 次级 | **完成（acceptance）**；焦点探针 + 入口×轨筛选已落地；实验卡/D3 仍可加深 |
| **M-B** 鉴权 / 合成身份 / 按轨观察 | AUTH 角色、合成身份、按轨执行、PoC 交接 | **大部分完成**（acceptance + live partial）；双 header 通道已通；JWT live 过闸对照仍薄 |
| **M-C** SQL D1–D3 + `DYNAMIC_CONFIRMED` | D1 挂 PathRun；D2 差分；D3 实验卡；H3 门禁 | **D1/D2 acceptance；D3 未做；H3 代码有、live 薄** |
| **M-D** Blade/Flowable 高价值形态 | JWT 默认证件、deploy/multipart 无破坏实验 | **部分启动依赖已兼容**；语义包级实验形态 **未完成** |

历史 M0–M6 条目：骨架/控制面/GUI/Agent/洪水等已并入上表「已完成」；未完成项转入 §4–§5，不再假装整章未开工。

---

## 4. 待完成开发项（按优先级）

### 4.0 推荐主脊：单入口人工 debug 闭环（P0）

**目标：** 选 1 个高价值 HTTP 入口，走完「像人 debug」的最小闭环，作为后续洪水与 AI 编排的验收锚点。

```text
选入口（静态 FACT）
  → AUTH 写出可执行 bypassPoC（或明确 infeasible）
  → sandbox_probe / 单轨实验执行
  → PathRun：HTTP 状态 + outcomeClass +（若有）真实 SQL
  → 参数是否绑定 / 是否触达 sink（可观测则写，否则 unknown）
  → 研判只依据 PathRun，不升 VERIFIED
  → GUI 单入口时间线可重放（finding replay / 同 plan）
```

**验收标准：**

- [x] 固定样例/API 焦点路径可产生含 HTTP 事件的 PathRun（**acceptance**；baldex 点名 live 对照仍建议复验）
- [x] AUTH conclusion 含非空 `bypassPoCs`（或零鉴权面 + `emptyReason`）（**acceptance**；含 RULE_GENERATED 种子）
- [x] DYNAMIC（或 auto-enqueue）对该入口至少 1 次 `sandbox_probe`，工具 fact 含 `lifecycle`/`stopReason`（**acceptance**）
- [x] 有 SQL 的入口：PathRun `sqlEvents` 无协议 meta；无 SQL 则显式空且不伪造成功注入（**acceptance**）
- [x] GUI/报告可展示该入口的请求摘要、轨、停止原因、MOCK 前置条件（**acceptance**；「只跑此入口」已接）
- [x] 全程无 `VERIFIED`；最高 `DYNAMIC_SUSPECTED` 或（若 H3 满足）`DYNAMIC_CONFIRMED`（服务端门禁）

**依赖：** runtime 镜像含最新 Agent；Control Plane 含 §60–§62 闸门；Docker 授权可用。  
**诚实边界：** 上表以自动化 acceptance 为准；完整 baldex live 单入口闭环仍建议在授权 Docker 下复验，不得标生产可用。

---

### 4.1 P0 — 堵住主脊缺口

**P0-01 单入口 debug GUI / API 表面**

- [x] 结果页以「入口 × 轨 × PathRun」为主视图；洪水摘要次之（**acceptance**）
- [x] 一键「只跑此入口」焦点任务：`POST /scans/{scanId}/entries/{entryId}/focus-probe`（**acceptance**；`EntryFocusProbeAcceptanceTest`）
- **验收：** 不打开全量 250 探针也能完成 §4.0 的 API/GUI 路径
- **依赖：** PathRun API 稳定；M-A 收尾

**P0-02 参数绑定与入口命中观测**

- [x] Agent/投影可靠填写 `entryHit` / `parameterBound`（或明确 `unknown` + 原因）
- [x] `REACHED_NO_BIND` 与业务 2xx 可区分
- **验收：** 合成 fixture 各 1 正 1 负（`EntryHitParameterBoundAcceptanceTest`）；baldex 至少 1 条 live 对照（待做）
- **依赖：** Agent 插桩点；PathRun schema
- **状态：** fixture 已通；未标 VERIFIED；live baldex 对照未完成

**P0-03 JWT 绕过动态对照（非仅静态/叙事）**

- [ ] ALG_NONE / 空 Bearer / MISSING_AUTH 等在 live PathRun 上形成轨对照（401 vs 过闸）（**live 待复验**）
- [x] Blade-Auth 与 Authorization 可分通道（**acceptance**；独立 TSV/头/工具字段）
- [x] 合成身份不可用时标 `IDENTITY_UNAVAILABLE`，不发空 token 假探针（**acceptance**）
- **验收：** 至少 1 个 technique 在授权样例上出现可解释的轨差分（live 仍开）；失败轨不再假成功
- **依赖：** P0-01；合成身份材料；§62 schema

**P0-04 SQL D1 打透 + D2 最小差分**

- [x] 语句级 PathRun SQL 过滤协议 meta（**acceptance**；live 深度仍依赖 runtime/业务 SQL）
- [x] 同任务良性 vs 元字符 SQL → `SqlDiffProbe.compare` 摘要，最高 `DYNAMIC_SUSPECTED`（**acceptance**）
- **验收：** acceptance fixture 已通；1 次 live 待做；meta 永不进 `sqlEvents`
- **依赖：** M-C；runtime 重建；H3 门禁保持服务端唯一升级口

**P0-05 AUTH P3 绕过确认续跑**

- [x] 洪水/焦点后流水线二次 `AUTH_ANALYSIS`（`AUTH_BYPASS_CONFIRM`）（**acceptance**）
- [x] 零动态证据禁止写「已绕过」：`bypassConfirmation` 门禁（**acceptance**）
- **验收：** 流水线事件可审计；conclusion 区分假设 vs 动态对照
- **依赖：** PathRun；AUTH conclusion schema

### 4.2 P1 — 加深路径实验与语义包

**P1-01 SQL D3 可重放实验卡**

- [ ] 身份轨 + 输入 + SQL 前后对比 + 停止条件齐套
- [ ] 默认仍不升 `VERIFIED`；满足 H3 才 `DYNAMIC_CONFIRMED`
- **验收：** 卡片可从 GUI 触发重放且结果稳定（MOCK 标注）
- **依赖：** P0-04

**P1-02 M-D Blade / Flowable 高价值实验形态**

- [ ] Blade JWT 默认证件 AnalysisPack（无破坏）
- [ ] Flowable deploy/multipart 有界实验（无内存马、无外连）
- **验收：** PDF 链可观测子集（合成身份过闸、deploy PathRun、SQL 分级）有文档化样例
- **依赖：** P0-03；启动依赖兼容（已有部分）

**P1-03 实验计划一等执行（AI 生成 → 闸门 → 按轨）**

- [ ] `plan_propose` 输出与洪水/焦点执行绑定；预算 T2+T3 可解释
- [ ] 超预算显式 `UNREACHED` / `PROBE_BUDGET`
- **验收：** baldex 高价值入口四轨，普通入口 UNAUTH+ADMIN 策略可在 dashboard 核对
- **依赖：** M-B；probe plan 持久化（已有元数据）

**P1-04 静态入口召回基准**

- [ ] 多 Spring / Blade 版本授权样本基准集；报告召回与漏报
- [ ] 组合注解 / 继承映射差距清单
- **验收：** 基准表入库；不得用 5/5 fixture 宣称生产召回
- **依赖：** 授权样本

**P1-05 攻击路径 AI 编排（证据约束）**

- [ ] PATH / TRIAGE 基于 PathRun 产出可执行下一步实验，而非综述 `AUTH_GAP`
- [ ] 组合链仅在共享资源/身份/文件证据上候选
- **验收：** 报告含「下一步验证步骤」且可被 `sandbox_probe` 消费
- **依赖：** §4.0 主脊稳定

### 4.3 P2 — 愿景扩展（不阻塞主脊）

**P2-01 WAR / 非 Boot 可运行画像**

- [ ] 用户提供完整运行画像后的动态路径；无画像则仅静态
- **验收：** 文档化失败模式；不静默宿主执行

**P2-02 强化隔离与 VERIFIED 门禁**

- [ ] gVisor/Kata 或等价 P0 逃逸套件通过后才开放 `VERIFIED`
- [ ] health 未通过保持 `DYNAMIC_DISABLED`
- **验收：** 见 TECHNICAL_ARCHITECTURE / 发布闸门；普通 Docker 永不标 VERIFIED

**P2-03 多语言 / 非 JVM 制品**

- [ ] Packager × FrameworkAdapter × AnalysisPack 扩展点落地第二语言包
- **验收：** 见 [`EXTENSIBLE_ANALYSIS.md`](EXTENSIBLE_ANALYSIS.md)；不破坏 JVM 主脊

**P2-04 底层真实形态统一视图**

- [ ] 入口+参数 → 归一化展示：HTTP 线、绑定参数、调用栈摘要、SQL AST/文本、文件/进程尝试
- [ ] 供人 debug 与 AI 共用同一证据模型
- **验收：** 单入口页一屏可读完一次实验
- **依赖：** P0-02、P0-04、P1-01

**P2-05 WebSocket / 非 HTTP 入口**

- [ ] 适配器接口可注册；MVP 可不计入覆盖率
- **验收：** 未知协议标 `UNREACHED` 而非误报 HTTP

---

## 5. 历史里程碑索引（M0–M6，状态摘要）

| 里程碑 | 原主题 | 状态 |
|--------|--------|------|
| M0 | 项目/制品/授权/Worker | **完成（acceptance）** — 单节点 SQLite，非分布式 |
| M1 | 制品接入与前置 AI | **完成（partial→acceptance）** — 注解切片已审计；真实召回基准仍 P1 |
| M2 | 沙箱与运行时观测 | **TRUSTED_DOCKER 完成（live）**；强化隔离 / VERIFIED **未完成** |
| M3 | 路径洪水与回溯 | **洪水完成（partial）**；状态快照回溯 / 覆盖率队列 **未完成** |
| M4 | AI 分析与全局串联 | **六角色 + PathRun 工具完成（partial）**；图谱/已验证链 **未完成** |
| M5 | GUI 与报告 | **主流程完成（acceptance）**；单入口 debug 主视图 **P0 待补** |
| M6 | 验收与硬化 | **进行中** — 个人本地样例回归有；恶意强化与指标门槛未封板 |

Definition of Done（仍适用）：自动化或可复现样例、结构化数据、审计日志、明确 stopReason、不绕过安全策略、可定位制品摘要；**另加**验证状态不得被模型或 UI 擅自提升。

---

## 6. 与愿景差距

| 维度 | 愿景 | 现状 | 差距要点 |
|------|------|------|----------|
| 语言 / 制品 | 不限语言与形态 | Spring Boot JAR 主路径；CLASS 仅静态 | 第二 Packager/Adapter 未开工；WAR 动态弱 |
| 入口覆盖 | 全部可探入口 | 注解召回 + 预算内多轨洪水 | 运行时注册/组合注解漏报；非 HTTP 未做 |
| Debug 深度 | 沙箱 = 人工 debug | 洪水 + 焦点 PoC + PathRun | 单入口主视图与参数绑定弱；D2/D3 薄 |
| AI PoC 环 | AI 推导路径并执行实验 | AUTH 写 PoC → 闸门 → DYNAMIC 探针（强制尝试） | JWT 动态确认不足；实验计划与研判未完全围绕 PathRun |
| 底层形态 | 入口+参数→真实 HTTP/SQL/调用 | Agent 事件 + 过滤后 SQL + MOCK 标注 | 统一「一次实验」视图未完成；实库/强化隔离未开 |
| 验证等级 | 证据升级至 VERIFIED | 最高常用 `DYNAMIC_SUSPECTED`；H3 稀有 | `VERIFIED` 与生产隔离门禁未开放 |

**当前最优推进顺序：** 做透 §4.0 单入口 debug 闭环 → P0 SQL/JWT 对照 → P1 实验卡与 Blade 语义包 → 再谈多语言与 VERIFIED。

---

## 7. 范围外（本版明确不做）

- [ ] 完整多租户 / 企业 SSO / 跨租户调度（已取消为当前承诺）
- [ ] 自动破坏性利用、内存马、外带真实生产网络
- [ ] LLM 单独出具「已验证」
- [ ] 100% 路径覆盖承诺
- [ ] 将 `TRUSTED_DOCKER` 宣传为恶意制品强化隔离
- [ ] 将 `DYNAMIC_CONFIRMED` 宣传为生产实库已证实

---

## 8. 衡量指标（校准用，非已达标声明）

在授权基准集上跟踪（须注明样例规模、框架版本、是否 MOCK、是否含模型）：

- 入口召回率；高价值入口四轨完成率
- 单入口 debug 闭环成功率（§4.0）
- PathRun 含真实 SQL 的比例（D1）；D2 差分可解释率
- `sandbox_probe` / AUTH PoC 尝试率（鉴权面非空时）
- 误报「已绕过 / 已注入」且无 PathRun 支撑的次数（目标 → 0）
- 单项目默认预算内完成率

首版门槛仍为建议值，未做跨环境达标认证：入口召回 ≥90%、已知 sink 到达 ≥80% 等——**达标前不得对外宣传已达成**。

---

## 9. 文档维护

- 实现与本文冲突时：先更新 [`PROJECT_MEMORY.md`](../PROJECT_MEMORY.md) 决策，再改本板与 [`PATH_EXPERIMENT_MODEL.md`](PATH_EXPERIMENT_MODEL.md) / [`AUDIT_FLOW.md`](AUDIT_FLOW.md)。
- 完成一项：勾选 checkbox，并标注验证等级（acceptance / live Docker / partial）。
- 未审计代码只可标「实验性」，不可写入「已完成」且暗示生产可用。

# 溯脉 · Veyrion MVP Backlog

> 更新：2026-07-30（文档瘦身）。**唯一实现状态来源**（开放项）；流程真相见 [CURRENT_SYSTEM](CURRENT_SYSTEM.md) / [AUDIT_PIPELINE_ASBUILT](AUDIT_PIPELINE_ASBUILT.md)。  
> 浓缩差距清单：[OPEN_GAPS.md](OPEN_GAPS.md)。  
> 历史已交付 checklist 与长篇审计流水账：**已删除**；以 git 与代码验收类为准。

## 0. 基线一页

| 项 | 现状 |
|----|------|
| 官方门禁 | `AcceptanceTestRunner` / `scripts/ci-gates.ps1`；数字以当次日志为准 |
| 静态 | Universe / IR / detectors / sink 主召回可用（fixture AUDITED 范围） |
| 动态 | TRUSTED_DOCKER 路径调试器：四姿态 + Sensor + PathTrace + IR2 重算 + 有界 OBS 回环；实战召回仍 PARTIAL |
| AI | 六角色 + 同扫描共享记忆 v1 + TRACE_PLAN_VS_ACTUAL |
| 验证 | SQL H3 → `DYNAMIC_CONFIRMED`（fixture）；`VERIFIED` **关闭** |
| 延后 | gVisor/Kata、生产 SSO（ADR-0003 PROPOSED）、Desktop/WAR 动态 |

`AUDITED` = 声明范围内合同/fixture/拒绝路径通过 ≠ 实战漏洞召回或恶意制品隔离。

## 1. 状态图例

| 状态 | 含义 |
|------|------|
| `AUDITED` | 声明范围已审 |
| `PARTIAL` | 主体在，路径或实战未闭合 |
| `SCAFFOLDING` | 骨架/门禁在，能力未开放 |
| `NOT STARTED` | 无可审计实现 |

## 2. 当前能力矩阵（摘要）

| 领域 | 状态 | 诚实边界 |
|------|------|----------|
| 制品导入 / 静态入口 / 调用图污点 / Universe / EG | `AUDITED`（fixture） | 非完整 IFDS/反射 |
| Provider SPI | `PARTIAL` | ArtifactNodes/MethodSummary/DynamicProbe 主流程未齐 |
| 多类 Detector / Hypothesis | `PARTIAL` | 实战召回与组链弱 |
| 多语言边界 / Control Plane / SQLite / AI Job 合同 | `AUDITED`（声明范围） | 非生产多进程/外网 Provider |
| 动态执行 / PathRun / PATH·TRIAGE probe | `PARTIAL` | World Pack、实战 JAR、参数观测 |
| GUI | `PARTIAL` | 合同有；手工视觉回归待补 |
| `DYNAMIC_CONFIRMED` | `AUDITED`（SQL H3 fixture） | 非 live 实库外推 |
| `VERIFIED` / gVisor / 生产 SSO | `SCAFFOLDING` | 明确延后 |

## 3. 开放工作（优先）

### P0 — 实战可用

| ID | 项 | 状态 | 要点 |
|----|-----|------|------|
| → OPEN P0-A | 实战 JAR 召回度量 | 开放 | 基准样例 + 保留集；勿用 fixture 外推 |
| → OPEN P0-B | 静态加深 | 开放 | wrapper/别名/`code_query` 切片（ADR-0002） |
| → OPEN P0-C/D | World Pack + TracePlan 编排完整度 | 开放 | PRE 前闭环、license/seed |
| → OPEN P0-E/F | effect 反馈与参数绑定观测 | 开放 | Sensor/投影 |
| → OPEN P0-G | 延迟组链硬状态机 | 开放 | 现为 prompt + FindingBindings |

细节与编号对照：[OPEN_GAPS.md](OPEN_GAPS.md)。

已落地、不再列 checklist 的近期能力（摘要）：pipeline CAS、AUTH 多轮、PATH/TRIAGE probe 闸门、三轨 Posture、GuardSurface FORCED、`compileFromStaticIr`、`TRACE_PLAN_VS_ACTUAL`、IR2 `AffectedDetectorRecompute`、OBS 回环（STATIC_ONLY + `VEYRION_AUDIT_OBS_LOOP_MAX`）、AUTH 无证据跳过、动态不可用静态续跑、ScanMemory v1、FindingBindings REPORT 分区。

### P1 — 合同与工程

| ID | 项 | 状态 |
|----|-----|------|
| P1-03 余量 | Provider ArtifactNodes / MethodSummary / DynamicProbe 主投影 | 开放 |
| P1-25 余量 | 手工视觉回归 | 开放 |
| P1-24 余量 | 外网 Provider 互操作 | 开放（需显式 live 旗标） |
| — | ControlPlane 编排大拆分 / 完整 DTO codegen | 开放 |

### P2 / 延后（勿当当前冲刺）

- `VERIFIED`、gVisor/Kata、逃逸套件  
- 生产 session/CSRF/SSO/多租户/保留  
- Gateway/WebFlux/RPC FORCED  
- 进程外重型静态引擎（新 ADR）  
- Desktop 安装包、WAR 动态、第二语言生产 Worker  

## 4. 明确不做

- 模型/前端直接操作 Docker、shell、宿主路径或外网  
- 沙箱不可用时宿主执行制品  
- 把 TRUSTED_DOCKER / MOCK / DYNAMIC_CONFIRMED 称为生产已验证  
- 为覆盖率跳过管理员/租户/业务前置  
- 宣称发现所有非常规漏洞  
- 在 PROJECT_MEMORY 写实现流水账  

## 5. 维护规则

- 完成项用验收类/命令证明；更新 [OPEN_GAPS](OPEN_GAPS.md) 删除对应开放行。  
- 稳定产品决策进 [PROJECT_MEMORY](../PROJECT_MEMORY.md)。  
- 历史长 checklist：**见 git 历史**，不在本文恢复数百行 `[x]`。  
- AI 实施遵守 [DEVELOPMENT_PLAYBOOK](DEVELOPMENT_PLAYBOOK.md) 与 [AI_TASK_TEMPLATE](AI_TASK_TEMPLATE.md)。

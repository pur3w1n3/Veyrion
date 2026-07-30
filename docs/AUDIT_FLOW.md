# 审计流程 — 产品意图模型（非 as-built）

> **本文不是代码执行说明书。**  
> 日常开发与排障请读：**[AUDIT_PIPELINE_ASBUILT.md](AUDIT_PIPELINE_ASBUILT.md)**。  
> 系统总览：**[CURRENT_SYSTEM.md](CURRENT_SYSTEM.md)**。  
> 开放差距：**[OPEN_GAPS.md](OPEN_GAPS.md)**。

## 角色

本文（及归档全文）描述**产品意图**：理想阶段语义、mermaid 主张与契约措辞。  
**不得**为「对齐代码」静默改写意图模型；若产品决策变更，由根 Agent / 产品所有者显式修订。

代码侧阶段名、跳过规则、OBS 回环与 TracePlan 编排位置以 as-built 为准。意图与实现差异见 as-built 文档「与 AUDIT_FLOW 产品模型差异」节。

## 意图全文

完整产品意图模型（含原 mermaid 与阶段契约）已归档：

→ **[archive/AUDIT_FLOW_PRODUCT_INTENT.md](archive/AUDIT_FLOW_PRODUCT_INTENT.md)**

## 相关

| 文档 | 用途 |
|------|------|
| [AUDIT_PIPELINE_ASBUILT.md](AUDIT_PIPELINE_ASBUILT.md) | 代码真实流水线 |
| [AI_ROLES.md](AI_ROLES.md) | 六角色 as-built |
| [PATH_EXPERIMENT_MODEL.md](PATH_EXPERIMENT_MODEL.md) | 姿态与验证门禁合同 |
| [adr/0004-sandbox-posture-vs-agent-bypass.md](adr/0004-sandbox-posture-vs-agent-bypass.md) | 沙箱 vs Agent 红线 |

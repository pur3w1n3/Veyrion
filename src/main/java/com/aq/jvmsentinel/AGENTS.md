# 后端实施约束

本文件适用于 `com.aq.jvmsentinel` 下的 Java 实现，并继承根目录规则。

## 必读

- [当前系统逻辑](../../../../../../docs/CURRENT_SYSTEM.md)（as-built 主入口）
- [技术架构](../../../../../../docs/TECHNICAL_ARCHITECTURE.md)
- [开发与 AI 实施手册](../../../../../../docs/DEVELOPMENT_PLAYBOOK.md)
- 涉及审计流水线时阅读 [AUDIT_PIPELINE_ASBUILT](../../../../../../docs/AUDIT_PIPELINE_ASBUILT.md)
- 涉及动态证据时阅读 [Path 实验模型](../../../../../../docs/PATH_EXPERIMENT_MODEL.md) 与 [AGENT_SENSOR_FLOW](../../../../../../docs/AGENT_SENSOR_FLOW.md)
- 涉及分析扩展时阅读 [可扩展分析](../../../../../../docs/EXTENSIBLE_ANALYSIS.md)

## 依赖与边界

- 保持 Java 17 兼容。新增/替换 HTTP 框架、数据库、队列、RPC、分析引擎或核心依赖需要已接受 ADR。
- 新领域逻辑进入 domain/application port，不继续堆入 `ControlPlaneServer`、`ApiDtos` 或 SQLite adapter。迁移采用小步兼容方式，不借功能任务大规模重写。
- Control Plane 不加载、初始化或宿主执行被测代码，不在进程内运行不可信反编译器和第三方 Analyzer 插件。
- 公共 domain/contract 不新增 JVM、Spring、HTTP 或 source/sink 必填假设。语言特有信息通过受限 namespaced extension 或语言 adapter 投影。
- 分析器和运行时只通过版本化合同提交结果，不能直接访问 Control Plane 存储、授权或验证状态。
- 现有耦合是待迁移基线，不是新增耦合的先例。

## 安全与数据

- 授权、策略、工具 allowlist、运行命令、镜像、挂载、网络、UID 和预算由服务端生成并在执行前复核。
- AI/前端/制品提供的字符串均视为不可信数据，不能成为权限、反射类名、SQL、路径或 shell 参数的隐式控制面。
- 所有异步写入绑定 project/artifact/scan/run/stage/task/probe attempt 的适用身份；迟到或错 scope 回调 fail-closed。
- Evidence 保留 provenance、schema、producer version、coverage 和 stop reason。部分输出、空投影和失败终态不能算成功。
- SQLite schema 只追加新迁移；不得改写已应用版本或以删库作为迁移策略。

## 验证

- 新状态机覆盖成功、失败、取消、超时、重试、迟到和非法转换。
- 新 contract 覆盖版本兼容、未知字段/kind、错误 scope、错误 digest、超预算和 malformed 输入。
- Analyzer/Detector 使用正例、近似负例、变异和保留集；动态能力同时测试拒绝路径和无宿主 fallback。
- 测试必须由官方命令实际执行非零断言；main 类存在不等于测试已运行。

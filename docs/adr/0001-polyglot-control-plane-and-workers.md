# ADR-0001: 稳定控制面与进程外多语言分析器

- Status: `ACCEPTED`
- Date: 2026-07-27
- Owners: root Agent / product owner
- Related: P0-14、P1-07、P1-08、P2 polyglot slice

## Context

当前产品使用 Java 17 Control Plane、SQLite、React/TypeScript/Vite GUI、ASM 静态索引和 JVM Agent 动态观察，优先支持 Spring Boot 可执行 JAR。该技术路线已形成可运行的本地垂直切片，但公共 DTO、控制面编排和 GUI 仍包含 JAR、Spring、HTTP、sink/taint 及 JVM Agent 假设。

未来希望支持更多语言和框架。直接在现有 Control Plane 中加入每种语言解析器，或为每种语言复制流水线，会造成：

- Control Plane 装载不可信或依赖冲突的语言工具链；
- 公共数据库和 API 被某一语言 AST/字节码模型绑死；
- 框架、漏洞族和运行时三种变化互相组合爆炸；
- GUI 产生大量语言/框架条件分支；
- 一个插件可能越过授权、证据和验证状态边界。

## Decision

1. 保留 React/TypeScript/Vite 作为 GUI，保留 Java 17 作为 Control Plane，保留 SQLite 作为个人单节点默认存储。
2. Control Plane 只负责授权、策略、编排、幂等、证据、状态机、持久化和公共投影，不承担所有语言的语义解析。
3. 建立语言无关的 Security IR、SecurityHypothesis、RuntimeObservation、CoverageGap、Analyzer 和 Runtime 协议。
4. 新语言通过进程外 `LanguageAnalyzer` 接入；新运行时通过独立 `RuntimeAdapter` 接入。
5. 扩展拆为 ArtifactPackager、LanguageAnalyzer、FrameworkAdapter、AnalysisPack、RuntimeAdapter 五条正交轴。
6. 第一阶段协议使用版本化 JSON Schema 与 JSONL/分块清单，沿用现有 Worker 合同经验；只有实测吞吐证明必要时才评估 Protobuf/gRPC。
7. 当前 JVM 解析、Spring 规则和 Java Agent 迁为默认 JVM 实现，通过兼容投影维持 `/api/v1` 和现有扫描只读语义。
8. 多语言迁移采用 strangler pattern：先抽合同和端口，再迁 JVM producer，最后接第二语言；禁止大爆炸重写。

## Alternatives

### 把所有分析器继续写在 Java 单体中

短期调用方便，但语言工具链、依赖、崩溃和信任域全部进入控制面，拒绝采用。

### 每种语言复制一套端到端服务

隔离较好，但会复制授权、流水线、证据、GUI 和验证逻辑，导致语义漂移，拒绝采用。

### 立即改写 Control Plane 或引入微服务平台

不能解决合同耦合，且会中断当前 JVM 垂直切片，拒绝采用。

### 在同进程使用 JNI、GraalVM Polyglot 或动态插件

会扩大崩溃、供应链和权限面，且使隔离与资源预算更难审计，不作为默认路线。

## Consequences

正面影响：

- 前后端技术栈可以继续复用；
- 语言解析器可独立升级、隔离和限额；
- 框架、漏洞族与运行时可分别扩展；
- 所有语言共享证据、假设、状态和报告语义；
- 第二语言成为对合同中立性的真实验证，而不是复制功能。

成本与限制：

- 需要设计 IR chunk、能力协商、终态、兼容和 coverage 合同；
- 跨进程传输增加序列化、暂存、摘要和调试成本；
- 某些语言特性不能被最低公分母 IR 完整表达，需要 namespaced extension；
- 在 JVM 默认实现迁入新端口前会存在一段兼容投影期。

## Security

- Analyzer 无动态执行、网络、验证状态或 Control Plane 数据库权限。
- RuntimeAdapter 无权接受模型/前端提供的任意命令、镜像、挂载、UID、网络或预算。
- Analyzer/Runtime 输出是不可信输入，必须校验 schema、scope、digest、budget 和终态后发布。
- namespaced extension 不能直接参与授权或状态提升。
- 插件不能直接写 Finding、FACT、权限或验证状态。

## Compatibility

- `/api/v1` 在迁移期保持兼容；新增中立资源优先新增端点或可选字段，不悄悄改变旧字段语义。
- 旧 Entry/Sink/Path/Finding 从 Security IR/Hypothesis 投影；旧扫描标 `LEGACY_INCOMPLETE` coverage。
- 已应用 SQLite migration 不修改，只追加新版本。
- Java package `com.aq.jvmsentinel` 和 Maven artifactId `jvm-security-verifier` 暂时保持兼容，但不得成为公共协议的语言限制。

## Migration

1. 固化 schema registry、兼容规则和 consumer contract。
2. 在当前 Java 工程内抽出 contract/domain/application/adapter 端口，不改变外部行为。
3. 让现有 JVM 分析输出中立 IR，并建立旧 DTO 等价投影。
4. 建立进程外 Analyzer 协议和 Test Analyzer。
5. 将 JVM Analyzer 移到该协议后，接入一个与 JVM 差异足够大的第二语言静态切片。
6. 为第二语言单独建立 RuntimeAdapter；未通过沙箱 attestation 前保持静态能力。
7. 根据实测规模决定是否替换 SQLite、JSON 传输或 HTTP server。

## Validation

- 同一 JVM fixture 在迁移前后 Entry/Sink/Path/Hypothesis 兼容投影等价。
- Test Analyzer 的越权 scope、错误 digest、超预算、未知 schema、部分 chunk 和迟到结果全部 fail-closed。
- 第二语言至少输出 ProgramNode、EntrySurface、TrustBoundary、SensitiveEffect、Guard 和 CoverageGap，并可被同一 GUI 查询。
- 同一语言的两个框架只更换 FrameworkAdapter；同一漏洞 detector 可在声明支持的多个语言 IR 上运行。
- 删除某 LanguageAnalyzer 不影响 Control Plane、其他语言数据和历史证据读取。


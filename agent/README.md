# Veyrion JVM Observation Agent

**Sensor Agent**：在授权 Docker 沙箱（`TRUSTED_DOCKER`）内对 Spring Boot 可执行 JAR 做字节码观测与有界 FORCED 短接，写出 `agent-events.jsonl`。

**不是**沙箱边界、控制面、AI 角色或漏洞判定器。

## 读哪里

| 文档 | 内容 |
|------|------|
| [AGENT_SENSOR_FLOW.md](../docs/AGENT_SENSOR_FLOW.md) | **流程主文档**（Attach → 姿态 → JSONL → PathTrace） |
| [AUDIT_PIPELINE_ASBUILT.md](../docs/AUDIT_PIPELINE_ASBUILT.md) | Agent 在审计阶段机中的位置（`DYNAMIC_OBSERVATION`） |
| [ADR-0004](../docs/adr/0004-sandbox-posture-vs-agent-bypass.md) | 红线：Sensor-only、禁止 Bypass Zoo |
| [OPEN_GAPS.md](../docs/OPEN_GAPS.md) | 仍开放差距 |

产品意图模型（非代码）：[AUDIT_FLOW.md](../docs/AUDIT_FLOW.md)。

## 是 / 不是

| 是 | 不是 |
|----|------|
| Java 17 `premain` / Byte Buddy 观测 | 沙箱 / 网络隔离 |
| Entry / MethodHop / Guard / Effect / Exit JSONL | 升 `DYNAMIC_CONFIRMED` / `VERIFIED` |
| Docker-only 已识别 guard DecisionShape | Bypass Zoo |
| 有界 JDBC/Redis/MySQL 替身 | 完整 World Pack / 真实业务状态 |

## 构建与测试

```bash
mvn -f agent/pom.xml package
# → agent/target/veyrion-jvm-agent-0.1.0-SNAPSHOT.jar
```

Acceptance（exec-maven-plugin）：`AgentAcceptanceTest`、`PathDebugSensorAcceptanceTest`、`ForcedReachabilityGuardAcceptanceTest` 等。

改 Agent 后须重建 runtime 镜像，例如：

```powershell
.\Start-Veyrion.ps1 -WithDockerRuntime -RebuildRuntimeImage
```

未加 `-RebuildRuntimeImage` 且已有 `sandbox-pack/.runtime/state.json` 时会跳过构建。

## 强制启动属性

| 属性 | 含义 |
|------|------|
| `veyrion.sandbox.traceDir.authorized=true` | 控制面授权写 trace |
| `veyrion.sandbox.traceDir` | 已存在、非符号链接目录 |

控制面常见注入：`veyrion.sandbox.docker=true`、`forcedGuardTypeNames`、`worldPack.dependencyMode`、`classPrefix`。容器内 jar：`/opt/veyrion/agent/veyrion-agent.jar`。

## ADR-0004 红线（摘要）

1. Agent = Sensor，禁止扩大 Bypass Zoo  
2. FORCED 仅 Docker + 服务端策略 + 已识别 guard；禁 sanitizer/业务不变量  
3. 强达标 `INSTRUMENTATION_REACHABILITY`  
4. 沙箱失败不得宿主回退  
5. AI/前端不能提供命令/镜像/挂载/网络/UID/预算  

## 关键类（目录）

```text
instrumentation/
  VeyrionAgent · AgentRuntime · AutomaticInstrumentation
  FrameworkBoundaryAdapter · EventWriter · ObservationTransformer
  mock/DependencyMockBootstrap · VeyrionMock*
agent/
  LoopbackHttpProbe · WaitHttpReady · ProcessListenPorts
```

控制面驱动：`ExternalArtifactTaskExecutor` · `ProbePlanService` · `GuardSurfaceCatalog` · `InstrumentationClassPrefix`。

更多参数、预算与 Advice 细节以源码为准；流程叙述不要在此重复维护第二份长文。

#!/usr/bin/env python3
"""Split ControlPlaneRouteHandlers into five domain handler classes + support."""
from __future__ import annotations

import pathlib
import re
import textwrap

HTTP = pathlib.Path(r"e:\ai\Veyrion\src\main\java\com\aq\jvmsentinel\control\http")
SRC = HTTP / "ControlPlaneRouteHandlers.monolith.bak"

SLICES: dict[str, list[str]] = {
    "OperatorProviderHttpHandlers": [
        "createProject", "sendProject", "listProjects", "updateProject", "deleteProject",
        "listOperators", "createOperator", "updateOperator",
        "listProviders", "createProvider", "updateProvider", "deleteProvider", "refreshProviderModels",
        "saveProviderBody",
        "registerArtifact", "initializeArtifactUpload", "appendArtifactUpload",
        "completeArtifactUpload", "cancelArtifactUpload", "listArtifacts", "listEntries",
        "listAudit", "sendHealth", "health",
        "requirePermission", "actor", "role", "operatorRole",
        "projectDto", "projectMap", "artifactDto", "artifactMap", "uploadSessionMap",
        "operatorMap", "providerMap", "inventoryMap",
    ],
    "AiJobHttpHandlers": [
        "listRoleAssignments", "sendRoleAssignment", "saveRoleAssignment", "deleteRoleAssignment",
        "listAiJobs", "createAiJob", "sendAiJob", "listAiJobEvents", "updateAiJob", "deleteAiJob",
        "outputLanguage", "roleBindingMap", "aiJobMap", "aiJobEventMap", "auditMap",
    ],
    "ScanBuildHttpHandlers": [
        "createOrReplayScan", "policyFrom", "buildScan", "buildFindings", "buildPaths", "buildChains",
    ],
    "ScanAuditHttpHandlers": [
        "listScans", "deleteScan", "startAudit", "retryAuditStage", "updateScan",
        "createScan", "sendScan", "dashboard",
        "pauseAuditPipeline", "cancelAuditPipeline", "resumeAuditPipeline", "enqueueAuditStage",
        "pipelineRunForScan",         "invalidateArmedPipelineForRetry", "requireRetryPrerequisite",
        "requireCompletedRole", "auditRunMap",
        "scanViewForPort", "attachPipelineProjection",
    ],
    "PathFindingsHttpHandlers": [
        "sendScanCoverage", "sendScanEvidenceGraph", "sendScanHypotheses", "sendScanAiMemory",
        "coverageMatrixForScan", "projectEvidenceGraphBase", "evidenceGraphForScan",
        "pathRunViewsForPort", "pathTracesByPathRunId", "mergedPathRunsForScan", "mergedPathRunsForTask",
        "dynamicPaths", "dynamicEvidence", "isAuthGapFinding", "mergeRuntimeLoadedClasses",
        "streamEvents", "listPaths", "sendPath", "listScanEvidence", "listScanFindings",
        "sendFinding", "sendEvidence", "listEvidence", "listChains",
        "enrichedFindingMap", "sqlExperimentCardMap", "experimentPlanMap",
    ],
    "SandboxProbeHttpHandlers": [
        "requestSandboxProbe", "probeAttemptId", "probeExecutionFailureFact", "isActiveLifecycle",
        "probeState", "refreshTaskSnapshot", "awaitDynamicTaskTerminal", "probeFact",
        "enqueueDynamicForPipeline", "dynamicBudgetForArtifact",
        "requireLocalArtifact", "resolveWorldPackDependencyMode",
        "restoreProbePlans", "restoredDynamicProbePlan", "persistedStringList", "probePlanHash",
        "buildProbePlan", "materializeAiPocAuth", "expandProbesByIdentityTracks",
        "hasExecutableMainClass",
    ],
    "DynamicWorkerHttpHandlers": [
        "createDynamicTask", "listDynamicTasks", "dynamicTaskWithDiagnostic", "dynamicTaskMap",
        "replayFinding", "findingReplayMap", "focusEntryProbe", "entryFocusProbeMap",
        "acceptExperimentPlan", "restoreExperimentPlans",
        "replaySqlExperimentCard",
    ],
}

SHARED = [
    "existingDurableIdempotency", "rememberDurableIdempotency", "releaseRetainedSandboxForScan", "latestScan",
    "findAcceptedPlan", "publishEvent",
    "mergeProviderBundleIntoScan", "ensureProviderEvidence", "entryKey", "stripPrefix",
    "sinkCategoryLabel", "sinkDeclaringClass", "entryBindingKey", "sinkBindingKey",
    "staticSinkSeverity", "prefixRefs", "simpleName", "envelope", "entryMap", "dependencyMap",
    "sinkMap", "evidenceMap", "findingMap", "hypothesisMaps", "pathStepMap", "pathMap",
    "pathRunMap", "correlationIdFromPathRun", "scanMap", "chainMap", "stringEnvelope",
]

CROSS_BY_SLICE: dict[str, list[tuple[str, str]]] = {
    "OperatorProviderHttpHandlers": [],
    "AiJobHttpHandlers": [(r"\bactor\(", "operators.actor("), (r"\brole\(", "operators.role(")],
    "ScanAuditHttpHandlers": [
        (r"\bactor\(", "operators.actor("),
        (r"\brequirePermission\(", "operators.requirePermission("),
        (r"\boutputLanguage\(", "aiJobs.outputLanguage("),
        (r"\benqueueDynamicForPipeline\(", "sandboxProbe.enqueueDynamicForPipeline("),
        (r"\baiJobMap\(", "aiJobs.aiJobMap("),
        (r"\bmergedPathRunsForScan\(", "pathFindings.mergedPathRunsForScan("),
        (r"\bpathTracesByPathRunId\(", "pathFindings.pathTracesByPathRunId("),
        (r"\bdynamicPaths\(", "pathFindings.dynamicPaths("),
        (r"\bisAuthGapFinding\(", "pathFindings.isAuthGapFinding("),
        (r"\bsqlExperimentCardMap\(", "pathFindings.sqlExperimentCardMap("),
        (r"\bexperimentPlanMap\(", "pathFindings.experimentPlanMap("),
        (r"\bcreateOrReplayScan\(", "scanBuild.createOrReplayScan("),
    ],
    "PathFindingsHttpHandlers": [],
    "SandboxProbeHttpHandlers": [
        (r"\bmergedPathRunsForTask\(", "pathFindings.mergedPathRunsForTask("),
    ],
    "DynamicWorkerHttpHandlers": [
        (r"\bactor\(", "operators.actor("),
        (r"\benqueueDynamicForPipeline\(", "sandboxProbe.enqueueDynamicForPipeline("),
        (r"\bmergedPathRunsForScan\(", "pathFindings.mergedPathRunsForScan("),
    ],
}

BUG_FIXES = [
    ("idempotentControlPlaneHandlerRecords.FindingReplays", "host.idempotentFindingReplays"),
    ("idempotentControlPlaneHandlerRecords.EntryFocusProbes", "host.idempotentEntryFocusProbes"),
    ("ensureIdempotencyCapacity(idempotentAuditRuns", "ensureIdempotencyCapacity(host.idempotentAuditRuns"),
    ("ensureIdempotencyCapacity(idempotentArtifacts", "ensureIdempotencyCapacity(host.idempotentArtifacts"),
    ("ensureIdempotencyCapacity(idempotentScans", "ensureIdempotencyCapacity(host.idempotentScans"),
    ("ControlPlaneHttpSupport.constantTimeEquals(workerToken,", "ControlPlaneHttpSupport.constantTimeEquals(host.workerToken,"),
    ("ControlPlaneHttpSupport.constantTimeEquals(mutationToken,", "ControlPlaneHttpSupport.constantTimeEquals(host.mutationToken,"),
    ("PayloadSchemaGuard.withSchemaVersion(\n                            JSON,", "PayloadSchemaGuard.withSchemaVersion(\n                            host.JSON,"),
    ("PayloadSchemaGuard.readIgnoringSchemaVersion(\n                                JSON,", "PayloadSchemaGuard.readIgnoringSchemaVersion(\n                                host.JSON,"),
    ("ScanMemoryBuilder.build(\n                store,", "ScanMemoryBuilder.build(\n                host.store,"),
    ("ControlPlaneRouteHandlers::sinkCategoryLabel", "ControlPlaneHandlerSupport::sinkCategoryLabel"),
    ("ControlPlaneRouteHandlers::sinkBindingKey", "ControlPlaneHandlerSupport::sinkBindingKey"),
    ("ControlPlaneRouteHandlers::entryBindingKey", "ControlPlaneHandlerSupport::entryBindingKey"),
]

COMMENT_TRANSLATIONS = [
    ("Local MVP exposes TRUSTED_DOCKER workers separately; VERIFIED stays closed.", "本地 MVP 单独暴露 TRUSTED_DOCKER worker；VERIFIED 保持关闭。"),
    ("Context is included even in v1 so consumers receive the required", "v1 仍包含 context，以便消费者收到所需的"),
    ("project, artifact, scan and task scope identifiers.", "project、artifact、scan 与 task 作用域标识。"),
    ("Thin P1-03 merge: provider-only entry/effect/guard contributions become scan DTOs when", "P1-03 薄合并：provider 独有的 entry/effect/guard 贡献在"),
    ("not already represented by PreAnalysis (compatibility retained).", "PreAnalysis 尚未表示时写入 scan DTO（保留兼容）。"),
    ("High-signal non-taint detector hyps (e.g. rememberMe cipher) → findings STATIC_INFERRED.", "高信号非污点 detector 假设（如 rememberMe 加密）→ findings STATIC_INFERRED。"),
    ("P1-02: persist authoritative Evidence Graph wire inside StaticFactSnapshot (schema v4).", "P1-02：在 StaticFactSnapshot 内持久化权威 Evidence Graph 线格式（schema v4）。"),
    ("Read-only coverage matrix projection; SUCCESS is never mapped to safe/secure.", "只读 coverage 矩阵投影；SUCCESS 永不映射为 safe/secure。"),
    ("Base Evidence Graph projection without analyzer overlays (P1-02 / P1-08).", "不含 analyzer 叠加层的基础 Evidence Graph 投影（P1-02 / P1-08）。"),
    ("Public query path goes through {@link #evidenceGraphQueryPort()}.", "公共查询路径经 {@link #evidenceGraphQueryPort()}。"),
    ("P1-02: prefer authoritative persisted graph from StaticFactSnapshot (schema v4).", "P1-02：优先使用 StaticFactSnapshot 中持久化的权威图（schema v4）。"),
    ("Read-only Evidence Graph including analyzer ProgramNode overlays (P1-08).", "含 analyzer ProgramNode 叠加层的只读 Evidence Graph（P1-08）。"),
    ("Operator-visible pipeline cursor projection (armed / paused / stopped).", "操作员可见的流水线游标投影（armed / paused / stopped）。"),
    ("PathRun maps for {@link PathRunQueryPort}; MOCK provenance remains visible.", "供 {@link PathRunQueryPort} 使用的 PathRun 映射；MOCK 来源仍可见。"),
    ("Stable attempt identity: {@code jobId + canonical toolCallId} (P0-03).", "稳定 attempt 标识：{@code jobId + canonical toolCallId}（P0-03）。"),
    ("Resolves only the immutable backend-managed copy for the process-local Docker worker.", "仅为进程内 Docker worker 解析不可变的后端托管副本。"),
    ("This method does not expose the path through HTTP.", "此方法不通过 HTTP 暴露路径。"),
    ("Hydrates in-memory probe plans from durable V026 payloads.", "从持久化 V026 载荷恢复内存 probe plan。"),
    ("Does not call {@code buildProbePlan} / identity harvest / posture re-persist on startup.", "启动时不调用 {@code buildProbePlan} / identity harvest / posture 重持久化。"),
    ("Incomplete or corrupt rows are skipped (fail closed per row) rather than silently rebuilt.", "不完整或损坏行按行 fail-closed 跳过，而非静默重建。"),
    ("Package-visible for restore acceptance tests.", "包可见，供恢复验收测试使用。"),
    ("Package-visible for acceptance tests of MISSING_AUTH / AI PoC materialization.", "包可见，供 MISSING_AUTH / AI PoC 物化验收测试使用。"),
    ("Package-visible facade for acceptance tests.", "包可见门面，供验收测试使用。"),
    ("Operator-facing single-entry debug probe. Reuses finding-replay / sandbox_probe gates:", "面向操作员的单入口调试 probe。复用 finding-replay / sandbox_probe 门禁："),
    ("operator auth, explicit authorized:true, Idempotency-Key, HTTP entry belonging to the scan,", "操作员鉴权、显式 authorized:true、Idempotency-Key、属于 scan 的 HTTP 入口，"),
    ("and DYNAMIC_TASK_BUSY when another dynamic task is active. Sandbox policy remains", "以及另一 dynamic task 活跃时的 DYNAMIC_TASK_BUSY。沙箱策略仍由"),
    ("server-owned; never upgrades to VERIFIED.", "服务端持有；永不升级为 VERIFIED。"),
    ("Accepts a server-gated {@link ExperimentPlan} from {@code plan_propose}. Process-local MVP", "接受来自 {@code plan_propose} 的服务端门禁 {@link ExperimentPlan}。进程内 MVP"),
    ("storage; binds later focus-probe / flood via experimentPlanId.", "存储；后续经 experimentPlanId 绑定 focus-probe / flood。"),
    ("D3 SQL experiment-card replay: reuses focus-probe gates with card benign/meta inputs.", "D3 SQL 实验卡 replay：以卡片 benign/meta 输入复用 focus-probe 门禁。"),
    ("Never upgrades to VERIFIED; dependencyMode remains MOCK-labeled via focus response.", "永不升级为 VERIFIED；dependencyMode 经 focus 响应保持 MOCK 标签。"),
    ("Re-arms the scan pipeline and re-enqueues one failed stage. Creates a new authorized", "重新 arm scan 流水线并重入队一个失败阶段。创建新的已授权"),
    ("AI job / dynamic task; never mutates the failed record into success.", "AI job / dynamic task；永不将失败记录变异为成功。"),
    ("Operator pipeline control: pause / resume / cancel the armed audit run for a scan.", "操作员流水线控制：pause / resume / cancel 某 scan 上已 arm 的 audit run。"),
    ("Pause persists {@code OPERATOR_PAUSED} without inventing verification status; resume", "Pause 持久化 {@code OPERATOR_PAUSED} 且不虚构 verification status；resume"),
    ("re-arms from the paused stage (same enqueue path as stage retry).", "从 paused 阶段重新 arm（与 stage retry 相同入队路径）。"),
    ("Shared enqueue used by stage retry and pause-resume. Creates a new authorized job/task", "stage retry 与 pause-resume 共用的入队。创建新的已授权 job/task"),
    ("and arms the pipeline; never mutates prior terminal records into success.", "并 arm 流水线；永不将先前终态记录变异为成功。"),
    ("Audit-history delete: cancel in-flight work for this scan, then hard-delete.", "审计历史删除：取消该 scan 在途工作，然后硬删除。"),
    ("Stuck QUEUED dynamic tasks (e.g. after restore skip / no Worker) must not 409 forever.", "卡住的 QUEUED dynamic task（如 restore 跳过 / 无 Worker）不得永久 409。"),
    ("Create-response projection via ScanQueryPort (hypotheses + coverage), not ad-hoc store reads.", "Create 响应经 ScanQueryPort 投影（hypotheses + coverage），非临时 store 读取。"),
    ("A mutation token authenticates the caller; it is not equivalent to", "mutation token 认证调用方；不等同于"),
    ("authorization to analyze a supplied artifact.  Require an explicit", "分析所供 artifact 的授权。要求显式"),
    ("per-scan consent flag so an accidentally omitted field fails closed.", "per-scan 同意标志，以便意外省略字段时 fail-closed。"),
    ("Prefer buildFocusedAiPocPlan: without technique/auth the shared plan still floods.", "优先 buildFocusedAiPocPlan：无 technique/auth 时共享 plan 仍会 flood。"),
    ("PathRun wire maps go through PathRunQueryPort (P1-08); DTOs still drive cards/gates.", "PathRun 线格式映射经 PathRunQueryPort（P1-08）；DTO 仍驱动 cards/gates。"),
    ("P0-20: do not promote scan status merely because dynamic paths/tasks exist.", "P0-20：不得仅因存在 dynamic paths/tasks 就提升 scan 状态。"),
    ("Pack matching without path still uses route heuristics.", "无 path 时 pack 匹配仍使用 route 启发式。"),
    ("Fail closed for a single corrupt row; other plans still restore.", "单行损坏 fail-closed；其他 plan 仍恢复。"),
    ("Expected job may already be terminal.", "预期 job 可能已终态。"),
    ("race with terminalization", "与终态化竞态"),
    ("already terminal", "已终态"),
    ("skip malformed persisted traces", "跳过格式错误的持久化 trace"),
    ("skip", "跳过"),
    ("Cursor already removed — onAiJobFinished is a no-op; avoid double disarm.", "Cursor 已移除 — onAiJobFinished 为 no-op；避免重复 disarm。"),
    ("Best-effort; scan teardown or foreign callbacks must not block pipeline CAS.", "尽力而为；scan 拆除或外部回调不得阻塞 pipeline CAS。"),
    ("WAR/CLASS never host-execute. Boot Main-Class is rechecked at worker registration.", "WAR/CLASS 永不宿主执行。Boot Main-Class 在 worker 注册时复检。"),
    ("Prefer common app package across scan entries so Service/Util/Repository hops", "优先 scan 入口间共用 app 包，以便 Service/Util/Repository 跳转"),
    ("are instrumented under FORCED (not only the primary entry's leaf .controller package).", "在 FORCED 下被插桩（不仅 primary entry 的 leaf .controller 包）。"),
    ("Resolve the single JVM World Pack dependency mode for a multi-probe Docker task.", "为多 probe Docker task 解析单一 JVM World Pack 依赖模式。"),
    ("Primary registration is always the exploration stage ({@code MOCK_CONTINUE});", "主注册始终为 exploration 阶段（{@code MOCK_CONTINUE}）；"),
    ("confirmation ({@code OBSERVE_FAIL}) is a later staged World Pack binding — never", "confirmation（{@code OBSERVE_FAIL}）为后续分阶段 World Pack 绑定 — 永不"),
    ("AI/frontend override and never DB-vendor branching.", "由 AI/前端覆盖，也永不按 DB 厂商分支。"),
    ("Attempt-scoped identity: jobId + canonical toolCallId (P0-03). Legacy job-only keys remain readable.", "Attempt 作用域标识：jobId + canonical toolCallId（P0-03）。旧 job-only 键仍可读。"),
    ("Do not bind a foreign in-flight task to the requested entry / attempt.", "勿将外来在途 task 绑定到请求的 entry / attempt。"),
    ("V011 stores bounded probe-input metadata (CHECK max_requests 1..8).", "V011 存储有界 probe-input 元数据（CHECK max_requests 1..8）。"),
    ("V026 also stores the compiled plan payload so startup restore skips harvest.", "V026 亦存储编译 plan 载荷，以便启动 restore 跳过 harvest。"),
    ("Re-check after metadata extraction as well as before it.  This", "元数据提取前后均复检。此"),
    ("closes the TOCTOU window where a file can be replaced while a", "关闭文件可在读取 ZIP/class 列表时被替换的 TOCTOU 窗口。"),
    ("ZIP/class listing is being read.", "（见上句）"),
    ("Parse and validate the consent flag before serving an idempotent", "在服务幂等"),
    ("replay.  Reusing a key must not turn an omitted authorization field", "replay 前解析并校验同意标志。复用 key 不得将省略的 authorization 字段"),
    ("into an implicit permission to analyze an artifact.", "变为分析 artifact 的隐式许可。"),
]

RELEASE_METHOD = """
    void releaseRetainedSandboxForScan(String scanId) {
        try {
            ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
            host.retainedSandboxRelease.release(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
        } catch (RuntimeException ignored) {
            // 尽力而为；scan 拆除或外部回调不得阻塞 pipeline CAS。
        }
    }
"""

IMPORTS_BY_SLICE = {
    "ControlPlaneHandlerSupport": textwrap.dedent("""
        import com.aq.jvmsentinel.control.ApiDtos;
        import com.aq.jvmsentinel.control.ControlPlaneStore;
        import com.aq.jvmsentinel.control.JsonCodec;
        import com.aq.jvmsentinel.control.StaticFactSnapshot;
        import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
        import com.aq.jvmsentinel.analysis.experiment.PathDebugWireHelper;
        import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
        import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
        import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
        import com.aq.jvmsentinel.domain.ir.EffectNode;
        import com.aq.jvmsentinel.domain.ir.EntryNode;
        import com.aq.jvmsentinel.domain.ir.GuardNode;
        import com.aq.jvmsentinel.model.ArtifactDescriptor;
        import com.aq.jvmsentinel.worker.TaskSnapshot;
        import com.aq.jvmsentinel.worker.WorkerTaskSpec;
        import com.aq.jvmsentinel.provider.ProviderContracts.ModelInventory;
        import com.aq.jvmsentinel.artifact.ArtifactUploadService;
        import com.aq.jvmsentinel.event.EventContext;
        import com.aq.jvmsentinel.event.EventFactory;
        import com.aq.jvmsentinel.event.IdempotencyKey;
        import com.aq.jvmsentinel.event.VersionedEvent;

        import java.time.Instant;
        import java.util.ArrayList;
        import java.util.LinkedHashMap;
        import java.util.LinkedHashSet;
        import java.util.List;
        import java.util.Locale;
        import java.util.Map;
        import java.util.Set;
    """).strip(),
    "OperatorProviderHttpHandlers": textwrap.dedent("""
        import com.aq.jvmsentinel.artifact.ArtifactDescriptor;
        import com.aq.jvmsentinel.artifact.ArtifactUploadService;
        import com.aq.jvmsentinel.artifact.ArtifactValidationException;
        import com.aq.jvmsentinel.control.ApiDtos;
        import com.aq.jvmsentinel.control.ControlPlaneStore;
        import com.aq.jvmsentinel.control.JsonCodec;
        import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
        import com.aq.jvmsentinel.model.ArtifactType;
        import com.aq.jvmsentinel.provider.AgentRole;
        import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
        import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
        import com.aq.jvmsentinel.provider.ProviderSecretCipher;
        import com.aq.jvmsentinel.security.auth.AuthContext;
        import com.aq.jvmsentinel.security.auth.Authorizer;
        import com.aq.jvmsentinel.security.auth.OperatorRole;
        import com.aq.jvmsentinel.security.auth.Permission;
        import com.sun.net.httpserver.HttpExchange;

        import java.io.IOException;
        import java.nio.file.Path;
        import java.time.Instant;
        import java.util.ArrayList;
        import java.util.LinkedHashMap;
        import java.util.List;
        import java.util.Locale;
        import java.util.Map;
        import java.util.Set;
    """).strip(),
    "AiJobHttpHandlers": textwrap.dedent("""
        import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
        import com.aq.jvmsentinel.control.ApiDtos;
        import com.aq.jvmsentinel.control.ControlPlaneHttpLimits;
        import com.aq.jvmsentinel.control.JsonCodec;
        import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
        import com.aq.jvmsentinel.provider.AgentRole;
        import com.aq.jvmsentinel.provider.AiOutputLanguage;
        import com.sun.net.httpserver.HttpExchange;

        import java.io.IOException;
        import java.time.Instant;
        import java.util.ArrayList;
        import java.util.LinkedHashMap;
        import java.util.List;
        import java.util.Map;
    """).strip(),
    "ScanBuildHttpHandlers": textwrap.dedent("""
        import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
        import com.aq.jvmsentinel.analysis.PreAnalysisInput;
        import com.aq.jvmsentinel.analysis.PreAnalysisResult;
        import com.aq.jvmsentinel.analysis.detector.DetectorContext;
        import com.aq.jvmsentinel.analysis.detector.DetectorRegistry;
        import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
        import com.aq.jvmsentinel.analysis.ir.EvidenceGraphProjector;
        import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
        import com.aq.jvmsentinel.analysis.spi.ProviderContext;
        import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
        import com.aq.jvmsentinel.analysis.spi.ProviderRegistry;
        import com.aq.jvmsentinel.analysis.universe.ArtifactUniverseBuilder;
        import com.aq.jvmsentinel.artifact.ArtifactValidationException;
        import com.aq.jvmsentinel.control.ApiDtos;
        import com.aq.jvmsentinel.control.ControlPlaneStore;
        import com.aq.jvmsentinel.control.JsonCodec;
        import com.aq.jvmsentinel.control.StaticFactSnapshot;
        import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords;
        import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
        import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
        import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
        import com.aq.jvmsentinel.domain.ir.IrNode;
        import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
        import com.aq.jvmsentinel.event.EventContext;
        import com.aq.jvmsentinel.model.ArtifactDescriptor;
        import com.aq.jvmsentinel.model.BytecodeFactIndex;
        import com.aq.jvmsentinel.model.DependencyAccess;
        import com.aq.jvmsentinel.model.Entrypoint;
        import com.aq.jvmsentinel.model.Evidence;
        import com.aq.jvmsentinel.model.PermissionRequirement;
        import com.aq.jvmsentinel.model.Sink;
        import com.aq.jvmsentinel.model.VerificationStatus;
        import com.aq.jvmsentinel.policy.DangerousActionMode;
        import com.aq.jvmsentinel.policy.NetworkMode;
        import com.aq.jvmsentinel.policy.PolicyValidator;
        import com.aq.jvmsentinel.policy.ScanPolicy;

        import java.io.IOException;
        import java.time.Instant;
        import java.util.ArrayList;
        import java.util.LinkedHashMap;
        import java.util.LinkedHashSet;
        import java.util.List;
        import java.util.Locale;
        import java.util.Map;
        import java.util.Optional;
        import java.util.Set;
        import java.util.UUID;
    """).strip(),
    "ScanAuditHttpHandlers": textwrap.dedent("""
        import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
        import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
        import com.aq.jvmsentinel.analysis.PreAnalysisInput;
        import com.aq.jvmsentinel.analysis.PreAnalysisResult;
        import com.aq.jvmsentinel.analysis.detector.DetectorContext;
        import com.aq.jvmsentinel.analysis.detector.DetectorRegistry;
        import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
        import com.aq.jvmsentinel.analysis.ir.EvidenceGraphProjector;
        import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
        import com.aq.jvmsentinel.analysis.spi.ProviderContext;
        import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
        import com.aq.jvmsentinel.analysis.spi.ProviderRegistry;
        import com.aq.jvmsentinel.analysis.universe.ArtifactUniverseBuilder;
        import com.aq.jvmsentinel.artifact.ArtifactValidationException;
        import com.aq.jvmsentinel.control.ApiDtos;
        import com.aq.jvmsentinel.control.ControlPlaneStore;
        import com.aq.jvmsentinel.control.JsonCodec;
        import com.aq.jvmsentinel.control.StaticFactSnapshot;
        import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords;
        import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
        import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
        import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
        import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
        import com.aq.jvmsentinel.domain.ir.IrNode;
        import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
        import com.aq.jvmsentinel.event.EventContext;
        import com.aq.jvmsentinel.event.EventFactory;
        import com.aq.jvmsentinel.event.IdempotencyKey;
        import com.aq.jvmsentinel.event.VersionedEvent;
        import com.aq.jvmsentinel.model.ArtifactDescriptor;
        import com.aq.jvmsentinel.model.BytecodeFactIndex;
        import com.aq.jvmsentinel.model.DependencyAccess;
        import com.aq.jvmsentinel.model.Entrypoint;
        import com.aq.jvmsentinel.model.Evidence;
        import com.aq.jvmsentinel.model.PermissionRequirement;
        import com.aq.jvmsentinel.model.Sink;
        import com.aq.jvmsentinel.model.VerificationStatus;
        import com.aq.jvmsentinel.policy.DangerousActionMode;
        import com.aq.jvmsentinel.policy.NetworkMode;
        import com.aq.jvmsentinel.policy.PolicyValidator;
        import com.aq.jvmsentinel.policy.ScanPolicy;
        import com.aq.jvmsentinel.provider.AgentRole;
        import com.aq.jvmsentinel.provider.AiOutputLanguage;
        import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
        import com.aq.jvmsentinel.worker.ProbeBudgetExplainer;
        import com.aq.jvmsentinel.worker.ResourceBudget;
        import com.aq.jvmsentinel.worker.TaskLifecycle;
        import com.aq.jvmsentinel.worker.TaskSnapshot;
        import com.sun.net.httpserver.HttpExchange;

        import java.io.IOException;
        import java.time.Instant;
        import java.util.ArrayList;
        import java.util.LinkedHashMap;
        import java.util.LinkedHashSet;
        import java.util.List;
        import java.util.Locale;
        import java.util.Map;
        import java.util.Objects;
        import java.util.Optional;
        import java.util.Set;
        import java.util.UUID;
    """).strip(),
    "PathFindingsHttpHandlers": textwrap.dedent("""
        import com.aq.jvmsentinel.analysis.FindingRanker;
        import com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector;
        import com.aq.jvmsentinel.analysis.experiment.PathDebugWireHelper;
        import com.aq.jvmsentinel.analysis.hypothesis.FindingRuntimeEnricher;
        import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
        import com.aq.jvmsentinel.analysis.ir.EvidenceGraphProjector;
        import com.aq.jvmsentinel.analysis.pack.AnalysisPack;
        import com.aq.jvmsentinel.analysis.pack.AnalysisPackRegistry;
        import com.aq.jvmsentinel.control.ApiDtos;
        import com.aq.jvmsentinel.control.ControlPlaneStore;
        import com.aq.jvmsentinel.control.JsonCodec;
        import com.aq.jvmsentinel.control.StaticFactSnapshot;
        import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
        import com.aq.jvmsentinel.control.service.DashboardService;
        import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
        import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
        import com.aq.jvmsentinel.model.ArtifactDescriptor;
        import com.aq.jvmsentinel.model.ExperimentPlan;
        import com.aq.jvmsentinel.model.IdentityTrack;
        import com.aq.jvmsentinel.model.SqlExperimentCard;
        import com.aq.jvmsentinel.worker.ProbeBudgetExplainer;
        import com.aq.jvmsentinel.worker.SqlExperimentCardBuilder;
        import com.aq.jvmsentinel.control.service.ProbePlanService;
        import com.sun.net.httpserver.HttpExchange;

        import java.io.IOException;
        import java.nio.file.Path;
        import java.util.ArrayList;
        import java.util.LinkedHashMap;
        import java.util.List;
        import java.util.Locale;
        import java.util.Map;
        import java.util.Objects;
        import java.util.Optional;
    """).strip(),
    "DynamicWorkerHttpHandlers": textwrap.dedent("""
        import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
        import com.aq.jvmsentinel.control.ApiDtos;
        import com.aq.jvmsentinel.control.ControlPlaneStore;
        import com.aq.jvmsentinel.control.JsonCodec;
        import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords;
        import com.aq.jvmsentinel.control.persistence.PayloadSchemaGuard;
        import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
        import com.aq.jvmsentinel.model.AuthBypassCandidate;
        import com.aq.jvmsentinel.model.AuthBypassTechnique;
        import com.aq.jvmsentinel.model.ExperimentPlan;
        import com.aq.jvmsentinel.worker.ExperimentPlanValidator;
        import com.aq.jvmsentinel.worker.SqlExperimentCardBuilder;
        import com.aq.jvmsentinel.worker.TaskSnapshot;
        import com.sun.net.httpserver.HttpExchange;

        import java.io.IOException;
        import java.time.Instant;
        import java.util.ArrayList;
        import java.util.LinkedHashMap;
        import java.util.List;
        import java.util.Locale;
        import java.util.Map;
        import java.util.Objects;
        import java.util.Optional;
        import java.util.Set;
    """).strip(),
    "SandboxProbeHttpHandlers": textwrap.dedent("""
        import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
        import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
        import com.aq.jvmsentinel.ai.tool.ToolDataSource;
        import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
        import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
        import com.aq.jvmsentinel.analysis.experiment.WorldPackPlanner;
        import com.aq.jvmsentinel.control.ApiDtos;
        import com.aq.jvmsentinel.control.ControlPlaneStore;
        import com.aq.jvmsentinel.control.JsonCodec;
        import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
        import com.aq.jvmsentinel.control.service.ProbePlanService;
        import com.aq.jvmsentinel.domain.pathdebug.WorldPackDependencyMode;
        import com.aq.jvmsentinel.domain.pathdebug.WorldPackExecutionStage;
        import com.aq.jvmsentinel.model.ArtifactDescriptor;
        import com.aq.jvmsentinel.model.ArtifactType;
        import com.aq.jvmsentinel.model.ExperimentPlan;
        import com.aq.jvmsentinel.model.RunProfile;
        import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
        import com.aq.jvmsentinel.worker.ResourceBudget;
        import com.aq.jvmsentinel.worker.TaskLifecycle;
        import com.aq.jvmsentinel.worker.TaskScope;
        import com.aq.jvmsentinel.worker.TaskSnapshot;
        import com.aq.jvmsentinel.worker.WorkerCapability;
        import com.aq.jvmsentinel.worker.WorkerControlPlaneApi;
        import com.aq.jvmsentinel.worker.WorkerTaskSpec;

        import java.io.IOException;
        import java.nio.file.Files;
        import java.nio.file.LinkOption;
        import java.nio.file.Path;
        import java.time.Duration;
        import java.time.Instant;
        import java.util.ArrayList;
        import java.util.LinkedHashMap;
        import java.util.List;
        import java.util.Locale;
        import java.util.Map;
        import java.util.Objects;
        import java.util.Optional;
        import java.util.Set;
        import java.util.UUID;
        import java.util.jar.JarFile;
    """).strip(),
}


def parse_methods(text: str) -> dict[str, str]:
    lines = text.splitlines()
    pat = re.compile(
        r"^    (?!\s)"  # 类级 4 空格缩进，排除方法体内的 8+ 空格行
        r"((?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|private|protected|static|synchronized)\s+)*)"
        r"(?:[\w<>,\s\[\]?\.]+\s+)?(\w+)\s*\("
    )
    KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "return", "throw", "new", "else", "try", "do"})
    indices: list[tuple[int, str]] = []
    for i, ln in enumerate(lines):
        if ln.strip().startswith("@FunctionalInterface"):
            break
        if ln.startswith("public final class ControlPlaneRouteHandlers"):
            continue
        m = pat.match(ln)
        if m and m.group(2) not in KEYWORDS:
            indices.append((i, m.group(2)))
    methods: dict[str, str] = {}
    for idx, (start, name) in enumerate(indices):
        if name == "ControlPlaneRouteHandlers":
            continue
        end = indices[idx + 1][0] if idx + 1 < len(indices) else len(lines)
        body = "\n".join(lines[start:end]).rstrip()
        if name in methods and name not in ("enqueueDynamicForPipeline", "buildProbePlan", "envelope",
                                            "materializeAiPocAuth", "requestSandboxProbe"):
            # keep first unless overload
            pass
        methods[name] = body
    # capture overload clusters manually by re-scanning
    overload_names = {"enqueueDynamicForPipeline", "buildProbePlan", "envelope",
                      "materializeAiPocAuth", "requestSandboxProbe", "coverageMatrixForScan"}
    for oname in overload_names:
        chunks = []
        for i, ln in enumerate(lines):
            if re.match(rf"^    (?!\s).*\b{oname}\s*\(", ln):
                # find end
                j = i + 1
                while j < len(lines):
                    if j < len(lines) - 1 and pat.match(lines[j]) and not lines[j].strip().startswith("//"):
                        nxt = pat.match(lines[j])
                        if nxt and lines[j].startswith("    ") and not lines[j].startswith("        "):
                            break
                    j += 1
                chunks.append("\n".join(lines[i:j]).rstrip())
        if chunks:
            methods[oname] = "\n\n".join(chunks)
    return methods


def transform_body(body: str, slice_name: str) -> str:
    for old, new in BUG_FIXES:
        body = body.replace(old, new)
    for pat, repl in CROSS_BY_SLICE.get(slice_name, []):
        body = re.sub(pat, repl, body)
    for eng, zh in COMMENT_TRANSLATIONS:
        body = body.replace(eng, zh)
    return body


def write_support(methods: dict[str, str]) -> None:
    bodies = [methods[n] for n in SHARED if n in methods]
    if "releaseRetainedSandboxForScan" not in methods:
        bodies.append(RELEASE_METHOD.strip())
    content = f"""package com.aq.jvmsentinel.control.http;

{IMPORTS_BY_SLICE["ControlPlaneHandlerSupport"]}

/** 处理器共享辅助（wire 映射、幂等、投影工具）。 */
class ControlPlaneHandlerSupport {{
    protected final ControlPlaneHandlerHost host;

    ControlPlaneHandlerSupport(ControlPlaneHandlerHost host) {{
        this.host = host;
    }}

{chr(10).join(bodies)}
}}
"""
    path = HTTP / "ControlPlaneHandlerSupport.java"
    path.write_text(content, encoding="utf-8", newline="\n")
    print(f"ControlPlaneHandlerSupport: {len(content.splitlines())} lines")


def write_slice(name: str, method_names: list[str], methods: dict[str, str]) -> None:
    bodies = []
    missing = []
    for mn in method_names:
        if mn in methods:
            bodies.append(transform_body(methods[mn], name))
        else:
            missing.append(mn)
    if missing:
        print(f"  {name} missing: {missing}")
    deps = ""
    ctor_params = "ControlPlaneHandlerHost host"
    fields = ""
    if name == "OperatorProviderHttpHandlers":
        pass
    elif name == "AiJobHttpHandlers":
        deps = "    private final OperatorProviderHttpHandlers operators;\n"
        ctor_params += ", OperatorProviderHttpHandlers operators"
        fields = "\n        this.operators = operators;"
    elif name == "ScanBuildHttpHandlers":
        pass
    elif name == "ScanAuditHttpHandlers":
        deps = textwrap.dedent("""
            private final OperatorProviderHttpHandlers operators;
            private final AiJobHttpHandlers aiJobs;
            private final SandboxProbeHttpHandlers sandboxProbe;
            private final PathFindingsHttpHandlers pathFindings;
            private final ScanBuildHttpHandlers scanBuild;
        """).strip() + "\n"
        ctor_params += ", OperatorProviderHttpHandlers operators, AiJobHttpHandlers aiJobs, SandboxProbeHttpHandlers sandboxProbe, PathFindingsHttpHandlers pathFindings, ScanBuildHttpHandlers scanBuild"
        fields = textwrap.dedent("""
            this.operators = operators;
            this.aiJobs = aiJobs;
            this.sandboxProbe = sandboxProbe;
            this.pathFindings = pathFindings;
            this.scanBuild = scanBuild;
        """).strip()
        fields = "\n        " + fields.replace("\n", "\n        ")
    elif name == "SandboxProbeHttpHandlers":
        deps = textwrap.dedent("""
            private final OperatorProviderHttpHandlers operators;
            private final PathFindingsHttpHandlers pathFindings;
        """).strip() + "\n"
        ctor_params += ", OperatorProviderHttpHandlers operators, PathFindingsHttpHandlers pathFindings"
        fields = "\n        this.operators = operators;\n        this.pathFindings = pathFindings;"
    elif name == "DynamicWorkerHttpHandlers":
        deps = textwrap.dedent("""
            private final OperatorProviderHttpHandlers operators;
            private final PathFindingsHttpHandlers pathFindings;
            private final SandboxProbeHttpHandlers sandboxProbe;
        """).strip() + "\n"
        ctor_params += ", OperatorProviderHttpHandlers operators, PathFindingsHttpHandlers pathFindings, SandboxProbeHttpHandlers sandboxProbe"
        fields = "\n        this.operators = operators;\n        this.pathFindings = pathFindings;\n        this.sandboxProbe = sandboxProbe;"

    content = f"""package com.aq.jvmsentinel.control.http;

{IMPORTS_BY_SLICE[name]}

/** 从 ControlPlaneRouteHandlers 拆出的 HTTP 处理器：{name.replace("HttpHandlers", "")} 域。 */
final class {name} extends ControlPlaneHandlerSupport {{
{deps}
    {name}({ctor_params}) {{
        super(host);{fields}
    }}

{chr(10).join(bodies)}
}}
"""
    path = HTTP / f"{name}.java"
    path.write_text(content, encoding="utf-8", newline="\n")
    print(f"{name}: {len(content.splitlines())} lines")


def write_facade() -> None:
    content = textwrap.dedent('''
        package com.aq.jvmsentinel.control.http;

        import com.aq.jvmsentinel.control.routing.ControlPlaneRouteActions;
        import com.aq.jvmsentinel.provider.AgentRole;
        import com.aq.jvmsentinel.security.auth.Permission;
        import com.sun.net.httpserver.HttpExchange;

        import java.io.IOException;
        import java.net.URI;

        /** 组合各域 HTTP 处理器，实现 {@link ControlPlaneRouteActions}。 */
        public final class ControlPlaneRouteHandlers implements ControlPlaneRouteActions {
            private final OperatorProviderHttpHandlers operators;
            private final AiJobHttpHandlers aiJobs;
            private final PathFindingsHttpHandlers pathFindings;
            private final SandboxProbeHttpHandlers sandboxProbe;
            private final DynamicWorkerHttpHandlers dynamicWorker;
            private final ScanBuildHttpHandlers scanBuild;
            private final ScanAuditHttpHandlers scanAudit;

            public ControlPlaneRouteHandlers(ControlPlaneHandlerHost host) {
                this.operators = new OperatorProviderHttpHandlers(host);
                this.aiJobs = new AiJobHttpHandlers(host, operators);
                this.pathFindings = new PathFindingsHttpHandlers(host);
                this.scanBuild = new ScanBuildHttpHandlers(host);
                this.sandboxProbe = new SandboxProbeHttpHandlers(host, operators, pathFindings);
                this.dynamicWorker = new DynamicWorkerHttpHandlers(host, operators, pathFindings, sandboxProbe);
                this.scanAudit = new ScanAuditHttpHandlers(host, operators, aiJobs, sandboxProbe, pathFindings, scanBuild);
            }

            @Override public void requirePermission(HttpExchange e, Permission p) { operators.requirePermission(e, p); }
            @Override public AgentRole role(String v) { return operators.role(v); }
            @Override public String query(URI u, String k) { return ControlPlaneHttpSupport.query(u, k); }
            @Override public void sendHealth(HttpExchange e) throws IOException { operators.sendHealth(e); }

            @Override public void createProject(HttpExchange e) throws IOException { operators.createProject(e); }
            @Override public void sendProject(HttpExchange e, String id) throws IOException { operators.sendProject(e, id); }
            @Override public void listProjects(HttpExchange e) throws IOException { operators.listProjects(e); }
            @Override public void updateProject(HttpExchange e, String id) throws IOException { operators.updateProject(e, id); }
            @Override public void deleteProject(HttpExchange e, String id) throws IOException { operators.deleteProject(e, id); }
            @Override public void registerArtifact(HttpExchange e, String id) throws IOException { operators.registerArtifact(e, id); }
            @Override public void initializeArtifactUpload(HttpExchange e, String id) throws IOException { operators.initializeArtifactUpload(e, id); }
            @Override public void appendArtifactUpload(HttpExchange e, String p, String u) throws IOException { operators.appendArtifactUpload(e, p, u); }
            @Override public void completeArtifactUpload(HttpExchange e, String p, String u) throws IOException { operators.completeArtifactUpload(e, p, u); }
            @Override public void cancelArtifactUpload(HttpExchange e, String p, String u) throws IOException { operators.cancelArtifactUpload(e, p, u); }
            @Override public void listArtifacts(HttpExchange e, String id) throws IOException { operators.listArtifacts(e, id); }
            @Override public void listEntries(HttpExchange e, String id) throws IOException { operators.listEntries(e, id); }
            @Override public void listOperators(HttpExchange e) throws IOException { operators.listOperators(e); }
            @Override public void createOperator(HttpExchange e) throws IOException { operators.createOperator(e); }
            @Override public void updateOperator(HttpExchange e, String id) throws IOException { operators.updateOperator(e, id); }
            @Override public void listProviders(HttpExchange e) throws IOException { operators.listProviders(e); }
            @Override public void createProvider(HttpExchange e) throws IOException { operators.createProvider(e); }
            @Override public void updateProvider(HttpExchange e, String id) throws IOException { operators.updateProvider(e, id); }
            @Override public void deleteProvider(HttpExchange e, String id) throws IOException { operators.deleteProvider(e, id); }
            @Override public void refreshProviderModels(HttpExchange e, String id) throws IOException { operators.refreshProviderModels(e, id); }
            @Override public void listRoleAssignments(HttpExchange e, String id) throws IOException { aiJobs.listRoleAssignments(e, id); }
            @Override public void sendRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { aiJobs.sendRoleAssignment(e, p, r); }
            @Override public void saveRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { aiJobs.saveRoleAssignment(e, p, r); }
            @Override public void deleteRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { aiJobs.deleteRoleAssignment(e, p, r); }
            @Override public void listAiJobs(HttpExchange e, String id) throws IOException { aiJobs.listAiJobs(e, id); }
            @Override public void createAiJob(HttpExchange e, String id) throws IOException { aiJobs.createAiJob(e, id); }
            @Override public void sendAiJob(HttpExchange e, String id) throws IOException { aiJobs.sendAiJob(e, id); }
            @Override public void listAiJobEvents(HttpExchange e, String id) throws IOException { aiJobs.listAiJobEvents(e, id); }
            @Override public void updateAiJob(HttpExchange e, String id) throws IOException { aiJobs.updateAiJob(e, id); }
            @Override public void deleteAiJob(HttpExchange e, String id) throws IOException { aiJobs.deleteAiJob(e, id); }
            @Override public void listAudit(HttpExchange e, String id) throws IOException { operators.listAudit(e, id); }
            @Override public void startAudit(HttpExchange e, String id) throws IOException { scanAudit.startAudit(e, id); }
            @Override public void retryAuditStage(HttpExchange e, String id) throws IOException { scanAudit.retryAuditStage(e, id); }
            @Override public void createScan(HttpExchange e, String id) throws IOException { scanAudit.createScan(e, id); }
            @Override public void listScans(HttpExchange e, String id) throws IOException { scanAudit.listScans(e, id); }
            @Override public void updateScan(HttpExchange e, String id) throws IOException { scanAudit.updateScan(e, id); }
            @Override public void deleteScan(HttpExchange e, String p, String s) throws IOException { scanAudit.deleteScan(e, p, s); }
            @Override public void sendScan(HttpExchange e, String id) throws IOException { scanAudit.sendScan(e, id); }
            @Override public void sendScanCoverage(HttpExchange e, String id) throws IOException { pathFindings.sendScanCoverage(e, id); }
            @Override public void sendScanEvidenceGraph(HttpExchange e, String id) throws IOException { pathFindings.sendScanEvidenceGraph(e, id); }
            @Override public void sendScanHypotheses(HttpExchange e, String id) throws IOException { pathFindings.sendScanHypotheses(e, id); }
            @Override public void sendScanAiMemory(HttpExchange e, String id) throws IOException { pathFindings.sendScanAiMemory(e, id); }
            @Override public void createDynamicTask(HttpExchange e, String id) throws IOException { dynamicWorker.createDynamicTask(e, id); }
            @Override public void listDynamicTasks(HttpExchange e, String id) throws IOException { dynamicWorker.listDynamicTasks(e, id); }
            @Override public void replayFinding(HttpExchange e, String id) throws IOException { dynamicWorker.replayFinding(e, id); }
            @Override public void focusEntryProbe(HttpExchange e, String s, String entry) throws IOException { dynamicWorker.focusEntryProbe(e, s, entry); }
            @Override public void replaySqlExperimentCard(HttpExchange e, String s, String c) throws IOException { dynamicWorker.replaySqlExperimentCard(e, s, c); }
            @Override public void streamEvents(HttpExchange e, String id) throws IOException { pathFindings.streamEvents(e, id); }
            @Override public void listPaths(HttpExchange e, String id) throws IOException { pathFindings.listPaths(e, id); }
            @Override public void sendPath(HttpExchange e, String s, String p) throws IOException { pathFindings.sendPath(e, s, p); }
            @Override public void listScanEvidence(HttpExchange e, String id) throws IOException { pathFindings.listScanEvidence(e, id); }
            @Override public void listScanFindings(HttpExchange e, String id) throws IOException { pathFindings.listScanFindings(e, id); }
            @Override public void sendFinding(HttpExchange e, String id) throws IOException { pathFindings.sendFinding(e, id); }
            @Override public void sendEvidence(HttpExchange e, String id) throws IOException { pathFindings.sendEvidence(e, id); }
            @Override public void listEvidence(HttpExchange e, String id) throws IOException { pathFindings.listEvidence(e, id); }
            @Override public void listChains(HttpExchange e) throws IOException { pathFindings.listChains(e); }
            @Override public void dashboard(HttpExchange e, String id) throws IOException { scanAudit.dashboard(e, id); }

            public java.util.Optional<com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord> requestSandboxProbe(
                    String scanId, com.aq.jvmsentinel.ai.tool.ToolExecutionContext.Scope scope, String principalId,
                    String jobId, String toolCallId, String entrypointRef, java.util.List<String> candidateInputs,
                    int maxRequests, String techniqueId, String authorizationHeader, String bladeAuthHeader,
                    String experimentPlanId) {
                return sandboxProbe.requestSandboxProbe(scanId, scope, principalId, jobId, toolCallId, entrypointRef,
                        candidateInputs, maxRequests, techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId);
            }

            public synchronized com.aq.jvmsentinel.worker.TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId) {
                return sandboxProbe.enqueueDynamicForPipeline(scanId, actorId);
            }

            public java.util.List<com.aq.jvmsentinel.control.ApiDtos.PathRunDto> mergedPathRunsForScan(
                    String projectId, String artifactDigest, String scanId) {
                return pathFindings.mergedPathRunsForScan(projectId, artifactDigest, scanId);
            }

            public synchronized void acceptExperimentPlan(String scanId, com.aq.jvmsentinel.model.ExperimentPlan plan) {
                dynamicWorker.acceptExperimentPlan(scanId, plan);
            }

            public java.util.Map<String, Object> scanViewForPort(String scanId) { return scanAudit.scanViewForPort(scanId); }
            public java.util.List<java.util.Map<String, Object>> pathRunViewsForPort(String scanId) { return pathFindings.pathRunViewsForPort(scanId); }
            public com.aq.jvmsentinel.domain.coverage.CoverageMatrix coverageMatrixForScan(String scanId) { return pathFindings.coverageMatrixForScan(scanId); }
            public com.aq.jvmsentinel.domain.coverage.CoverageMatrix coverageMatrixForScan(String scanId, com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector.SuppressMode m) { return pathFindings.coverageMatrixForScan(scanId, m); }
            public com.aq.jvmsentinel.domain.ir.EvidenceGraph projectEvidenceGraphBase(String scanId) { return pathFindings.projectEvidenceGraphBase(scanId); }
            public java.util.Map<String, Object> enrichedFindingMap(com.aq.jvmsentinel.control.ApiDtos.FindingDto dto) { return pathFindings.enrichedFindingMap(dto); }
            public com.aq.jvmsentinel.control.service.ProbePlanService.ProbePlan restoredDynamicProbePlan(String taskId) { return sandboxProbe.restoredDynamicProbePlan(taskId); }
            public com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor.ArtifactRegistration requireLocalArtifact(com.aq.jvmsentinel.worker.TaskScope scope) { return sandboxProbe.requireLocalArtifact(scope); }
            public java.util.Map<String, Object> health() { return operators.health(); }
            public void mergeRuntimeLoadedClasses(String scanId, java.util.List<String> names, String actorId) { pathFindings.mergeRuntimeLoadedClasses(scanId, names, actorId); }
            public void restoreProbePlans() { sandboxProbe.restoreProbePlans(); }
            public void restoreExperimentPlans() { dynamicWorker.restoreExperimentPlans(); }

            public static String probeAttemptId(String jobId, String toolCallId) { return SandboxProbeHttpHandlers.probeAttemptId(jobId, toolCallId); }
            public static com.aq.jvmsentinel.control.service.ProbePlanService.AuthMaterialized materializeAiPocAuth(
                    String techniqueId, String authorizationHeader, java.nio.file.Path artifactPath) {
                return SandboxProbeHttpHandlers.materializeAiPocAuth(techniqueId, authorizationHeader, artifactPath);
            }
            public static com.aq.jvmsentinel.control.service.ProbePlanService.AuthMaterialized materializeAiPocAuth(
                    String techniqueId, String authorizationHeader, String bladeAuthHeader, java.nio.file.Path artifactPath) {
                return SandboxProbeHttpHandlers.materializeAiPocAuth(techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
            }
            public static java.util.List<com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
                    java.nio.file.Path artifactPath, java.util.List<com.aq.jvmsentinel.control.ApiDtos.EntryDto> entries,
                    java.util.List<com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor.ProbeTarget> base, int max) {
                return SandboxProbeHttpHandlers.expandProbesByIdentityTracks(artifactPath, entries, base, max);
            }
        }
    ''').strip() + "\n"
    (HTTP / "ControlPlaneRouteHandlers.java").write_text(content, encoding="utf-8", newline="\n")
    print(f"ControlPlaneRouteHandlers: {len(content.splitlines())} lines")


def main() -> None:
    monolith = SRC.read_text(encoding="utf-8")
    (HTTP / "ControlPlaneRouteHandlers.monolith.bak").write_text(monolith, encoding="utf-8", newline="\n")
    methods = parse_methods(monolith)
    print(f"parsed {len(methods)} methods")
    write_support(methods)
    for slice_name, names in SLICES.items():
        write_slice(slice_name, names, methods)
    write_facade()


if __name__ == "__main__":
    main()

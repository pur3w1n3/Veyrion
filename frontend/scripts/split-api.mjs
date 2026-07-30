import fs from 'fs'
import path from 'path'

const root = path.resolve('e:/ai/Veyrion/frontend/src')
const apiDir = path.join(root, 'api')
const srcLines = fs.readFileSync(path.join(root, 'api.ts'), 'utf8').split(/\r?\n/)

const slice = (start, end) => srcLines.slice(start, end).join('\n')

const commentReplacements = [
  [/The only boundary between the GUI and the Java Control Plane\./g, 'GUI 与 Java 控制面之间的唯一边界。'],
  [/The UI deliberately consumes DTOs instead of Java records\.\s*Runtime\s*validation here is important: a malformed response must never be rendered\s*as a verified security result\.\s*The demo adapter uses the same UI-shaped\s*values, but is selected only when VITE_DEMO_MODE=true\./gs, '界面刻意消费 DTO 而非 Java record。此处运行时校验很重要：畸形响应绝不能被渲染为已验证的安全结果。演示适配器使用相同 UI 形态的值，但仅在 VITE_DEMO_MODE=true 时选用。'],
  [/Schema field constants \(Finding \/ Hypothesis \/ Coverage\) are generated from\s*contracts\/schemas via scripts\/generate-contract-types\.ps1 into\s*frontend\/src\/generated\/contracts\.ts — import those for drift checks; parsers\s*below remain the runtime wire validators\./gs, 'Schema 字段常量（Finding / Hypothesis / Coverage）由 scripts/generate-contract-types.ps1 从 contracts/schemas 生成到 frontend/src/generated/contracts.ts — 漂移检查请导入那些常量；下方 parser 仍是运行时 wire 校验器。'],
  [/\/\*\* Entry DTO plus the small projection consumed by the existing views\. \*\//g, '/** Entry DTO 及现有视图消费的小型投影。 */'],
  [/\/\*\* UI coverage is a percentage\. The Control Plane may omit it for a new entry\. \*\//g, '/** UI coverage 为百分比。控制面可能对新 entry 省略该字段。 */'],
  [/\/\*\* Attack-path step inside RootCauseAnalysis \(MVP-5\)\. \*\//g, '/** RootCauseAnalysis 内的攻击路径步骤（MVP-5）。 */'],
  [/\/\*\* Structured root-cause payload when a finding or verified row carries it\. \*\//g, '/** finding 或 verified 行携带时的结构化根因载荷。 */'],
  [/\/\*\* Optional TRIAGE counterevidence refs preserved through FindingDto wire copy\. \*\//g, '/** 可选 TRIAGE 反证 refs，经 FindingDto wire 拷贝保留。 */'],
  [/\/\*\* Known HypothesisFamily taxonomy \(open wire; unknown → UNKNOWN\)\. \*\//g, '/** 已知 HypothesisFamily 分类（开放 wire；未知 → UNKNOWN）。 */'],
  [/\/\*\* Normalize open-taxonomy family strings; unknown values degrade to UNKNOWN\. \*\//g, '/** 规范化开放分类 family 字符串；未知值降级为 UNKNOWN。 */'],
  [/\/\*\* P0-12 SecurityHypothesis wire DTO from dashboard\/scan\.hypotheses\[\]\. \*\//g, '/** P0-12 SecurityHypothesis wire DTO，来自 dashboard/scan.hypotheses[]。 */'],
  [/\/\*\* Raw wire family before normalize \(for unknown degradation display\)\. \*\//g, '/** normalize 前的原始 wire family（用于未知降级展示）。 */'],
  [/\/\*\* Present only if the API attaches RootCauseAnalysis \(MVP-5\); not on FindingDto today\. \*\//g, '/** 仅当 API 附加 RootCauseAnalysis（MVP-5）时存在；FindingDto 上暂无。 */'],
  [/\/\*\* Optional P0-12 SecurityHypothesis binding; absent on legacy findings\. \*\//g, '/** 可选 P0-12 SecurityHypothesis 绑定；旧版 finding 无此字段。 */'],
  [/\/\*\* FORCED\/COVERAGE PathRun refs attached at serve time; never elevates VERIFIED\. \*\//g, '/** 服务时附加的 FORCED/COVERAGE PathRun refs；永不提升为 VERIFIED。 */'],
  [/\/\*\* INSTRUMENTATION_REACHABILITY or SCAN_AUTH_POSTURE when PathRun materials attach\. \*\//g, '/** PathRun 材料附加时的 INSTRUMENTATION_REACHABILITY 或 SCAN_AUTH_POSTURE。 */'],
  [/\/\*\* CandidateRanker row from dashboard\.rankedSinks \(MVP-1\)\. \*\//g, '/** 来自 dashboard.rankedSinks 的 CandidateRanker 行（MVP-1）。 */'],
  [/\/\*\* LedgerDiff aggregate from dashboard\.ledgerDiff \(MVP-3\)\. \*\//g, '/** 来自 dashboard.ledgerDiff 的 LedgerDiff 聚合（MVP-3）。 */'],
  [/\/\*\* MVP-6 verified_findings scaffolding\. Dashboard currently returns \[\]\.\s*Parser accepts either finding-shaped rows or persistence-shaped fields\./gs, '/** MVP-6 verified_findings 脚手架。Dashboard 当前返回 []。Parser 接受 finding 形态行或持久化形态字段。'],
  [/\/\*\* Contrast ledger status strings \(not VerificationStatus\)\. \*\//g, '/** 对照账本状态字符串（非 VerificationStatus）。 */'],
  [/\/\*\* ExperimentPlan\.fuzzStrategyJson when exposed on the wire \(MVP-4\)\. \*\//g, '/** wire 暴露时的 ExperimentPlan.fuzzStrategyJson（MVP-4）。 */'],
  [/\/\*\* Alias accepted if the API uses fuzzStrategy \/ fuzz_strategy\. \*\//g, '/** API 使用 fuzzStrategy / fuzz_strategy 时可接受的别名。 */'],
  [/\/\*\* INITIAL focus vs REPLAY of an experiment card \/ idempotent retry\. \*\//g, '/** INITIAL focus 与 experiment card 重放 / 幂等重试。 */'],
  [/\/\*\* Demoted secondary finding rows omitted from findings\[\] \(not AUTH_GAP sink population\)\. \*\//g, '/** 从 findings[] 省略的降级次要 finding 行（非 AUTH_GAP sink 数量）。 */'],
  [/\/\*\* AUTH_GAP category sink signals in the scan \(often larger than authGapFindingCount\)\. \*\//g, '/** 扫描中 AUTH_GAP 类 sink 信号（常大于 authGapFindingCount）。 */'],
  [/\/\*\* First-class SecurityHypothesis rows \(P0-12\); authoritative for multi-family views\. \*\//g, '/** 一等 SecurityHypothesis 行（P0-12）；多 family 视图的权威来源。 */'],
  [/\/\*\* CandidateRanker top sinks \(MVP-1\); empty when unscanned\. \*\//g, '/** CandidateRanker 顶部 sink（MVP-1）；未扫描时为空。 */'],
  [/\/\*\* Multi-round contrast ledger delta \(MVP-3\)\. \*\//g, '/** 多轮对照账本增量（MVP-3）。 */'],
  [/\/\*\* MVP-6 gate scaffolding; currently always \[\] until VerifiedStatusGate opens\. \*\//g, '/** MVP-6 门禁脚手架；VerifiedStatusGate 开启前始终为 []。 */'],
  [/\/\*\* Server-provided dynamic PathRun counts when present; UI must not upgrade verification\. \*\//g, '/** 存在时由服务端提供的动态 PathRun 计数；UI 不得升级验证状态。 */'],
  [/\/\*\* Primary label for audit-target lists and selectors\. \*\//g, '/** 审计目标列表与选择器的主标签。 */'],
  [/\/\*\* Original upload\/path basename; preferred UI title over digest\/artifactId\. \*\//g, '/** 原始上传/路径 basename；UI 标题优先于 digest/artifactId。 */'],
  [/\/\*\* P0-13 Coverage Matrix \(read-only aggregation; SUCCESS ≠ safe\)\. \*\//g, '/** P0-13 Coverage Matrix（只读聚合；SUCCESS ≠ safe）。 */'],
  [/\/\*\* Known Evidence Graph node kinds; unknown kinds degrade without failing the page\. \*\//g, '/** 已知 Evidence Graph 节点 kind；未知 kind 降级且不致使页面失败。 */'],
  [/\/\*\* P1-02 \/ P1-08 Evidence Graph wire node \(open taxonomy \+ namespaced extensions\)\. \*\//g, '/** P1-02 / P1-08 Evidence Graph wire 节点（开放分类 + 命名空间 extensions）。 */'],
  [/\/\*\* Raw wire kind before normalize\. \*\//g, '/** normalize 前的原始 wire kind。 */'],
  [/\/\*\* Remaining open fields preserved for degraded display\. \*\//g, '/** 保留的其余开放字段，用于降级展示。 */'],
  [/\/\*\* Embedded when returned by create\/get scan \(P0-13\)\. \*\//g, '/** create/get scan 返回时内嵌（P0-13）。 */'],
  [/\/\*\* Armed audit pipeline cursor projection \(optional; absent on older servers\)\. \*\//g, '/** 已武装审计流水线游标投影（可选；旧服务端无）。 */'],
  [/\/\*\* Latest worker\/container step line for the audit timeline\. \*\//g, '/** 审计时间线最新 worker/容器步骤行。 */'],
  [/\/\*\* A local path understood by the Control Plane; the browser never reads it\. \*\//g, '/** 控制面可理解的本地路径；浏览器从不读取。 */'],
  [/\/\*\* Optional policy object is flattened into the Control Plane policy fields\. \*\//g, '/** 可选 policy 对象扁平化到控制面 policy 字段。 */'],
  [/\/\*\* HTTP probe ↔ JDBC join key when present \(P0-06\)\. \*\//g, '/** 存在时的 HTTP probe ↔ JDBC 关联键（P0-06）。 */'],
  [/\/\*\* method → hit branch indices from BRANCH_COVERAGE \(MVP-1\)\. \*\//g, '/** 来自 BRANCH_COVERAGE 的 method → hit 分支索引（MVP-1）。 */'],
  [/\/\*\* P0-21 path-debug extensions \(optional; absent on legacy runs\)\. \*\//g, '/** P0-21 path-debug 扩展（可选；旧 run 无）。 */'],
  [/\/\*\* Event scope is explicit even when the current envelope is schema v1\. \*\//g, '/** 即使当前 envelope 为 schema v1，事件 scope 也显式给出。 */'],
  [/\/\*\* Called after an event \(and after reconnect\) with the authoritative GET result\. \*\//g, '/** 事件后（及重连后）以权威 GET 结果回调。 */'],
  [/\/\/ JSON null and empty string are treated as absent optional fields\./g, '// JSON null 与空字符串视为缺失的可选字段。'],
  [/\/\/ JSON null and omitted fields are equivalent for optional arrays\./g, '// JSON null 与省略字段对可选数组等价。'],
  [/\/\/ Server-side traces occasionally use node names\. Keep the projection safe\./g, '// 服务端 trace 偶用节点名。保持投影安全。'],
  [/\/\/ ProbePlan IDENTITY_UNAVAILABLE steps; treat as a decision\/branch node\./g, '// ProbePlan IDENTITY_UNAVAILABLE 步骤；视为决策/分支节点。'],
  [/\/\/ Unknown kind must not fail the whole scan view \(frontend AGENTS: degrade\)\./g, '// 未知 kind 不得使整个扫描视图失败（frontend AGENTS：降级）。'],
  [/\/\/ Unknown state: prefer blocked over crashing the dashboard\./g, '// 未知 state：优先 blocked，避免 dashboard 崩溃。'],
  [/\/\/ Backend copyRootCause may emit "" when label was null\./g, '// 后端 copyRootCause 在 label 为 null 时可能输出 ""。'],
  [/\/\/ GET dashboard remains authoritative\. Prefer its compact projection when\s*\/\/ present, while retaining every rich path and using the first path only as\s*\/\/ a compatibility projection for views that still consume `path`\./gs, '// GET dashboard 仍为权威。存在时优先其紧凑投影，同时保留每条 rich path，并仅用第一条 path 作为仍消费 `path` 的视图的兼容投影。'],
  [/\/\/ PathTrace enrichment may live nested under pathTrace; prefer top-level, fall back to nested\./g, '// PathTrace enrichment 可能嵌套在 pathTrace 下；优先顶层，回退嵌套。'],
  [/\/\/ Legacy \/ no-trace rows omit these arrays; treat missing as empty\./g, '// 旧版/无 trace 行省略这些数组；缺失视为空。'],
  [/\/\/ The Java DTO calls the terminal timestamp completedAt\. Keep a stable\s*\/\/ updatedAt projection for the UI while accepting in-flight snapshots\./gs, '// Java DTO 将终态时间戳称为 completedAt。为 UI 保持稳定的 updatedAt 投影，同时接受进行中快照。'],
  [/\/\/ Demo mode must be explicit\. An unset flag now uses the real Control Plane\s*\/\/ adapter, preventing a production build from silently showing mock results\./gs, '// 演示模式必须显式开启。未设置标志时现使用真实控制面适配器，防止生产构建静默展示 mock 结果。'],
  [/\/\/ projectId is optional at construction: workspace home can list\/create projects\s*\/\/ before any workspace is selected\. Per-project calls still require an explicit id\./gs, '// 构造时 projectId 可选：工作区首页可在选定工作区前列表/创建项目。按项目调用仍需显式 id。'],
  [/\/\/ Keep native fetch detached from this API instance\. Calling a stored\s*\/\/ browser fetch as this\.fetchFn\(\.\.\.\) gives it the wrong receiver and\s*\/\/ Chrome rejects the call before any network request is sent\./gs, '// 保持原生 fetch 与本 API 实例分离。以 this.fetchFn(...) 调用存储的浏览器 fetch 会绑定错误 receiver，Chrome 会在任何网络请求发出前拒绝调用。'],
  [/\/\/ Only a small, allowlisted JSON shape from client\/validation failures is\s*\/\/ safe to render\. HTML, 5xx diagnostics, and arbitrary fields are never\s*\/\/ propagated\./gs, '// 仅客户端/校验失败的小规模白名单 JSON 形态可安全渲染。HTML、5xx 诊断与任意字段永不传播。'],
  [/\/\/ Keep the wire contract explicit\. Unknown values from a policy editor\s*\/\/ are not forwarded to the server and cannot widen its authorization or\s*\/\/ sandbox policy by accident\./gs, '// 保持 wire 合同显式。策略编辑器中的未知值不转发到服务端，不能意外扩大其授权或沙箱策略。'],
  [/\/\/ 204 No Content = success; 409 SCAN_ACTIVE and other errors throw \(never silent success\)\./g, '// 204 No Content = 成功；409 SCAN_ACTIVE 等错误抛异常（永不静默成功）。'],
  [/\/\/ EventSource is intentionally cookie\/credential based\. Browsers do not\s*\/\/ allow custom Authorization headers on EventSource; deployments should\s*\/\/ use an HttpOnly same-origin session for the SSE endpoint\./gs, '// EventSource 刻意基于 cookie/凭据。浏览器不允许 EventSource 自定义 Authorization 头；部署应对 SSE 端点使用 HttpOnly 同源 session。'],
  [/\/\/ EventSource may replay the last event after a reconnect, and a server\s*\/\/ can legally emit both a named event and a default message\. Keep a\s*\/\/ bounded idempotency window so the UI does not double-count findings\./gs, '// EventSource 重连后可能重放最后事件，服务端也可合法同时发出命名事件与默认 message。保持有界幂等窗口，避免 UI 重复计数 finding。'],
  [/\/\/ MessageEvent\.data is normally a string\. Accept an object for test\s*\/\/ adapters and browser polyfills without weakening validation\./gs, '// MessageEvent.data 通常为字符串。为测试适配器与浏览器 polyfill 接受 object，但不弱化校验。'],
  [/\/\/ The server closes finite replay streams after a terminal event;\s*\/\/ close the browser side as well so EventSource does not reconnect\s*\/\/ forever and re-fetch an already immutable scan\./gs, '// 服务端在终态事件后关闭有限重放流；浏览器侧也关闭，避免 EventSource 无限重连并重复拉取已不可变扫描。'],
  [/\/\/ EventSource automatically retries while OPEN\/CONNECTING\. Reconcile on\s*\/\/ each error so a terminal state is not hidden if the final event was lost\./gs, '// EventSource 在 OPEN/CONNECTING 时自动重试。每次 error 时对账，避免终态事件丢失后终态被隐藏。'],
  [/\/\/ Cancellation is best-effort and must not hide the original error\./g, '// 取消为尽力而为，不得掩盖原始错误。'],
  [/\/\/ The Java SSE writer keeps the scope in a nested `context` object while\s*\/\/ the public contract also permits flattened fields\. Accept both forms,\s*\/\/ but require the scoped values before handing an event to the UI\./gs, '// Java SSE writer 将 scope 放在嵌套 `context` 中，公开合同也允许扁平字段。两种形式均接受，但交给 UI 前必须有 scope 值。'],
  [/\/\/ Control plane emits schemaVersion 2 once promptZh\/promptEn are on the wire \(V010\+\)\./g, '// 控制面在 promptZh/promptEn 上 wire 后发出 schemaVersion 2（V010+）。'],
]

const zh = (text) => {
  let out = text
  for (const [pattern, replacement] of commentReplacements) {
    out = out.replace(pattern, replacement)
  }
  return out
}

const exportInternals = (body) => body.replace(/^const /gm, 'export const ')

fs.mkdirSync(apiDir, { recursive: true })

// types.ts
fs.writeFileSync(path.join(apiDir, 'types.ts'), zh(slice(0, 999)) + '\n')

// helpers.ts — wire 校验工具
const helpersImports = `import type {
  VerificationStatus,
  ProvenanceKind,
  WorkerCapability,
  OutputLanguage,
  EvidenceRef,
  PathStep,
} from './types'

`
fs.writeFileSync(
  path.join(apiDir, 'helpers.ts'),
  zh(helpersImports + exportInternals(slice(1000, 1113)) + '\n\n' + exportInternals(slice(1909, 1910)) + '\n\n' + exportInternals(slice(2059, 2065))) + '\n'
)

// pathRuns.ts — PathRun / 实验 / path-debug parser
const pathRunsImports = `import type {
  PathRunDto,
  SqlExperimentCardDto,
  ExperimentPlanDto,
  ProbeBudgetDto,
  AnalysisPackDto,
  PathDebugTrackSummary,
  PathDebugEntrySummary,
} from './types'
import {
  asText,
  optionalText,
  strictOptionalText,
  asFiniteNumber,
  asSafeInteger,
  asBoolean,
  schemaVersion,
  statusOf,
  listOfText,
  evidenceRefsOf,
  isRecord,
} from './helpers'

`
fs.writeFileSync(
  path.join(apiDir, 'pathRuns.ts'),
  zh(pathRunsImports + exportInternals(slice(1692, 1909))) + '\n'
)

// scans.ts — 扫描 / dashboard / finding parser
const scansImports = `import type {
  Entry,
  SecurityHypothesisDto,
  CoverageMatrixDto,
  EvidenceGraphNodeDto,
  EvidenceGraphDto,
  ScanHypothesesDto,
  Finding,
  FindingReplayDto,
  FocusEntryProbeDto,
  PathStep,
  PathTrace,
  DashboardSnapshot,
  EntryDto,
  ScanDto,
  DynamicTaskDto,
  EvidenceDto,
  ScanEvent,
  EvidenceNodeKind,
  RootCauseDto,
  RankedSinkDto,
  LedgerDiffDto,
  VerifiedFindingDto,
} from './types'
import { EVIDENCE_NODE_KINDS, normalizeHypothesisFamily } from './types'
import {
  asText,
  optionalText,
  strictOptionalText,
  asFiniteNumber,
  asSafeInteger,
  asBoolean,
  schemaVersion,
  statusOf,
  provenanceKindOf,
  workerCapabilityOf,
  listOfText,
  evidenceRefsOf,
  pathKind,
  pathState,
  isRecord,
  unwrap,
} from './helpers'
import {
  parseExperimentShape,
  parseSqlExperimentCard,
  parseExperimentPlan,
  parseProbeBudget,
  parseAnalysisPack,
  parsePathDebugTrackSummary,
  parsePathDebugEntrySummary,
  parsePathRun,
} from './pathRuns'

`
const scansBody = [
  exportInternals(slice(1148, 1264)),
  slice(1113, 1148),
  slice(1264, 1381),
  exportInternals(slice(1381, 1395)),
  slice(1395, 1692),
  slice(1954, 2059),
  slice(2292, 2328),
].join('\n\n')
fs.writeFileSync(path.join(apiDir, 'scans.ts'), zh(scansImports + scansBody) + '\n')

// projects.ts
const projectsImports = `import type { ProjectDto } from './types'
import { asText, optionalText, statusOf, evidenceRefsOf, isRecord, schemaVersion, unwrap } from './helpers'
import { parseArtifact } from './artifacts'

`
fs.writeFileSync(path.join(apiDir, 'projects.ts'), zh(projectsImports + slice(1911, 1928)) + '\n')

// artifacts.ts
const artifactsImports = `import type { ArtifactDto } from './types'
import { asText, optionalText, statusOf, evidenceRefsOf, isRecord, schemaVersion, asSafeInteger, asBoolean, unwrap } from './helpers'

`
fs.writeFileSync(path.join(apiDir, 'artifacts.ts'), zh(artifactsImports + slice(1928, 1954)) + '\n')

// providers.ts
const providersImports = `import type { ProviderDto, ProviderKind, ProviderModelInventoryDto, RoleAssignmentDto, AiRole } from './types'
import {
  asText,
  optionalText,
  strictOptionalText,
  asBoolean,
  schemaVersion,
  isRecord,
  unwrap,
  parseList,
} from './helpers'

`
fs.writeFileSync(path.join(apiDir, 'providers.ts'), zh(providersImports + slice(2065, 2147)) + '\n')

// ai.ts
const aiImports = `import type {
  AiJobDto,
  AiRole,
  AuditRunDto,
  AiJobEventDto,
  AiJobEventStatus,
  OutputLanguage,
} from './types'
import {
  asText,
  optionalText,
  asSafeInteger,
  schemaVersion,
  isRecord,
  outputLanguageOf,
  unwrap,
} from './helpers'
import { parseScan, parseDynamicTask } from './scans'

`
fs.writeFileSync(path.join(apiDir, 'ai.ts'), zh(aiImports + slice(2147, 2292)) + '\n')

// client.ts — HTTP 客户端与 fetch 工具
const clientImports = `import type {
  SentinelApi,
  ApiMode,
  DashboardSnapshot,
  RetryAuditStageRequest,
  RetryAuditStageResult,
  ProjectDto,
  CreateProjectRequest,
  UpdateProjectRequest,
  ArtifactDto,
  RegisterArtifactRequest,
  UploadProgressHandler,
  UploadTask,
  ScanDto,
  CreateScanRequest,
  StartAuditRequest,
  AuditRunDto,
  DynamicTaskDto,
  FindingReplayDto,
  FocusEntryProbeRequest,
  FocusEntryProbeDto,
  UpdateScanRequest,
  ProviderDto,
  SaveProviderRequest,
  ProviderModelInventoryDto,
  RoleAssignmentDto,
  AiRole,
  SaveRoleAssignmentRequest,
  AiJobDto,
  CreateAiJobRequest,
  AiJobEventDto,
  EntryDto,
  CoverageMatrixDto,
  EvidenceGraphDto,
  ScanHypothesesDto,
  EvidenceDto,
  ScanEvent,
  ScanEventType,
  SubscribeOptions,
} from './types'
import {
  ApiUnavailableError,
  ApiRequestError,
  UploadCancelledError,
  ARTIFACT_UPLOAD_CHUNK_BYTES,
  MAX_BROWSER_HASH_BYTES,
} from './types'
import {
  asText,
  asBoolean,
  asSafeInteger,
  schemaVersion,
  isRecord,
  unwrap,
  parseList,
} from './helpers'
import {
  parseDashboard,
  parseFindingReplay,
  parseFocusEntryProbe,
  parseEntries,
  parseScan,
  parseDynamicTask,
  parseCoverageMatrix,
  parseEvidenceGraph,
  parseScanHypotheses,
  parseEvidence,
  parseScanEvent,
} from './scans'
import { parseProject } from './projects'
import { parseArtifact } from './artifacts'
import { parseProvider, parseProviderModelInventory, parseRoleAssignment } from './providers'
import { parseAiJob, parseAuditRun, parseAiJobEvents } from './ai'

`
fs.writeFileSync(path.join(apiDir, 'client.ts'), zh(clientImports + slice(2379, 3077)) + '\n')

// mockClient.ts
const mockImports = `import type {
  SentinelApi,
  ApiMode,
  DashboardSnapshot,
  RetryAuditStageResult,
  ProjectDto,
  CreateProjectRequest,
  ArtifactDto,
  RegisterArtifactRequest,
  UploadTask,
  ScanDto,
  CreateScanRequest,
  StartAuditRequest,
  AuditRunDto,
  DynamicTaskDto,
  FindingReplayDto,
  FocusEntryProbeDto,
  ProviderDto,
  ProviderModelInventoryDto,
  RoleAssignmentDto,
  AiJobDto,
  AiJobEventDto,
  EntryDto,
  CoverageMatrixDto,
  EvidenceGraphDto,
  ScanHypothesesDto,
  EvidenceDto,
  ScanEvent,
  SubscribeOptions,
} from './types'
import { ApiUnavailableError } from './types'

`
const uploadTaskHelper = `
const uploadTask = (promise: Promise<ArtifactDto>, controller: AbortController): UploadTask =>
  Object.assign(promise, { cancel: () => controller.abort() })
`
fs.writeFileSync(
  path.join(apiDir, 'mockClient.ts'),
  zh(mockImports + slice(2328, 2379).replace(/^const demoSnapshot/, 'export const demoSnapshot') + uploadTaskHelper + slice(3077, 3349)) + '\n'
)

// api/index.ts
fs.writeFileSync(
  path.join(apiDir, 'index.ts'),
  `import { HttpSentinelApi } from './client'
import { MockSentinelApi } from './mockClient'

// 演示模式必须显式开启。未设置标志时现使用真实控制面适配器，防止生产构建静默展示 mock 结果。
const demoMode = import.meta.env.VITE_DEMO_MODE === 'true'
export const api: import('./types').SentinelApi = demoMode
  ? new MockSentinelApi()
  : new HttpSentinelApi(import.meta.env.VITE_API_BASE_URL || '/api/v1', import.meta.env.VITE_PROJECT_ID || '')
`
)

// api.ts barrel
fs.writeFileSync(
  path.join(root, 'api.ts'),
  `/**
 * GUI 与 Java 控制面之间的唯一边界（薄 re-export 桶）。
 *
 * 拆分模块见 \`./api/\`；本文件保持 \`from '../api'\` 等现有导入路径不变。
 */

export {
  FindingRequiredFields,
  SecurityHypothesisRequiredFields,
  CoverageMatrixRequiredFields,
} from './generated/contracts'

export * from './api/types'
export * from './api/scans'
export * from './api/projects'
export * from './api/artifacts'
export * from './api/providers'
export * from './api/ai'
export * from './api/client'
export * from './api/mockClient'
export { api } from './api/index'
`
)

console.log('Split complete')

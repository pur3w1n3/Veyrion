/**
 * GUI 与 Java 控制面之间的唯一边界。
 *
 * UI 刻意消费 DTO 而非 Java record。此处 runtime
 * 校验很重要：畸形响应永不得渲染为
 * 已验证的安全结果。Demo adapter 使用相同 UI 形状
 * 的值，但仅在 VITE_DEMO_MODE=true 时选中。
 *
 * Schema 字段常量（Finding / Hypothesis / Coverage）由
 * contracts/schemas 经 scripts/generate-contract-types.ps1 生成到
 * 自 frontend/src/generated/contracts.ts 导入用于 drift 检查；下方 parser
 * 仍为 runtime wire 校验器。
 */

export {
  FindingRequiredFields,
  SecurityHypothesisRequiredFields,
  CoverageMatrixRequiredFields,
} from '../generated/contracts'

export type VerificationStatus =
  | 'VERIFIED'
  | 'DYNAMIC_CONFIRMED'
  | 'DYNAMIC_SUSPECTED'
  | 'STATIC_INFERRED'
  | 'UNREACHED'
export type OutputLanguage = 'ZH_CN' | 'EN'

export type DependencyMode = 'MOCK' | 'REPLAY' | 'LIVE_DISABLED' | 'LIVE' | string
export type ProvenanceKind = 'FACT' | 'INFERENCE' | 'SIMULATION' | 'RUNTIME_OBSERVED' | 'AGENT_INSTRUMENTED' | 'APPLICATION_REPORTED'
export type WorkerCapability = 'STATIC_ONLY' | 'TRUSTED_DOCKER' | 'HARDENED_GVISOR' | 'HARDENED_KATA'

export type EvidenceRef = string | {
  evidenceId: string
  kind?: string
  summary?: string
}

export type EvidenceDto = {
  schemaVersion: number
  evidenceId: string
  projectId?: string
  artifactDigest?: string
  scanId?: string
  kind: string
  provenanceKind?: ProvenanceKind
  verificationStatus?: VerificationStatus
  source: string
  confidence: number
  summary: string
  observedAt?: string
  toolVersion?: string
  modelVersion?: string
  snapshotRef?: string
}

/** Entry DTO 及现有视图消费的小型投影。 */
export type Entry = {
  id: string
  route: string
  method: string
  module: string
  protocol: string
  precondition: string
  status: VerificationStatus
  verificationStatus?: VerificationStatus
  /** UI coverage 为百分比。控制面可能对新 entry 省略该字段。 */
  coverage: number
  schemaVersion?: number
  projectId?: string
  artifactDigest?: string
  scanId?: string
  declaringClass?: string
  parameters?: string[]
  preconditions?: string[]
  evidenceRefs?: EvidenceRef[]
  confidence?: number
}

export type EntryDto = Entry

/** RootCauseAnalysis 内的攻击路径步骤（MVP-5）。 */
export type AttackStepDto = {
  layer: string
  label: string
  evidenceRefs: string[]
}

/** finding 或 verified 行携带时的结构化根因载荷。 */
export type RootCauseDto = {
  attackPath: AttackStepDto[]
  rootCauseStatement: string
  affectedComponent?: string
  cweId?: string
  fixSuggestion?: string
  /** 可选 TRIAGE 反证 refs，经 FindingDto wire 拷贝保留。 */
  counterevidence?: string[]
}

/** 已知 HypothesisFamily 分类（开放 wire；未知 → UNKNOWN）。 */
export const HYPOTHESIS_FAMILIES = [
  'DATAFLOW',
  'GUARD_COVERAGE',
  'STATE',
  'TYPESTATE',
  'CONFIG',
  'DEPENDENCY',
  'CONCURRENCY',
  'COMPOSITION',
  'UNKNOWN'
] as const

export type HypothesisFamily = (typeof HYPOTHESIS_FAMILIES)[number]

/** 规范化开放分类 family 字符串；未知值降级为 UNKNOWN。 */
export const normalizeHypothesisFamily = (raw: unknown): HypothesisFamily => {
  if (typeof raw !== 'string' || raw.trim() === '') return 'UNKNOWN'
  const upper = raw.trim().toUpperCase()
  return (HYPOTHESIS_FAMILIES as readonly string[]).includes(upper)
    ? (upper as HypothesisFamily)
    : 'UNKNOWN'
}

/** P0-12 SecurityHypothesis wire DTO，来自 dashboard/scan.hypotheses[]。 */
export type SecurityHypothesisDto = {
  schemaVersion: number
  hypothesisId: string
  scanId: string
  securityProperty: string
  family: HypothesisFamily
  /** normalize 前的原始 wire family（用于未知降级展示）。 */
  familyRaw?: string
  lifecycle: string
  lifecycleRaw?: string
  detectorVersion: string
  supportingEvidenceRefs: string[]
  contradictingEvidenceRefs: string[]
  coverageGapRefs: string[]
  source?: string
  effect?: string
  extensions?: Record<string, unknown>
}

export type Finding = {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: VerificationStatus
  verificationStatus?: VerificationStatus
  entry: string
  sink: string
  dependency: string
  evidence: number
  evidenceCount?: number
  findingId?: string
  entrypointId?: string
  sinkId?: string
  dependencyMode?: DependencyMode
  schemaVersion?: number
  projectId?: string
  artifactDigest?: string
  scanId?: string
  evidenceRefs?: EvidenceRef[]
  confidence?: number
  /** 仅当 API 附加 RootCauseAnalysis（MVP-5）时存在；FindingDto 上暂无。 */
  rootCause?: RootCauseDto
  /** 可选 P0-12 SecurityHypothesis 绑定；旧版 finding 无此字段。 */
  hypothesisId?: string
  securityProperty?: string
  /** 服务时附加的 FORCED/COVERAGE PathRun refs；永不提升为 VERIFIED。 */
  pathRunRefs?: string[]
  /** PathRun 材料附加时的 INSTRUMENTATION_REACHABILITY 或 SCAN_AUTH_POSTURE。 */
  postureProvenance?: string
  postureKind?: string
}

/** 来自 dashboard.rankedSinks 的 CandidateRanker 行（MVP-1）。 */
export type RankedSinkDto = {
  sinkId: string
  rank: number
  score: number
  category: string
  symbol?: string
  rankReasons: string[]
}

/** 来自 dashboard.ledgerDiff 的 LedgerDiff 聚合（MVP-3）。 */
export type LedgerDiffDto = {
  newlyMatched: string[]
  regressions: string[]
  unchangedCount: number
  coverageDelta: number
  summary?: string
}

/**
 * MVP-6 脚手架 verified_findings；Dashboard 当前返回 []。
 * Parser 接受 finding 形行或 persistence 形字段。
 */
export type VerifiedFindingDto = {
  findingId: string
  scanId?: string
  title?: string
  entry?: string
  sink?: string
  severity?: Finding['severity']
  verificationStatus: VerificationStatus
  rootCause?: RootCauseDto
  replayEvidenceRefs?: EvidenceRef[]
  verifiedAt?: string
  attestationRef?: string
  evidenceRefs?: EvidenceRef[]
}

/** 对照账本状态字符串（非 VerificationStatus）。 */
export type ContrastStatus =
  | 'MATCHED'
  | 'PARTIAL'
  | 'STATIC_ONLY'
  | 'DYNAMIC_ONLY'
  | 'DYNAMIC_REACHED'
  | 'UNKNOWN'
  | string

export type FindingReplayDto = {
  schemaVersion: number
  projectId: string
  scanId: string
  findingId: string
  entrypointId: string
  taskId: string
  lifecycle: string
  verificationStatus: VerificationStatus
  dependencyMode: DependencyMode
  replayed: boolean
  requiredCapability?: WorkerCapability
  dynamicExecutionMode?: string
}

export type FocusEntryProbeRequest = {
  authorized: true
  techniqueId?: string
  authorizationHeader?: string
  bladeAuthHeader?: string
  candidateInputs?: string[]
  maxRequests?: number
  experimentPlanId?: string
}

export type SqlExperimentCardDto = {
  cardId: string
  scanId: string
  entrypointRef: string
  track: string
  experimentPlanId?: string
  benignInput: string
  metaInput: string
  sqlBefore: string
  sqlAfter: string
  structureInfluenced: boolean
  stopCondition: string
  dependencyMode: DependencyMode
  verificationStatus: VerificationStatus
  pathRunRefs: string[]
  evidenceRefs?: EvidenceRef[]
  replayable: boolean
}

export type ExperimentPlanDto = {
  planId: string
  entrypointRef: string
  track: string
  method: string
  contentType: string
  maxAttempts: number
  candidateInputs: string[]
  stopCondition: string
  packId?: string
  boundForExecution?: boolean
  serverGated?: boolean
  /** wire 暴露时的 ExperimentPlan.fuzzStrategyJson（MVP-4）。 */
  fuzzStrategyJson?: string
  /** API 使用 fuzzStrategy / fuzz_strategy 时可接受的别名。 */
  fuzzStrategy?: string
}

export type ProbeBudgetDto = {
  maxProbes: number
  plannedProbes: number
  unreachedEntries: number
  strategy: string
  entryTrackPlans: Array<Record<string, unknown>>
}

export type AnalysisPackDto = {
  packId: string
  destructive: boolean
  jwtSecretHint?: string
  templates: ExperimentPlanDto[]
}

export type FocusEntryProbeDto = {
  schemaVersion: number
  projectId: string
  scanId: string
  findingId?: string | null
  entrypointId: string
  taskId: string
  lifecycle: string
  verificationStatus: VerificationStatus
  dependencyMode: DependencyMode
  replayed: boolean
  /** INITIAL focus 与 experiment card 重放 / 幂等重试。 */
  attemptKind?: 'INITIAL' | 'REPLAY' | string
  experimentPlanId?: string
  requiredCapability?: WorkerCapability
  dynamicExecutionMode?: string
}

export type PathStep = {
  label: string
  detail: string
  kind: 'entry' | 'transform' | 'branch' | 'dependency' | 'sink'
  state: 'done' | 'active' | 'blocked'
  evidenceRefs?: EvidenceRef[]
  verificationStatus?: VerificationStatus
  provenanceKind?: ProvenanceKind
  eventType?: string
  sequence?: number
}

export type PathTrace = {
  pathId: string
  entrypointId: string
  verificationStatus: VerificationStatus
  dependencyMode: DependencyMode
  stopReason: string
  preconditions: string[]
  steps: PathStep[]
  evidenceRefs?: EvidenceRef[]
  requiredCapability?: WorkerCapability
  taskId?: string
  dynamicExecutionMode?: string
}

export type PathDebugTrackSummary = {
  track?: string
  postureKind?: string
  postureProvenance?: string
  exitReason?: string
  lastBusinessHop?: string
  effectRefs?: string[]
  forcedGuardRefs?: string[]
  worldPackId?: string
  authRequirement?: string
  httpStatus?: number
  verificationStatus?: VerificationStatus
  legacyIncomplete?: boolean
  parameterFlow?: PathTraceParameterFlowStep[]
}

export type PathDebugEntrySummary = {
  entryId: string
  route: string
  tracks: PathDebugTrackSummary[]
}

export type DashboardSnapshot = {
  schemaVersion?: number
  projectId?: string
  artifactDigest?: string
  scanId?: string
  verificationStatus?: VerificationStatus
  dependencyMode?: DependencyMode
  evidenceRefs?: EvidenceRef[]
  entries: Entry[]
  findings: Finding[]
  /** 从 findings[] 省略的降级次要 finding 行（非 AUTH_GAP sink 数量）。 */
  authGapFindingCount?: number
  /** 扫描中 AUTH_GAP 类 sink 信号（常大于 authGapFindingCount）。 */
  authGapSinkCount?: number
  /** 一等 SecurityHypothesis 行（P0-12）；多 family 视图的权威来源。 */
  hypotheses?: SecurityHypothesisDto[]
  path: PathStep[]
  paths: PathTrace[]
  pathRuns: PathRunDto[]
  pathDebugSummaries?: PathDebugEntrySummary[]
  sqlExperimentCards?: SqlExperimentCardDto[]
  experimentPlans?: ExperimentPlanDto[]
  experimentShapes?: ExperimentShapeDto[]
  analysisPacks?: AnalysisPackDto[]
  probeBudget?: ProbeBudgetDto
  /** CandidateRanker 顶部 sink（MVP-1）；未扫描时为空。 */
  rankedSinks?: RankedSinkDto[]
  /** 多轮对照账本增量（MVP-3）。 */
  ledgerDiff?: LedgerDiffDto
  /** MVP-6 门禁脚手架；VerifiedStatusGate 开启前始终为 []。 */
  verifiedFindings?: VerifiedFindingDto[]
  contrastSnapshotId?: string
  contrastRoundIndex?: number
  /** 存在时由服务端提供的动态 PathRun 计数；UI 不得升级验证状态。 */
  dynamicSupportedPathRuns?: number
  dynamicFailedPathRuns?: number
}

export type ExperimentShapeDto = {
  pathRunId: string
  entrypointRef: string
  track: string
  httpLine: string
  httpStatus: number
  entryHit?: boolean | null
  parameterBound?: boolean | null
  sqlTexts: string[]
  stopReason: string
  outcomeClass: string
  dependencyMode: DependencyMode
  verificationStatus: VerificationStatus
  evidenceRefs?: EvidenceRef[]
}

export type ProjectDto = {
  schemaVersion: number
  projectId: string
  name: string
  createdAt: string
  verificationStatus?: VerificationStatus
  dependencyMode?: DependencyMode
  evidenceRefs?: EvidenceRef[]
  artifacts?: ArtifactDto[]
}
export type Project = ProjectDto

export type ArtifactType = 'JAR' | 'WAR' | 'CLASS' | string

export type ArtifactDto = {
  schemaVersion: number
  artifactId: string
  type: ArtifactType
  artifactType?: ArtifactType
  artifactDigest: string
  sizeBytes: number
  staticOnly: boolean
  verificationStatus: VerificationStatus
  dependencyMode?: DependencyMode
  evidenceRefs?: EvidenceRef[]
  projectId?: string
  registeredAt?: string
  /** 原始上传/路径 basename；UI 标题优先于 digest/artifactId。 */
  originalFileName?: string
  fileName?: string
  displayName?: string
}

/** 审计目标列表与选择器的主标签。 */
export const artifactLabel = (artifact: Pick<ArtifactDto, 'type' | 'artifactId' | 'originalFileName' | 'fileName' | 'displayName'>): string => {
  const name = artifact.displayName
    ?? artifact.originalFileName
    ?? artifact.fileName
    ?? artifact.artifactId
  return `${artifact.type} · ${name}`
}
export type Artifact = ArtifactDto

/** P0-13 Coverage Matrix（只读聚合；SUCCESS ≠ safe）。 */
export type CoverageMatrixDto = {
  schemaVersion: number
  scanId: string
  artifactUniverseSummary: {
    classCount: number
    methodCount: number
    fieldCount: number
    dependencyCount: number
    incomplete: boolean
    note: string
  }
  entryFamilies: Array<{ name: string; count: number }>
  callResolution: {
    DIRECT: number
    CHA: number
    UNRESOLVED: number
    unresolvedIsGap: true
  }
  detectors: Array<{
    family: string
    detectorVersion: string
    signals: number
    countedAsCovered: boolean
    note: string
  }>
  dynamicExperiments: {
    pathRunCount: number
    effectiveAttemptCount: number
    unreachedCount: number
    stopReasonSamples: string[]
  }
  stopReasons: Array<{ name: string; count: number }>
  gaps: {
    unknown: number
    unresolved: number
    truncated: number
    unreached: number
    total: number
    countedAsCovered: false
  }
  honestyFlags: {
    neverTreatSuccessAsSafe: true
    gapsNeverCountAsCovered: true
    scanSuccessMeans: 'analysis_finished_not_safe'
  }
  checksum: string
}

/** 已知 Evidence Graph 节点 kind；未知 kind 降级且不致使页面失败。 */
export const EVIDENCE_NODE_KINDS = [
  'PROGRAM',
  'ENTRY',
  'TRUST_BOUNDARY',
  'EFFECT',
  'GUARD',
  'SANITIZER',
  'STATE',
  'RESOURCE',
  'RUNTIME_OBSERVATION'
] as const
export type EvidenceNodeKind = (typeof EVIDENCE_NODE_KINDS)[number] | 'UNKNOWN'

/** P1-02 / P1-08 Evidence Graph wire 节点（开放分类 + 命名空间 extensions）。 */
export type EvidenceGraphNodeDto = {
  id: string
  kind: EvidenceNodeKind
  /** normalize 前的原始 wire kind。 */
  kindRaw?: string
  language?: string
  symbol?: string
  location?: string
  elementKind?: string
  protocol?: string
  evidenceRefs: string[]
  provenanceKind: string
  verificationStatus?: VerificationStatus
  extensions?: Record<string, unknown>
  /** 保留的其余开放字段，用于降级展示。 */
  extras?: Record<string, unknown>
}

export type EvidenceGraphEdgeDto = {
  id: string
  kind: string
  fromId: string
  toId: string
  evidenceRefs: string[]
  provenanceKind?: string
}

export type EvidenceGraphDto = {
  schemaVersion: number
  scanId: string
  nodes: EvidenceGraphNodeDto[]
  edges: EvidenceGraphEdgeDto[]
  truncated: boolean
  maxNodes: number
  maxEdges: number
  stopReason?: string
  nodeCount?: number
  edgeCount?: number
  compatibilityGap: {
    entryDtoCount: number
    entryNodeCount: number
    filteredEntryIds: string[]
    notes: string[]
  }
  extensions?: Record<string, unknown>
}

export type ScanHypothesesDto = {
  schemaVersion: number
  scanId: string
  hypotheses: SecurityHypothesisDto[]
  count: number
}

export type ScanDto = {
  schemaVersion: number
  scanId: string
  projectId: string
  artifactDigest: string
  status: string
  verificationStatus: VerificationStatus
  dependencyMode: DependencyMode
  createdAt: string
  updatedAt: string
  evidenceRefs: EvidenceRef[]
  completedAt?: string
  entries?: EntryDto[]
  findings?: Finding[]
  hypotheses?: SecurityHypothesisDto[]
  paths?: PathStep[]
  /** create/get scan 返回时内嵌（P0-13）。 */
  coverage?: CoverageMatrixDto
  /** 已武装审计流水线游标投影（可选；旧服务端无）。 */
  pipelineArmed?: boolean
  pipelineStage?: string
  pipelineStopReason?: string
  pipelineStatus?: 'NONE' | 'IDLE' | 'RUNNING' | 'PAUSED' | 'STOPPED' | 'COMPLETE' | string
}
export type Scan = ScanDto
export type Evidence = EvidenceDto

export type DynamicTaskDto = {
  schemaVersion: number
  projectId: string
  artifactDigest: string
  scanId: string
  taskId: string
  status: string
  verificationStatus: 'DYNAMIC_SUSPECTED'
  requiredCapability: 'TRUSTED_DOCKER'
  dynamicExecutionMode: string
  stopReason?: string
  failureCode?: string
  failureDiagnostic?: string
  /** 审计时间线最新 worker/容器步骤行。 */
  progressDetail?: string
  updatedAt: string
}

export type CreateProjectRequest = {
  name: string
  projectId?: string
  idempotencyKey?: string
}

export type RegisterArtifactRequest = {
  /** 控制面可理解的本地路径；浏览器从不读取。 */
  path: string
  type?: ArtifactType
  staticOnly?: boolean
  authorized?: boolean
  idempotencyKey?: string
}

export type UploadProgressHandler = (percent: number) => void

export type UploadTask = Promise<ArtifactDto> & {
  cancel: () => void
}

export const ARTIFACT_UPLOAD_CHUNK_BYTES = 1024 * 1024
export const MAX_BROWSER_HASH_BYTES = 256 * 1024 * 1024

export type CreateScanRequest = {
  artifactId?: string
  artifactDigest?: string
  dependencyMode?: DependencyMode
  authorized?: boolean
  networkMode?: 'DENY' | 'ALLOWLIST' | string
  dangerousActionMode?: 'DRY_RUN' | 'SIMULATE' | string
  networkAllowlist?: string[]
  maxWallClockSeconds?: number
  maxMemoryBytes?: number
  maxDiskBytes?: number
  idempotencyKey?: string
  /** 可选 policy 对象扁平化到控制面 policy 字段。 */
  policy?: Record<string, unknown>
}

export type StartAuditRequest = CreateScanRequest & {
  aiAuthorized: boolean
  outputLanguage: OutputLanguage
}

export type AuditRunDto = {
  schemaVersion: number
  auditRunId: string
  projectId: string
  artifactDigest: string
  scanId: string
  status: string
  scan: ScanDto
  preAnalysisJob: AiJobDto
}

export type UpdateProjectRequest = { name: string }
export type UpdateArtifactRequest = { label?: string }
export type UpdateScanRequest = {
  action: 'pause' | 'resume' | 'cancel'
  authorized: true
  aiAuthorized?: true
  outputLanguage?: OutputLanguage
}

export type ProviderKind = 'OPENAI_CHAT' | 'ANTHROPIC_MESSAGES' | 'OPENAI_COMPATIBLE' | 'AZURE_OPENAI' | 'LOCAL'
export type ProviderDto = {
  schemaVersion: number
  providerId: string
  name: string
  kind: ProviderKind
  baseUrl?: string
  model?: string
  enabled: boolean
  hasCredential: boolean
  updatedAt?: string
}
export type SaveProviderRequest = {
  name: string
  kind: ProviderKind
  baseUrl?: string
  model?: string
  apiKey?: string
  enabled?: boolean
}

export type ProviderInventoryModelDto = {
  schemaVersion: number
  modelId: string
  providerId: string
  providerModelName: string
  contextWindowTokens: 0
  enabled: false
}
export type ProviderModelInventoryDto = {
  schemaVersion: number
  workspaceId: string
  providerId: string
  protocol: 'OPENAI_CHAT' | 'ANTHROPIC_MESSAGES'
  semantics: 'REMOTE_INVENTORY_ONLY'
  fetchedAt: string
  models: ProviderInventoryModelDto[]
}

export type AiRole =
  | 'PRE_ANALYSIS'
  | 'AUTH_ANALYSIS'
  | 'PATH_EXPLORATION'
  | 'DYNAMIC_VERIFICATION'
  | 'VULNERABILITY_TRIAGE'
  | 'REPORT_GENERATION'

export type IdentityTrack = 'UNAUTH' | 'USER' | 'ADMIN' | 'BYPASS_CANDIDATE'

export type PathOutcomeClass =
  | 'COLD_START'
  | 'AUTH_CHALLENGE'
  | 'REACHED_NO_BIND'
  | 'BUSINESS_TIMEOUT'
  | 'ENGINE_BUSY'
  | 'DEPENDENCY_MOCK_GAP'
  | 'TRANSPORT_ERROR'
  | 'PROBE_BUDGET'
  | 'IDENTITY_UNAVAILABLE'
  | 'HTTP_OBSERVED'
  | 'UNKNOWN'

export type SqlEventDto = {
  sqlText: string
  parameterSummary?: string
  readWrite?: string
  parameterized?: boolean
  maliciousFragmentPresent?: boolean
  captureMode?: string
}

export type PathTraceParameterFlowStep = {
  source?: string
  boundTo?: string
  flowedTo?: string
  effectRef?: string
}

export type PathRunDto = {
  schemaVersion: number
  pathRunId: string
  scanId: string
  entrypointRef: string
  track: IdentityTrack | string
  attemptId: string
  experimentPlanId?: string
  /** 存在时的 HTTP probe ↔ JDBC 关联键（P0-06）。 */
  correlationId?: string
  method: string
  contentType?: string
  requestSummary?: string
  outcomeClass: PathOutcomeClass | string
  httpStatus: number
  entryHit?: boolean | null
  parameterBound?: boolean | null
  sqlEvents: SqlEventDto[]
  stopReason?: string
  verificationStatus: VerificationStatus
  evidenceRefs?: EvidenceRef[]
  identityProvenance?: string
  identityPrecondition?: string
  /** 来自 BRANCH_COVERAGE 的 method → hit 分支索引（MVP-1）。 */
  branchHitMap?: Record<string, number[]>
  /** P0-21 path-debug 扩展（可选；旧 run 无）。 */
  postureKind?: string
  postureProvenance?: string
  forcedGuardRefs?: string[]
  tracePlanId?: string
  pathTraceId?: string
  worldPackId?: string
  worldPackDependencyMode?: string
  exitReason?: string
  legacyIncomplete?: boolean
  authRequirement?: string
  parameterFlow?: PathTraceParameterFlowStep[]
  lastBusinessHop?: string
  effectRefs?: string[]
}
export type RoleAssignmentDto = {
  schemaVersion: number
  projectId: string
  role: AiRole
  providerId: string
  model?: string
  updatedAt?: string
  promptZh?: string
  promptEn?: string
}
export type SaveRoleAssignmentRequest = {
  providerId: string
  model?: string
  promptZh?: string
  promptEn?: string
}

export type AiJobDto = {
  schemaVersion: number
  aiJobId: string
  projectId: string
  scanId?: string
  artifactDigest?: string
  role: AiRole
  providerId?: string
  model?: string
  status: string
  createdAt: string
  updatedAt?: string
  errorCode?: string
  outputLanguage?: OutputLanguage
}
export type AiJobEventStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'BLOCKED'
export type AiJobEventDto = {
  schemaVersion: number
  aiJobId: string
  sequence: number
  projectId: string
  stage: string
  status: AiJobEventStatus
  providerRequestSummary?: string
  providerResultSummary?: string
  toolCallName?: string
  toolArgumentsSummary?: string
  toolResultStatus?: string
  modelInferenceSummary?: string
  failureDiagnostic?: string
  createdAt: string
}
export type CreateAiJobRequest = {
  role: AiRole
  authorized: true
  scanId?: string
  outputLanguage: OutputLanguage
}

export type AuditRetryStage =
  | 'PRE_ANALYSIS'
  | 'AUTH_ANALYSIS'
  | 'AUTH_BYPASS_CONFIRM'
  | 'PATH_EXPLORATION'
  | 'DYNAMIC_OBSERVATION'
  | 'DYNAMIC_VERIFICATION'
  | 'VULNERABILITY_TRIAGE'
  | 'REPORT_GENERATION'

export type RetryAuditStageRequest = {
  scanId: string
  stage: AuditRetryStage
  authorized: true
  aiAuthorized?: true
  outputLanguage?: OutputLanguage
}

export type RetryAuditStageResult = {
  schemaVersion: number
  projectId: string
  scanId: string
  stage: string
  pipelineArmed: boolean
  aiJob?: AiJobDto
  dynamicTask?: DynamicTaskDto
}

export class ApiUnavailableError extends Error {
  constructor(operation: string, status?: number, options?: ErrorOptions) {
    super(`${operation} unavailable${status ? ` (${status})` : ''}`, options)
    this.name = 'ApiUnavailableError'
  }
}

export class ApiRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly requestId?: string
  ) {
    super(message)
    this.name = 'ApiRequestError'
  }
}

export class UploadCancelledError extends Error {
  constructor() {
    super('上传已取消')
    this.name = 'UploadCancelledError'
  }
}

export type ScanEventType =
  | 'ScanCreated'
  | 'TaskLeased'
  | 'TraceCommitted'
  | 'FindingUpdated'
  | 'TaskStopped'
  | 'ScanCompleted'
  | string

export type ScanEvent = {
  eventId: string
  eventType: ScanEventType
  /** 即使当前 envelope 为 schema v1，事件 scope 也显式给出。 */
  schemaVersion: number
  occurredAt: string
  projectId: string
  artifactDigest: string
  scanId: string
  taskId?: string
  idempotencyKey?: string | { scope: string; value: string }
  payload: unknown
  context?: { projectId: string; artifactDigest: string; scanId: string; taskId?: string }
}

export type ApiMode = 'demo' | 'control-plane'

export type SubscribeOptions = {
  /** 事件后（及重连后）以权威 GET 结果回调。 */
  onReconcile?: (scan: ScanDto) => void
  onError?: (error: unknown) => void
}

export interface SentinelApi {
  readonly mode: ApiMode
  loadDashboard(projectId?: string, scanId?: string): Promise<DashboardSnapshot>
  retryAuditStage(projectId: string, request: RetryAuditStageRequest): Promise<RetryAuditStageResult>
  listProjects(): Promise<ProjectDto[]>
  getProject(projectId: string): Promise<ProjectDto>
  createProject(request: CreateProjectRequest | string): Promise<ProjectDto>
  updateProject(projectId: string, request: UpdateProjectRequest): Promise<ProjectDto>
  deleteProject(projectId: string): Promise<void>
  listArtifacts(projectId: string): Promise<ArtifactDto[]>
  registerArtifact(request: RegisterArtifactRequest | string, projectId?: string): Promise<ArtifactDto>
  uploadArtifact(file: File, projectId: string, onProgress: UploadProgressHandler): UploadTask
  updateArtifact(projectId: string, artifactId: string, request: UpdateArtifactRequest): Promise<ArtifactDto>
  deleteArtifact(projectId: string, artifactId: string): Promise<void>
  listScans(projectId: string): Promise<ScanDto[]>
  createScan(request?: CreateScanRequest | string, projectId?: string): Promise<ScanDto>
  startAudit(projectId: string, request: StartAuditRequest): Promise<AuditRunDto>
  createDynamicTask(scanId: string): Promise<DynamicTaskDto>
  listDynamicTasks(scanId: string): Promise<DynamicTaskDto[]>
  replayFinding(findingId: string): Promise<FindingReplayDto>
  focusEntryProbe(scanId: string, entryId: string, body?: FocusEntryProbeRequest): Promise<FocusEntryProbeDto>
  replaySqlExperimentCard(scanId: string, cardId: string): Promise<FocusEntryProbeDto>
  updateScan(scanId: string, request: UpdateScanRequest): Promise<ScanDto>
  deleteScan(projectId: string, scanId: string): Promise<void>
  listProviders(): Promise<ProviderDto[]>
  createProvider(request: SaveProviderRequest): Promise<ProviderDto>
  updateProvider(providerId: string, request: Partial<SaveProviderRequest>): Promise<ProviderDto>
  deleteProvider(providerId: string): Promise<void>
  refreshProviderModels(providerId: string): Promise<ProviderModelInventoryDto>
  listRoleAssignments(projectId: string): Promise<RoleAssignmentDto[]>
  saveRoleAssignment(projectId: string, role: AiRole, request: SaveRoleAssignmentRequest): Promise<RoleAssignmentDto>
  deleteRoleAssignment(projectId: string, role: AiRole): Promise<void>
  listAiJobs(projectId: string): Promise<AiJobDto[]>
  createAiJob(projectId: string, request: CreateAiJobRequest): Promise<AiJobDto>
  getAiJob(aiJobId: string): Promise<AiJobDto>
  listAiJobEvents(aiJobId: string): Promise<AiJobEventDto[]>
  updateAiJob(aiJobId: string, action: 'cancel' | 'retry'): Promise<AiJobDto>
  deleteAiJob(aiJobId: string): Promise<void>
  getEntries(projectId?: string, scanId?: string): Promise<EntryDto[]>
  getScan(scanId: string): Promise<ScanDto>
  getScanCoverage(scanId: string): Promise<CoverageMatrixDto>
  getEvidenceGraph(scanId: string): Promise<EvidenceGraphDto>
  getScanHypotheses(scanId: string): Promise<ScanHypothesesDto>
  getScanAiMemory(scanId: string, section?: string): Promise<Record<string, unknown>>
  getEvidence(evidenceId: string): Promise<EvidenceDto>
  subscribe(scanId: string, onEvent: (event: ScanEvent) => void, options?: SubscribeOptions): () => void
}

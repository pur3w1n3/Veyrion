/**
 * The only boundary between the GUI and the Java Control Plane.
 *
 * The UI deliberately consumes DTOs instead of Java records.  Runtime
 * validation here is important: a malformed response must never be rendered
 * as a verified security result.  The demo adapter uses the same UI-shaped
 * values, but is selected only when VITE_DEMO_MODE=true.
 *
 * Schema field constants (Finding / Hypothesis / Coverage) are generated from
 * contracts/schemas via scripts/generate-contract-types.ps1 into
 * frontend/src/generated/contracts.ts — import those for drift checks; parsers
 * below remain the runtime wire validators.
 */

export {
  FindingRequiredFields,
  SecurityHypothesisRequiredFields,
  CoverageMatrixRequiredFields,
} from './generated/contracts'

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

/** Entry DTO plus the small projection consumed by the existing views. */
export type Entry = {
  id: string
  route: string
  method: string
  module: string
  protocol: string
  precondition: string
  status: VerificationStatus
  verificationStatus?: VerificationStatus
  /** UI coverage is a percentage. The Control Plane may omit it for a new entry. */
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

/** Attack-path step inside RootCauseAnalysis (MVP-5). */
export type AttackStepDto = {
  layer: string
  label: string
  evidenceRefs: string[]
}

/** Structured root-cause payload when a finding or verified row carries it. */
export type RootCauseDto = {
  attackPath: AttackStepDto[]
  rootCauseStatement: string
  affectedComponent?: string
  cweId?: string
  fixSuggestion?: string
  /** Optional TRIAGE counterevidence refs preserved through FindingDto wire copy. */
  counterevidence?: string[]
}

/** Known HypothesisFamily taxonomy (open wire; unknown → UNKNOWN). */
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

/** Normalize open-taxonomy family strings; unknown values degrade to UNKNOWN. */
export const normalizeHypothesisFamily = (raw: unknown): HypothesisFamily => {
  if (typeof raw !== 'string' || raw.trim() === '') return 'UNKNOWN'
  const upper = raw.trim().toUpperCase()
  return (HYPOTHESIS_FAMILIES as readonly string[]).includes(upper)
    ? (upper as HypothesisFamily)
    : 'UNKNOWN'
}

/** P0-12 SecurityHypothesis wire DTO from dashboard/scan.hypotheses[]. */
export type SecurityHypothesisDto = {
  schemaVersion: number
  hypothesisId: string
  scanId: string
  securityProperty: string
  family: HypothesisFamily
  /** Raw wire family before normalize (for unknown degradation display). */
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
  /** Present only if the API attaches RootCauseAnalysis (MVP-5); not on FindingDto today. */
  rootCause?: RootCauseDto
  /** Optional P0-12 SecurityHypothesis binding; absent on legacy findings. */
  hypothesisId?: string
  securityProperty?: string
}

/** CandidateRanker row from dashboard.rankedSinks (MVP-1). */
export type RankedSinkDto = {
  sinkId: string
  rank: number
  score: number
  category: string
  symbol?: string
  rankReasons: string[]
}

/** LedgerDiff aggregate from dashboard.ledgerDiff (MVP-3). */
export type LedgerDiffDto = {
  newlyMatched: string[]
  regressions: string[]
  unchangedCount: number
  coverageDelta: number
  summary?: string
}

/**
 * MVP-6 verified_findings scaffolding. Dashboard currently returns [].
 * Parser accepts either finding-shaped rows or persistence-shaped fields.
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

/** Contrast ledger status strings (not VerificationStatus). */
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
  /** ExperimentPlan.fuzzStrategyJson when exposed on the wire (MVP-4). */
  fuzzStrategyJson?: string
  /** Alias accepted if the API uses fuzzStrategy / fuzz_strategy. */
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
  /** INITIAL focus vs REPLAY of an experiment card / idempotent retry. */
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
  /** Demoted secondary finding rows omitted from findings[] (not AUTH_GAP sink population). */
  authGapFindingCount?: number
  /** AUTH_GAP category sink signals in the scan (often larger than authGapFindingCount). */
  authGapSinkCount?: number
  /** First-class SecurityHypothesis rows (P0-12); authoritative for multi-family views. */
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
  /** CandidateRanker top sinks (MVP-1); empty when unscanned. */
  rankedSinks?: RankedSinkDto[]
  /** Multi-round contrast ledger delta (MVP-3). */
  ledgerDiff?: LedgerDiffDto
  /** MVP-6 gate scaffolding; currently always [] until VerifiedStatusGate opens. */
  verifiedFindings?: VerifiedFindingDto[]
  contrastSnapshotId?: string
  contrastRoundIndex?: number
  /** Server-provided dynamic PathRun counts when present; UI must not upgrade verification. */
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
  /** Original upload/path basename; preferred UI title over digest/artifactId. */
  originalFileName?: string
  fileName?: string
  displayName?: string
}

/** Primary label for audit-target lists and selectors. */
export const artifactLabel = (artifact: Pick<ArtifactDto, 'type' | 'artifactId' | 'originalFileName' | 'fileName' | 'displayName'>): string => {
  const name = artifact.displayName
    ?? artifact.originalFileName
    ?? artifact.fileName
    ?? artifact.artifactId
  return `${artifact.type} · ${name}`
}
export type Artifact = ArtifactDto

/** P0-13 Coverage Matrix (read-only aggregation; SUCCESS ≠ safe). */
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

/** Known Evidence Graph node kinds; unknown kinds degrade without failing the page. */
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

/** P1-02 / P1-08 Evidence Graph wire node (open taxonomy + namespaced extensions). */
export type EvidenceGraphNodeDto = {
  id: string
  kind: EvidenceNodeKind
  /** Raw wire kind before normalize. */
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
  /** Remaining open fields preserved for degraded display. */
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
  /** Embedded when returned by create/get scan (P0-13). */
  coverage?: CoverageMatrixDto
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
  /** Latest worker/container step line for the audit timeline. */
  progressDetail?: string
  updatedAt: string
}

export type CreateProjectRequest = {
  name: string
  projectId?: string
  idempotencyKey?: string
}

export type RegisterArtifactRequest = {
  /** A local path understood by the Control Plane; the browser never reads it. */
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
  /** Optional policy object is flattened into the Control Plane policy fields. */
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
export type UpdateScanRequest = { action: 'cancel' | 'resume' }

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
  /** HTTP probe ↔ JDBC join key when present (P0-06). */
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
  /** method → hit branch indices from BRANCH_COVERAGE (MVP-1). */
  branchHitMap?: Record<string, number[]>
  /** P0-21 path-debug extensions (optional; absent on legacy runs). */
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
  /** Event scope is explicit even when the current envelope is schema v1. */
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
  /** Called after an event (and after reconnect) with the authoritative GET result. */
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
  deleteScan(scanId: string): Promise<void>
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
  getEvidence(evidenceId: string): Promise<EvidenceDto>
  subscribe(scanId: string, onEvent: (event: ScanEvent) => void, options?: SubscribeOptions): () => void
}

const statuses = new Set<VerificationStatus>([
  'VERIFIED',
  'DYNAMIC_CONFIRMED',
  'DYNAMIC_SUSPECTED',
  'STATIC_INFERRED',
  'UNREACHED'
])
const provenanceKinds = new Set<ProvenanceKind>(['FACT', 'INFERENCE', 'SIMULATION', 'RUNTIME_OBSERVED', 'AGENT_INSTRUMENTED', 'APPLICATION_REPORTED'])
const workerCapabilities = new Set<WorkerCapability>(['STATIC_ONLY', 'TRUSTED_DOCKER', 'HARDENED_GVISOR', 'HARDENED_KATA'])
const outputLanguages = new Set<OutputLanguage>(['ZH_CN', 'EN'])
const supportedSchemaVersion = 1
const supportedEventSchemaVersions = new Set([1, 2])

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null

const asText = (value: unknown, field: string): string => {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`invalid ${field}`)
  return value
}

const optionalText = (value: unknown): string | undefined => typeof value === 'string' ? value : undefined

const strictOptionalText = (value: unknown, field: string): string | undefined => {
  // JSON null and empty string are treated as absent optional fields.
  if (value === undefined || value === null || value === '') return undefined
  return asText(value, field)
}

const asFiniteNumber = (value: unknown, field: string, min = Number.NEGATIVE_INFINITY, max = Number.POSITIVE_INFINITY): number => {
  if (typeof value !== 'number') throw new Error(`invalid ${field}`)
  const number = value
  if (!Number.isFinite(number) || number < min || number > max) throw new Error(`invalid ${field}`)
  return number
}

const asSafeInteger = (value: unknown, field: string, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER): number => {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw new Error(`invalid ${field}`)
  return value as number
}

const asBoolean = (value: unknown, field: string): boolean => {
  if (typeof value !== 'boolean') throw new Error(`invalid ${field}`)
  return value
}

const schemaVersion = (value: unknown, field: string, required = true): number => {
  if (value === undefined && !required) return supportedSchemaVersion
  if (!Number.isSafeInteger(value) || value !== supportedSchemaVersion) throw new Error(`unsupported ${field}`)
  return value
}

const statusOf = (value: unknown, field: string): VerificationStatus => {
  if (typeof value !== 'string' || !statuses.has(value as VerificationStatus)) throw new Error(`invalid ${field}`)
  return value as VerificationStatus
}

const provenanceKindOf = (value: unknown, field: string): ProvenanceKind => {
  if (typeof value !== 'string' || !provenanceKinds.has(value as ProvenanceKind)) throw new Error(`invalid ${field}`)
  return value as ProvenanceKind
}

const workerCapabilityOf = (value: unknown, field: string): WorkerCapability => {
  if (typeof value !== 'string' || !workerCapabilities.has(value as WorkerCapability)) throw new Error(`invalid ${field}`)
  return value as WorkerCapability
}

const outputLanguageOf = (value: unknown, field: string): OutputLanguage => {
  if (typeof value !== 'string' || !outputLanguages.has(value as OutputLanguage)) throw new Error(`invalid ${field}`)
  return value as OutputLanguage
}

const listOfText = (value: unknown, field: string, optional = false): string[] => {
  // JSON null and omitted fields are equivalent for optional arrays.
  if ((value === undefined || value === null) && optional) return []
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) throw new Error(`invalid ${field}`)
  return value as string[]
}

const evidenceRefsOf = (value: unknown, field: string, optional = true): EvidenceRef[] => {
  if ((value === undefined || value === null) && optional) return []
  if (!Array.isArray(value)) throw new Error(`invalid ${field}`)
  return value.map((item) => {
    if (typeof item === 'string' && item.trim() !== '') return item
    if (!isRecord(item) || typeof item.evidenceId !== 'string' || item.evidenceId.trim() === '') throw new Error(`invalid ${field}`)
    const ref: { evidenceId: string; kind?: string; summary?: string } = { evidenceId: item.evidenceId }
    if (typeof item.kind === 'string') ref.kind = item.kind
    if (typeof item.summary === 'string') ref.summary = item.summary
    return ref
  })
}

const pathKind = (value: unknown): PathStep['kind'] => {
  if (value === 'entry' || value === 'transform' || value === 'branch' || value === 'dependency' || value === 'sink') return value
  // Server-side traces occasionally use node names. Keep the projection safe.
  if (value === 'resource' || value === 'database' || value === 'jdbc' || value === 'file') return 'dependency'
  if (value === 'source' || value === 'http') return 'entry'
  // ProbePlan IDENTITY_UNAVAILABLE steps; treat as a decision/branch node.
  if (value === 'identity' || value === 'auth' || value === 'precondition') return 'branch'
  if (value === 'call' || value === 'param' || value === 'return' || value === 'sanitizer' || value === 'guard') {
    return 'transform'
  }
  // Unknown kind must not fail the whole scan view (frontend AGENTS: degrade).
  if (typeof value === 'string' && value.trim() !== '') return 'transform'
  throw new Error('invalid path step kind')
}

const pathState = (value: unknown): PathStep['state'] => {
  if (value === 'blocked' || value === 'active' || value === 'done') return value
  // Unknown state: prefer blocked over crashing the dashboard.
  if (typeof value === 'string' && value.trim() !== '') return 'blocked'
  throw new Error('invalid path step state')
}

export const parseEntry = (item: unknown, context?: { schemaVersion?: number; projectId?: string; artifactDigest?: string }): Entry => {
  if (!isRecord(item)) throw new Error('invalid entry')
  const status = statusOf(item.verificationStatus ?? item.status, 'entry.verificationStatus')
  const route = asText(item.route, 'entry.route')
  const declaringClass = optionalText(item.declaringClass) ?? optionalText(item.className)
  const module = optionalText(item.module) ?? declaringClass ?? 'unknown'
  const parameters = listOfText(item.parameters, 'entry.parameters', true)
  const preconditionValue = item.preconditions ?? (item.precondition === undefined ? undefined : [item.precondition])
  const preconditions = listOfText(preconditionValue, 'entry.preconditions', true)
  const confidence = item.confidence === undefined ? undefined : asFiniteNumber(item.confidence, 'entry.confidence', 0, 1)
  const coverage = item.coverage === undefined
    ? confidence === undefined ? 0 : Math.round(confidence * 100)
    : asSafeInteger(item.coverage, 'entry.coverage', 0, 100)
  return {
    id: asText(item.id ?? item.entryId, 'entry.id'),
    route,
    method: asText(item.method, 'entry.method'),
    module,
    protocol: asText(item.protocol, 'entry.protocol'),
    precondition: preconditions.join(' · ') || '未标注',
    status,
    verificationStatus: status,
    coverage,
    schemaVersion: context?.schemaVersion,
    projectId: optionalText(item.projectId) ?? context?.projectId,
    artifactDigest: optionalText(item.artifactDigest) ?? context?.artifactDigest,
    scanId: optionalText(item.scanId),
    declaringClass,
    parameters,
    preconditions,
    evidenceRefs: evidenceRefsOf(item.evidenceRefs, 'entry.evidenceRefs'),
    confidence
  }
}

const severityOf = (value: unknown): Finding['severity'] => {
  if (typeof value !== 'string') throw new Error('invalid finding.severity')
  const normalized = value.toLowerCase()
  if (normalized !== 'critical' && normalized !== 'high' && normalized !== 'medium' && normalized !== 'low' && normalized !== 'info') throw new Error('invalid finding.severity')
  return normalized
}

const parseRootCause = (value: unknown, field: string): RootCauseDto | undefined => {
  if (value === undefined || value === null) return undefined
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed) return undefined
    try {
      return parseRootCause(JSON.parse(trimmed) as unknown, field)
    } catch {
      return { attackPath: [], rootCauseStatement: trimmed }
    }
  }
  if (!isRecord(value)) throw new Error(`invalid ${field}`)
  const attackRaw = value.attackPath
  const attackPath = attackRaw === undefined
    ? []
    : Array.isArray(attackRaw)
      ? attackRaw.map((step, index) => {
        if (!isRecord(step)) throw new Error(`invalid ${field}.attackPath[${index}]`)
        return {
          layer: optionalText(step.layer) ?? 'unknown',
          // Backend copyRootCause may emit "" when label was null.
          label: optionalText(step.label) || 'unknown',
          evidenceRefs: listOfText(step.evidenceRefs ?? [], `${field}.attackPath[${index}].evidenceRefs`, true)
        }
      })
      : (() => { throw new Error(`invalid ${field}.attackPath`) })()
  const counterRaw = value.counterevidence
  const counterevidence = counterRaw === undefined
    ? undefined
    : Array.isArray(counterRaw)
      ? listOfText(counterRaw, `${field}.counterevidence`)
      : (() => { throw new Error(`invalid ${field}.counterevidence`) })()
  return {
    attackPath,
    rootCauseStatement: optionalText(value.rootCauseStatement) ?? '',
    affectedComponent: strictOptionalText(value.affectedComponent, `${field}.affectedComponent`),
    cweId: strictOptionalText(value.cweId, `${field}.cweId`),
    fixSuggestion: strictOptionalText(value.fixSuggestion, `${field}.fixSuggestion`),
    ...(counterevidence !== undefined && counterevidence.length > 0 ? { counterevidence } : {})
  }
}

const parseRankedSink = (value: unknown): RankedSinkDto => {
  if (!isRecord(value)) throw new Error('invalid rankedSink')
  return {
    sinkId: asText(value.sinkId, 'rankedSink.sinkId'),
    rank: asSafeInteger(value.rank, 'rankedSink.rank', 1),
    score: asFiniteNumber(value.score, 'rankedSink.score', 0),
    category: optionalText(value.category) ?? '',
    symbol: strictOptionalText(value.symbol, 'rankedSink.symbol'),
    rankReasons: listOfText(value.rankReasons, 'rankedSink.rankReasons', true)
  }
}

const parseLedgerDiff = (value: unknown): LedgerDiffDto => {
  if (!isRecord(value)) throw new Error('invalid ledgerDiff')
  return {
    newlyMatched: listOfText(value.newlyMatched, 'ledgerDiff.newlyMatched', true),
    regressions: listOfText(value.regressions, 'ledgerDiff.regressions', true),
    unchangedCount: typeof value.unchangedCount === 'number' && Number.isFinite(value.unchangedCount)
      ? Math.max(0, Math.floor(value.unchangedCount))
      : 0,
    coverageDelta: typeof value.coverageDelta === 'number' && Number.isFinite(value.coverageDelta)
      ? value.coverageDelta
      : 0,
    summary: strictOptionalText(value.summary, 'ledgerDiff.summary')
  }
}

const parseBranchHitMap = (value: unknown): Record<string, number[]> | undefined => {
  if (value === undefined || value === null) return undefined
  if (!isRecord(value)) throw new Error('invalid pathRun.branchHitMap')
  const result: Record<string, number[]> = {}
  for (const [key, hits] of Object.entries(value)) {
    if (!key.trim()) continue
    if (!Array.isArray(hits)) throw new Error('invalid pathRun.branchHitMap')
    result[key] = hits.map((hit, index) => {
      if (typeof hit !== 'number' || !Number.isFinite(hit)) {
        throw new Error(`invalid pathRun.branchHitMap[${key}][${index}]`)
      }
      return Math.trunc(hit)
    })
  }
  return result
}

const parseVerifiedFinding = (value: unknown): VerifiedFindingDto => {
  if (!isRecord(value)) throw new Error('invalid verifiedFinding')
  const findingId = asText(value.findingId ?? value.id, 'verifiedFinding.findingId')
  const statusRaw = value.verificationStatus ?? value.status ?? 'VERIFIED'
  const verificationStatus = statusOf(statusRaw, 'verifiedFinding.verificationStatus')
  const rootCause = parseRootCause(value.rootCause ?? value.rootCauseJson ?? value.root_cause_json, 'verifiedFinding.rootCause')
  const replayRefs = value.replayEvidenceRefs ?? value.replay_evidence_refs
  return {
    findingId,
    scanId: optionalText(value.scanId),
    title: optionalText(value.title ?? value.summary),
    entry: optionalText(value.entry ?? value.entryRoute),
    sink: optionalText(value.sink),
    severity: value.severity === undefined ? undefined : severityOf(value.severity),
    verificationStatus,
    rootCause,
    replayEvidenceRefs: replayRefs === undefined ? undefined : evidenceRefsOf(replayRefs, 'verifiedFinding.replayEvidenceRefs'),
    verifiedAt: optionalText(value.verifiedAt ?? value.verified_at),
    attestationRef: optionalText(value.attestationRef ?? value.attestation_ref),
    evidenceRefs: evidenceRefsOf(value.evidenceRefs, 'verifiedFinding.evidenceRefs')
  }
}

export const parseSecurityHypothesis = (item: unknown): SecurityHypothesisDto => {
  if (!isRecord(item)) throw new Error('invalid securityHypothesis')
  const familyRaw = typeof item.family === 'string' ? item.family : undefined
  const lifecycleRaw = optionalText(item.lifecycle)
  const lifecycleValues = new Set(['CANDIDATE', 'SUPPORTED', 'CONTRADICTED', 'INSUFFICIENT_EVIDENCE', 'DISMISSED'])
  const lifecycle = lifecycleRaw && lifecycleValues.has(lifecycleRaw) ? lifecycleRaw : 'CANDIDATE'
  const family = normalizeHypothesisFamily(item.family)
  if (family === 'DATAFLOW') {
    if (typeof item.source !== 'string' || item.source.trim() === '' || typeof item.effect !== 'string' || item.effect.trim() === '') {
      throw new Error('invalid securityHypothesis.DATAFLOW')
    }
  }
  if (item.extensions !== undefined && !isRecord(item.extensions)) throw new Error('invalid securityHypothesis.extensions')
  const listRefs = (value: unknown, field: string): string[] => {
    if (value === undefined || value === null) return []
    if (!Array.isArray(value)) throw new Error(`invalid ${field}`)
    return value.map((entry, index) => asText(entry, `${field}[${index}]`))
  }
  return {
    schemaVersion: asSafeInteger(item.schemaVersion, 'securityHypothesis.schemaVersion', 1),
    hypothesisId: asText(item.hypothesisId, 'securityHypothesis.hypothesisId'),
    scanId: asText(item.scanId, 'securityHypothesis.scanId'),
    securityProperty: asText(item.securityProperty, 'securityHypothesis.securityProperty'),
    family,
    familyRaw,
    lifecycle,
    lifecycleRaw,
    detectorVersion: asText(item.detectorVersion, 'securityHypothesis.detectorVersion'),
    supportingEvidenceRefs: listRefs(item.supportingEvidenceRefs, 'securityHypothesis.supportingEvidenceRefs'),
    contradictingEvidenceRefs: listRefs(item.contradictingEvidenceRefs, 'securityHypothesis.contradictingEvidenceRefs'),
    coverageGapRefs: listRefs(item.coverageGapRefs, 'securityHypothesis.coverageGapRefs'),
    source: optionalText(item.source),
    effect: optionalText(item.effect),
    extensions: isRecord(item.extensions) ? { ...item.extensions } : undefined
  }
}

export const parseCoverageMatrix = (value: unknown): CoverageMatrixDto => {
  if (!isRecord(value)) throw new Error('invalid coverage matrix')
  if (!isRecord(value.artifactUniverseSummary)) throw new Error('invalid coverage.artifactUniverseSummary')
  if (!Array.isArray(value.entryFamilies)) throw new Error('invalid coverage.entryFamilies')
  if (!isRecord(value.callResolution)) throw new Error('invalid coverage.callResolution')
  if (!Array.isArray(value.detectors)) throw new Error('invalid coverage.detectors')
  if (!isRecord(value.dynamicExperiments)) throw new Error('invalid coverage.dynamicExperiments')
  if (!Array.isArray(value.stopReasons)) throw new Error('invalid coverage.stopReasons')
  if (!isRecord(value.gaps)) throw new Error('invalid coverage.gaps')
  if (!isRecord(value.honestyFlags)) throw new Error('invalid coverage.honestyFlags')
  if (value.callResolution.unresolvedIsGap !== true) throw new Error('invalid coverage.callResolution.unresolvedIsGap')
  if (value.gaps.countedAsCovered !== false) throw new Error('invalid coverage.gaps.countedAsCovered')
  if (value.honestyFlags.neverTreatSuccessAsSafe !== true
      || value.honestyFlags.gapsNeverCountAsCovered !== true
      || value.honestyFlags.scanSuccessMeans !== 'analysis_finished_not_safe') {
    throw new Error('invalid coverage.honestyFlags')
  }
  if (typeof value.checksum !== 'string' || !/^[0-9a-f]{64}$/.test(value.checksum)) {
    throw new Error('invalid coverage.checksum')
  }

  const namedCounts = (rows: unknown[], field: string) => rows.map((row, index) => {
    if (!isRecord(row)) throw new Error(`invalid ${field}[${index}]`)
    return {
      name: asText(row.name, `${field}[${index}].name`),
      count: asSafeInteger(row.count, `${field}[${index}].count`, 0)
    }
  })

  return {
    schemaVersion: asSafeInteger(value.schemaVersion, 'coverage.schemaVersion', 1),
    scanId: asText(value.scanId, 'coverage.scanId'),
    artifactUniverseSummary: {
      classCount: asSafeInteger(value.artifactUniverseSummary.classCount, 'coverage.classCount', 0),
      methodCount: asSafeInteger(value.artifactUniverseSummary.methodCount, 'coverage.methodCount', 0),
      fieldCount: asSafeInteger(value.artifactUniverseSummary.fieldCount, 'coverage.fieldCount', 0),
      dependencyCount: asSafeInteger(value.artifactUniverseSummary.dependencyCount, 'coverage.dependencyCount', 0),
      incomplete: asBoolean(value.artifactUniverseSummary.incomplete, 'coverage.incomplete'),
      note: asText(value.artifactUniverseSummary.note, 'coverage.note')
    },
    entryFamilies: namedCounts(value.entryFamilies, 'coverage.entryFamilies'),
    callResolution: {
      DIRECT: asSafeInteger(value.callResolution.DIRECT, 'coverage.callResolution.DIRECT', 0),
      CHA: asSafeInteger(value.callResolution.CHA, 'coverage.callResolution.CHA', 0),
      UNRESOLVED: asSafeInteger(value.callResolution.UNRESOLVED, 'coverage.callResolution.UNRESOLVED', 0),
      unresolvedIsGap: true
    },
    detectors: value.detectors.map((row, index) => {
      if (!isRecord(row)) throw new Error(`invalid coverage.detectors[${index}]`)
      return {
        family: asText(row.family, `coverage.detectors[${index}].family`),
        detectorVersion: asText(row.detectorVersion, `coverage.detectors[${index}].detectorVersion`),
        signals: asSafeInteger(row.signals, `coverage.detectors[${index}].signals`, 0),
        countedAsCovered: asBoolean(row.countedAsCovered, `coverage.detectors[${index}].countedAsCovered`),
        note: asText(row.note, `coverage.detectors[${index}].note`)
      }
    }),
    dynamicExperiments: {
      pathRunCount: asSafeInteger(value.dynamicExperiments.pathRunCount, 'coverage.dynamicExperiments.pathRunCount', 0),
      effectiveAttemptCount: asSafeInteger(value.dynamicExperiments.effectiveAttemptCount, 'coverage.dynamicExperiments.effectiveAttemptCount', 0),
      unreachedCount: asSafeInteger(value.dynamicExperiments.unreachedCount, 'coverage.dynamicExperiments.unreachedCount', 0),
      stopReasonSamples: stringRefList(value.dynamicExperiments.stopReasonSamples, 'coverage.dynamicExperiments.stopReasonSamples')
    },
    stopReasons: namedCounts(value.stopReasons, 'coverage.stopReasons'),
    gaps: {
      unknown: asSafeInteger(value.gaps.unknown, 'coverage.gaps.unknown', 0),
      unresolved: asSafeInteger(value.gaps.unresolved, 'coverage.gaps.unresolved', 0),
      truncated: asSafeInteger(value.gaps.truncated, 'coverage.gaps.truncated', 0),
      unreached: asSafeInteger(value.gaps.unreached, 'coverage.gaps.unreached', 0),
      total: asSafeInteger(value.gaps.total, 'coverage.gaps.total', 0),
      countedAsCovered: false
    },
    honestyFlags: {
      neverTreatSuccessAsSafe: true,
      gapsNeverCountAsCovered: true,
      scanSuccessMeans: 'analysis_finished_not_safe'
    },
    checksum: asText(value.checksum, 'coverage.checksum')
  }
}
const knownEvidenceNodeKinds = new Set<string>(EVIDENCE_NODE_KINDS)

export const normalizeEvidenceNodeKind = (raw: unknown): EvidenceNodeKind => {
  if (typeof raw !== 'string' || raw.trim() === '') return 'UNKNOWN'
  const upper = raw.trim().toUpperCase()
  return knownEvidenceNodeKinds.has(upper) ? upper as EvidenceNodeKind : 'UNKNOWN'
}

const stringRefList = (value: unknown, field: string): string[] => {
  if (value === undefined || value === null) return []
  if (!Array.isArray(value)) throw new Error(`invalid ${field}`)
  return value.map((entry, index) => asText(entry, `${field}[${index}]`))
}

export const parseEvidenceGraphNode = (value: unknown): EvidenceGraphNodeDto => {
  if (!isRecord(value)) throw new Error('invalid evidence graph node')
  const kindRaw = optionalText(value.kind)
  if (value.extensions !== undefined && !isRecord(value.extensions)) throw new Error('invalid evidenceGraph.node.extensions')
  const knownKeys = new Set([
    'id', 'kind', 'language', 'symbol', 'location', 'elementKind', 'protocol',
    'evidenceRefs', 'provenanceKind', 'extensions', 'verificationStatus'
  ])
  const extras: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) {
    if (!knownKeys.has(key)) extras[key] = entry
  }
  return {
    id: asText(value.id, 'evidenceGraph.node.id'),
    kind: normalizeEvidenceNodeKind(value.kind),
    kindRaw,
    language: optionalText(value.language),
    symbol: optionalText(value.symbol),
    location: optionalText(value.location),
    elementKind: optionalText(value.elementKind),
    protocol: optionalText(value.protocol),
    evidenceRefs: stringRefList(value.evidenceRefs, 'evidenceGraph.node.evidenceRefs'),
    provenanceKind: typeof value.provenanceKind === 'string' && value.provenanceKind.trim()
      ? value.provenanceKind
      : 'UNKNOWN',
    verificationStatus: value.verificationStatus === undefined
      ? undefined
      : statusOf(value.verificationStatus, 'evidenceGraph.node.verificationStatus'),
    extensions: isRecord(value.extensions) ? { ...value.extensions } : undefined,
    extras: Object.keys(extras).length > 0 ? extras : undefined
  }
}

export const parseEvidenceGraph = (value: unknown): EvidenceGraphDto => {
  if (!isRecord(value)) throw new Error('invalid evidence graph')
  if (!Array.isArray(value.nodes)) throw new Error('invalid evidenceGraph.nodes')
  if (!Array.isArray(value.edges)) throw new Error('invalid evidenceGraph.edges')
  if (!isRecord(value.compatibilityGap)) throw new Error('invalid evidenceGraph.compatibilityGap')
  if (value.extensions !== undefined && !isRecord(value.extensions)) throw new Error('invalid evidenceGraph.extensions')

  const nodes = value.nodes.map(parseEvidenceGraphNode)
  const edges = value.edges.map((edge, index) => {
    if (!isRecord(edge)) throw new Error(`invalid evidenceGraph.edges[${index}]`)
    return {
      id: asText(edge.id, `evidenceGraph.edges[${index}].id`),
      kind: asText(edge.kind, `evidenceGraph.edges[${index}].kind`),
      fromId: asText(edge.fromId, `evidenceGraph.edges[${index}].fromId`),
      toId: asText(edge.toId, `evidenceGraph.edges[${index}].toId`),
      evidenceRefs: stringRefList(edge.evidenceRefs, `evidenceGraph.edges[${index}].evidenceRefs`),
      provenanceKind: optionalText(edge.provenanceKind)
    }
  })
  return {
    schemaVersion: asSafeInteger(value.schemaVersion, 'evidenceGraph.schemaVersion', 1),
    scanId: asText(value.scanId, 'evidenceGraph.scanId'),
    nodes,
    edges,
    truncated: asBoolean(value.truncated, 'evidenceGraph.truncated'),
    maxNodes: asSafeInteger(value.maxNodes, 'evidenceGraph.maxNodes', 1),
    maxEdges: asSafeInteger(value.maxEdges, 'evidenceGraph.maxEdges', 1),
    stopReason: optionalText(value.stopReason),
    nodeCount: value.nodeCount === undefined
      ? nodes.length
      : asSafeInteger(value.nodeCount, 'evidenceGraph.nodeCount', 0),
    edgeCount: value.edgeCount === undefined
      ? edges.length
      : asSafeInteger(value.edgeCount, 'evidenceGraph.edgeCount', 0),
    compatibilityGap: {
      entryDtoCount: asSafeInteger(value.compatibilityGap.entryDtoCount, 'evidenceGraph.compatibilityGap.entryDtoCount', 0),
      entryNodeCount: asSafeInteger(value.compatibilityGap.entryNodeCount, 'evidenceGraph.compatibilityGap.entryNodeCount', 0),
      filteredEntryIds: stringRefList(value.compatibilityGap.filteredEntryIds, 'evidenceGraph.compatibilityGap.filteredEntryIds'),
      notes: stringRefList(value.compatibilityGap.notes, 'evidenceGraph.compatibilityGap.notes')
    },
    extensions: isRecord(value.extensions) ? { ...value.extensions } : undefined
  }
}

export const parseScanHypotheses = (value: unknown): ScanHypothesesDto => {
  if (!isRecord(value)) throw new Error('invalid scan hypotheses')
  if (!Array.isArray(value.hypotheses)) throw new Error('invalid scanHypotheses.hypotheses')
  const hypotheses = value.hypotheses.map(parseSecurityHypothesis)
  const count = asSafeInteger(value.count, 'scanHypotheses.count', 0)
  if (count !== hypotheses.length) throw new Error('invalid scanHypotheses.count')
  return {
    schemaVersion: asSafeInteger(value.schemaVersion, 'scanHypotheses.schemaVersion', 1),
    scanId: asText(value.scanId, 'scanHypotheses.scanId'),
    hypotheses,
    count
  }
}

export const parseFinding = (item: unknown, context?: { schemaVersion?: number; projectId?: string; artifactDigest?: string; scanId?: string }): Finding => {
  if (!isRecord(item)) throw new Error('invalid finding')
  const refs = evidenceRefsOf(item.evidenceRefs, 'finding.evidenceRefs')
  const findingStatus = statusOf(item.verificationStatus ?? item.status, 'finding.verificationStatus')
  const evidenceValue = item.evidence === undefined
    ? item.evidenceCount === undefined ? refs.length : asSafeInteger(item.evidenceCount, 'finding.evidenceCount', 0)
    : asSafeInteger(item.evidence, 'finding.evidence', 0)
  const rootCause = parseRootCause(item.rootCause ?? item.rootCauseJson, 'finding.rootCause')
  return {
    id: asText(item.id ?? item.findingId, 'finding.id'),
    title: asText(item.title ?? item.summary, 'finding.title'),
    severity: severityOf(item.severity),
    status: findingStatus,
    entry: asText(item.entry ?? item.entryRoute ?? item.entryId, 'finding.entry'),
    sink: asText(item.sink, 'finding.sink'),
    dependency: asText(item.dependency ?? item.dependencyMode ?? 'unknown', 'finding.dependency'),
    evidence: evidenceValue,
    evidenceCount: evidenceValue,
    verificationStatus: findingStatus,
    findingId: optionalText(item.findingId),
    entrypointId: optionalText(item.entrypointId),
    sinkId: optionalText(item.sinkId),
    dependencyMode: optionalText(item.dependencyMode),
    schemaVersion: context?.schemaVersion,
    projectId: optionalText(item.projectId) ?? context?.projectId,
    artifactDigest: optionalText(item.artifactDigest) ?? context?.artifactDigest,
    scanId: optionalText(item.scanId) ?? context?.scanId,
    evidenceRefs: refs,
    confidence: item.confidence === undefined ? undefined : asFiniteNumber(item.confidence, 'finding.confidence', 0, 1),
    rootCause,
    hypothesisId: optionalText(item.hypothesisId),
    securityProperty: optionalText(item.securityProperty)
  }
}

export const parseFindingReplay = (item: unknown): FindingReplayDto => {
  if (!isRecord(item)) throw new Error('invalid finding replay response')
  const status = statusOf(item.verificationStatus, 'findingReplay.verificationStatus')
  return {
    schemaVersion: asSafeInteger(item.schemaVersion, 'findingReplay.schemaVersion', 1),
    projectId: asText(item.projectId, 'findingReplay.projectId'),
    scanId: asText(item.scanId, 'findingReplay.scanId'),
    findingId: asText(item.findingId, 'findingReplay.findingId'),
    entrypointId: asText(item.entrypointId, 'findingReplay.entrypointId'),
    taskId: asText(item.taskId, 'findingReplay.taskId'),
    lifecycle: asText(item.lifecycle, 'findingReplay.lifecycle'),
    verificationStatus: status,
    dependencyMode: asText(item.dependencyMode, 'findingReplay.dependencyMode'),
    replayed: asBoolean(item.replayed, 'findingReplay.replayed'),
    requiredCapability: optionalText(item.requiredCapability) as WorkerCapability | undefined,
    dynamicExecutionMode: optionalText(item.dynamicExecutionMode)
  }
}

export const parseFocusEntryProbe = (item: unknown): FocusEntryProbeDto => {
  if (!isRecord(item)) throw new Error('invalid entry focus-probe response')
  const status = statusOf(item.verificationStatus, 'focusEntryProbe.verificationStatus')
  if (status === 'VERIFIED') throw new Error('focus-probe must not return VERIFIED')
  return {
    schemaVersion: asSafeInteger(item.schemaVersion, 'focusEntryProbe.schemaVersion', 1),
    projectId: asText(item.projectId, 'focusEntryProbe.projectId'),
    scanId: asText(item.scanId, 'focusEntryProbe.scanId'),
    findingId: item.findingId == null ? null : optionalText(item.findingId),
    entrypointId: asText(item.entrypointId, 'focusEntryProbe.entrypointId'),
    taskId: asText(item.taskId, 'focusEntryProbe.taskId'),
    lifecycle: asText(item.lifecycle, 'focusEntryProbe.lifecycle'),
    verificationStatus: status,
    dependencyMode: asText(item.dependencyMode, 'focusEntryProbe.dependencyMode'),
    replayed: asBoolean(item.replayed, 'focusEntryProbe.replayed'),
    attemptKind: strictOptionalText(item.attemptKind, 'focusEntryProbe.attemptKind'),
    experimentPlanId: strictOptionalText(item.experimentPlanId, 'focusEntryProbe.experimentPlanId'),
    requiredCapability: optionalText(item.requiredCapability) as WorkerCapability | undefined,
    dynamicExecutionMode: optionalText(item.dynamicExecutionMode)
  }
}

export const parsePath = (item: unknown): PathStep => {
  if (!isRecord(item)) throw new Error('invalid path step')
  const refs = evidenceRefsOf(item.evidenceRefs, 'path.evidenceRefs')
  return {
    label: asText(item.label ?? item.name ?? item.node, 'path.label'),
    detail: asText(item.detail ?? item.description ?? '', 'path.detail'),
    kind: pathKind(item.kind),
    state: pathState(item.state),
    evidenceRefs: refs,
    verificationStatus: item.verificationStatus === undefined ? undefined : statusOf(item.verificationStatus, 'path.verificationStatus'),
    provenanceKind: item.provenanceKind === undefined ? undefined : provenanceKindOf(item.provenanceKind, 'path.provenanceKind'),
    eventType: strictOptionalText(item.eventType, 'path.eventType'),
    sequence: item.sequence === undefined ? undefined : asSafeInteger(item.sequence, 'path.sequence', 0)
  }
}

export const parsePathTrace = (item: unknown): PathTrace => {
  if (!isRecord(item) || !Array.isArray(item.steps)) throw new Error('invalid dashboard.paths')
  return {
    pathId: asText(item.pathId, 'dashboard.paths.pathId'),
    entrypointId: asText(item.entrypointId, 'dashboard.paths.entrypointId'),
    verificationStatus: statusOf(item.verificationStatus ?? item.status, 'dashboard.paths.verificationStatus'),
    dependencyMode: asText(item.dependencyMode, 'dashboard.paths.dependencyMode'),
    stopReason: asText(item.stopReason, 'dashboard.paths.stopReason'),
    preconditions: listOfText(item.preconditions, 'dashboard.paths.preconditions', true),
    steps: item.steps.map(parsePath),
    evidenceRefs: evidenceRefsOf(item.evidenceRefs, 'dashboard.paths.evidenceRefs', true),
    requiredCapability: item.requiredCapability === undefined ? undefined : workerCapabilityOf(item.requiredCapability, 'dashboard.paths.requiredCapability'),
    taskId: strictOptionalText(item.taskId, 'dashboard.paths.taskId'),
    dynamicExecutionMode: strictOptionalText(item.dynamicExecutionMode, 'dashboard.paths.dynamicExecutionMode')
  }
}

export const parseDashboard = (value: unknown): DashboardSnapshot => {
  if (!isRecord(value)) throw new Error('invalid dashboard response')
  const version = schemaVersion(value.schemaVersion, 'dashboard.schemaVersion')
  const projectId = optionalText(value.projectId)
  const artifactDigest = optionalText(value.artifactDigest)
  const scanId = optionalText(value.scanId)
  const entriesValue = value.entries
  const findingsValue = value.findings
  const rawPaths = value.paths
  const richPaths = rawPaths === undefined
    ? []
    : Array.isArray(rawPaths) ? rawPaths.map(parsePathTrace) : (() => { throw new Error('invalid dashboard.paths') })()
  const rawPathValue = value.path ?? value.trace
  if (!Array.isArray(entriesValue) || !Array.isArray(findingsValue) || (rawPathValue !== undefined && !Array.isArray(rawPathValue))) throw new Error('invalid dashboard response')
  // GET dashboard remains authoritative. Prefer its compact projection when
  // present, while retaining every rich path and using the first path only as
  // a compatibility projection for views that still consume `path`.
  const pathValue = rawPathValue === undefined ? richPaths[0]?.steps ?? [] : rawPathValue
  const rawPathRuns = value.pathRuns
  const pathRuns = rawPathRuns === undefined
    ? []
    : Array.isArray(rawPathRuns) ? rawPathRuns.map(parsePathRun) : (() => { throw new Error('invalid dashboard.pathRuns') })()
  return {
    schemaVersion: version,
    projectId,
    artifactDigest,
    scanId,
    verificationStatus: value.verificationStatus === undefined ? undefined : statusOf(value.verificationStatus, 'dashboard.verificationStatus'),
    dependencyMode: typeof value.dependencyMode === 'string' ? value.dependencyMode : undefined,
    evidenceRefs: evidenceRefsOf(value.evidenceRefs, 'dashboard.evidenceRefs'),
    entries: entriesValue.map((item) => parseEntry(item, { schemaVersion: version, projectId, artifactDigest })),
    findings: findingsValue.map((item) => parseFinding(item, { schemaVersion: version, projectId, artifactDigest, scanId })),
    authGapFindingCount: typeof value.authGapFindingCount === 'number' && Number.isFinite(value.authGapFindingCount)
      ? Math.max(0, Math.floor(value.authGapFindingCount))
      : undefined,
    authGapSinkCount: typeof value.authGapSinkCount === 'number' && Number.isFinite(value.authGapSinkCount)
      ? Math.max(0, Math.floor(value.authGapSinkCount))
      : undefined,
    hypotheses: value.hypotheses === undefined
      ? []
      : Array.isArray(value.hypotheses)
        ? value.hypotheses.map(parseSecurityHypothesis)
        : (() => { throw new Error('invalid dashboard.hypotheses') })(),
    path: pathValue.map(parsePath),
    paths: richPaths,
    pathRuns,
    pathDebugSummaries: value.pathDebugSummaries === undefined
      ? []
      : Array.isArray(value.pathDebugSummaries)
        ? value.pathDebugSummaries.map(parsePathDebugEntrySummary)
        : (() => { throw new Error('invalid dashboard.pathDebugSummaries') })(),
    sqlExperimentCards: Array.isArray(value.sqlExperimentCards)
      ? value.sqlExperimentCards.map(parseSqlExperimentCard)
      : undefined,
    experimentPlans: Array.isArray(value.experimentPlans)
      ? value.experimentPlans.map(parseExperimentPlan)
      : undefined,
    experimentShapes: Array.isArray(value.experimentShapes)
      ? value.experimentShapes.map(parseExperimentShape)
      : undefined,
    analysisPacks: Array.isArray(value.analysisPacks)
      ? value.analysisPacks.map(parseAnalysisPack)
      : undefined,
    probeBudget: value.probeBudget === undefined ? undefined : parseProbeBudget(value.probeBudget),
    rankedSinks: value.rankedSinks === undefined
      ? []
      : Array.isArray(value.rankedSinks)
        ? value.rankedSinks.map(parseRankedSink)
        : (() => { throw new Error('invalid dashboard.rankedSinks') })(),
    ledgerDiff: value.ledgerDiff === undefined
      ? { newlyMatched: [], regressions: [], unchangedCount: 0, coverageDelta: 0, summary: '' }
      : parseLedgerDiff(value.ledgerDiff),
    verifiedFindings: value.verifiedFindings === undefined
      ? []
      : Array.isArray(value.verifiedFindings)
        ? value.verifiedFindings.map(parseVerifiedFinding)
        : (() => { throw new Error('invalid dashboard.verifiedFindings') })(),
    contrastSnapshotId: strictOptionalText(value.contrastSnapshotId, 'dashboard.contrastSnapshotId'),
    contrastRoundIndex: typeof value.contrastRoundIndex === 'number' && Number.isFinite(value.contrastRoundIndex)
      ? Math.max(0, Math.floor(value.contrastRoundIndex))
      : undefined,
    dynamicSupportedPathRuns: typeof value.dynamicSupportedPathRuns === 'number'
      && Number.isFinite(value.dynamicSupportedPathRuns)
      ? Math.max(0, Math.floor(value.dynamicSupportedPathRuns))
      : undefined,
    dynamicFailedPathRuns: typeof value.dynamicFailedPathRuns === 'number'
      && Number.isFinite(value.dynamicFailedPathRuns)
      ? Math.max(0, Math.floor(value.dynamicFailedPathRuns))
      : undefined
  }
}

const parseExperimentShape = (value: unknown): ExperimentShapeDto => {
  if (!isRecord(value)) throw new Error('invalid experimentShape')
  const status = statusOf(value.verificationStatus, 'experimentShape.verificationStatus')
  if (status === 'VERIFIED') throw new Error('experimentShape must not claim VERIFIED')
  return {
    pathRunId: asText(value.pathRunId, 'experimentShape.pathRunId'),
    entrypointRef: asText(value.entrypointRef, 'experimentShape.entrypointRef'),
    track: asText(value.track, 'experimentShape.track'),
    httpLine: optionalText(value.httpLine) ?? '',
    httpStatus: typeof value.httpStatus === 'number' ? value.httpStatus : -1,
    entryHit: value.entryHit === undefined ? undefined : value.entryHit === null ? null : value.entryHit === true,
    parameterBound: value.parameterBound === undefined ? undefined : value.parameterBound === null ? null : value.parameterBound === true,
    sqlTexts: listOfText(value.sqlTexts, 'experimentShape.sqlTexts', true),
    stopReason: optionalText(value.stopReason) ?? 'UNKNOWN',
    outcomeClass: optionalText(value.outcomeClass) ?? 'UNKNOWN',
    dependencyMode: typeof value.dependencyMode === 'string' ? value.dependencyMode : 'MOCK',
    verificationStatus: status,
    evidenceRefs: evidenceRefsOf(value.evidenceRefs, 'experimentShape.evidenceRefs')
  }
}

const parseSqlExperimentCard = (value: unknown): SqlExperimentCardDto => {
  if (!isRecord(value)) throw new Error('invalid sqlExperimentCard')
  const status = statusOf(value.verificationStatus, 'sqlExperimentCard.verificationStatus')
  if (status === 'VERIFIED') throw new Error('sqlExperimentCard must not claim VERIFIED')
  return {
    cardId: asText(value.cardId, 'sqlExperimentCard.cardId'),
    scanId: asText(value.scanId, 'sqlExperimentCard.scanId'),
    entrypointRef: asText(value.entrypointRef, 'sqlExperimentCard.entrypointRef'),
    track: asText(value.track, 'sqlExperimentCard.track'),
    experimentPlanId: strictOptionalText(value.experimentPlanId, 'sqlExperimentCard.experimentPlanId'),
    benignInput: optionalText(value.benignInput) ?? '',
    metaInput: optionalText(value.metaInput) ?? '',
    sqlBefore: optionalText(value.sqlBefore) ?? '',
    sqlAfter: optionalText(value.sqlAfter) ?? '',
    structureInfluenced: value.structureInfluenced === true,
    stopCondition: optionalText(value.stopCondition) ?? 'UNKNOWN',
    dependencyMode: typeof value.dependencyMode === 'string' ? value.dependencyMode : 'MOCK',
    verificationStatus: status,
    pathRunRefs: listOfText(value.pathRunRefs, 'sqlExperimentCard.pathRunRefs', true),
    evidenceRefs: evidenceRefsOf(value.evidenceRefs, 'sqlExperimentCard.evidenceRefs'),
    replayable: value.replayable !== false
  }
}

const parseExperimentPlan = (value: unknown): ExperimentPlanDto => {
  if (!isRecord(value)) throw new Error('invalid experimentPlan')
  const fuzzRaw = value.fuzzStrategyJson ?? value.fuzzStrategy ?? value.fuzz_strategy
  const fuzzStrategyJson = typeof fuzzRaw === 'string' && fuzzRaw.trim() !== '' ? fuzzRaw : undefined
  return {
    planId: asText(value.planId, 'experimentPlan.planId'),
    entrypointRef: asText(value.entrypointRef, 'experimentPlan.entrypointRef'),
    track: asText(value.track, 'experimentPlan.track'),
    method: asText(value.method, 'experimentPlan.method'),
    contentType: asText(value.contentType, 'experimentPlan.contentType'),
    maxAttempts: typeof value.maxAttempts === 'number' ? Math.max(1, Math.min(8, Math.floor(value.maxAttempts))) : 1,
    candidateInputs: listOfText(value.candidateInputs, 'experimentPlan.candidateInputs', true),
    stopCondition: optionalText(value.stopCondition) ?? 'COMPLETED',
    packId: strictOptionalText(value.packId, 'experimentPlan.packId'),
    boundForExecution: value.boundForExecution === true,
    serverGated: value.serverGated === true,
    fuzzStrategyJson,
    fuzzStrategy: fuzzStrategyJson
  }
}

const parseProbeBudget = (value: unknown): ProbeBudgetDto => {
  if (!isRecord(value)) throw new Error('invalid probeBudget')
  return {
    maxProbes: typeof value.maxProbes === 'number' ? Math.max(0, Math.floor(value.maxProbes)) : 0,
    plannedProbes: typeof value.plannedProbes === 'number' ? Math.max(0, Math.floor(value.plannedProbes)) : 0,
    unreachedEntries: typeof value.unreachedEntries === 'number' ? Math.max(0, Math.floor(value.unreachedEntries)) : 0,
    strategy: optionalText(value.strategy) ?? '',
    entryTrackPlans: Array.isArray(value.entryTrackPlans)
      ? value.entryTrackPlans.filter(isRecord) as Array<Record<string, unknown>>
      : []
  }
}

const parseAnalysisPack = (value: unknown): AnalysisPackDto => {
  if (!isRecord(value)) throw new Error('invalid analysisPack')
  return {
    packId: asText(value.packId, 'analysisPack.packId'),
    destructive: value.destructive === true,
    jwtSecretHint: strictOptionalText(value.jwtSecretHint, 'analysisPack.jwtSecretHint'),
    templates: Array.isArray(value.templates) ? value.templates.map(parseExperimentPlan) : []
  }
}

const parsePathDebugTrackSummary = (value: unknown): PathDebugTrackSummary => {
  if (!isRecord(value)) throw new Error('invalid pathDebug track summary')
  return {
    track: optionalText(value.track),
    postureKind: optionalText(value.postureKind),
    postureProvenance: optionalText(value.postureProvenance),
    exitReason: optionalText(value.exitReason),
    lastBusinessHop: optionalText(value.lastBusinessHop),
    // Legacy / no-trace rows omit these arrays; treat missing as empty.
    effectRefs: listOfText(value.effectRefs, 'pathDebug.effectRefs', true),
    forcedGuardRefs: listOfText(value.forcedGuardRefs, 'pathDebug.forcedGuardRefs', true),
    worldPackId: optionalText(value.worldPackId),
    authRequirement: optionalText(value.authRequirement),
    httpStatus: typeof value.httpStatus === 'number' ? value.httpStatus : undefined,
    verificationStatus: value.verificationStatus === undefined
      ? undefined
      : statusOf(value.verificationStatus, 'pathDebug.verificationStatus'),
    legacyIncomplete: value.legacyIncomplete === true,
    parameterFlow: Array.isArray(value.parameterFlow)
      ? value.parameterFlow.filter(isRecord).map((step) => ({
        source: optionalText(step.source),
        boundTo: optionalText(step.boundTo),
        flowedTo: optionalText(step.flowedTo),
        effectRef: optionalText(step.effectRef)
      }))
      : undefined
  }
}

const parsePathDebugEntrySummary = (value: unknown): PathDebugEntrySummary => {
  if (!isRecord(value)) throw new Error('invalid pathDebug entry summary')
  const tracksRaw = value.tracks
  return {
    entryId: asText(value.entryId, 'pathDebug.entryId'),
    route: asText(value.route, 'pathDebug.route'),
    tracks: Array.isArray(tracksRaw)
      ? tracksRaw.map(parsePathDebugTrackSummary)
      : (() => { throw new Error('invalid pathDebug.tracks') })()
  }
}

const parsePathRun = (value: unknown): PathRunDto => {
  if (!isRecord(value)) throw new Error('invalid pathRun')
  // PathTrace enrichment may live nested under pathTrace; prefer top-level, fall back to nested.
  const nestedTrace = isRecord(value.pathTrace) ? value.pathTrace : undefined
  const sqlRaw = value.sqlEvents
  const sqlEvents = sqlRaw === undefined || sqlRaw === null
    ? []
    : Array.isArray(sqlRaw)
      ? sqlRaw.map((item) => {
        if (!isRecord(item)) throw new Error('invalid pathRun.sqlEvents')
        return {
          sqlText: typeof item.sqlText === 'string' ? item.sqlText : '',
          parameterSummary: typeof item.parameterSummary === 'string' ? item.parameterSummary : undefined,
          readWrite: typeof item.readWrite === 'string' ? item.readWrite : undefined,
          parameterized: typeof item.parameterized === 'boolean' ? item.parameterized : undefined,
          maliciousFragmentPresent: typeof item.maliciousFragmentPresent === 'boolean'
            ? item.maliciousFragmentPresent : undefined,
          captureMode: typeof item.captureMode === 'string' ? item.captureMode : undefined
        }
      })
      : (() => { throw new Error('invalid pathRun.sqlEvents') })()
  return {
    schemaVersion: schemaVersion(value.schemaVersion, 'pathRun.schemaVersion'),
    pathRunId: asText(value.pathRunId, 'pathRun.pathRunId'),
    scanId: asText(value.scanId, 'pathRun.scanId'),
    entrypointRef: asText(value.entrypointRef, 'pathRun.entrypointRef'),
    track: asText(value.track, 'pathRun.track'),
    attemptId: asText(value.attemptId, 'pathRun.attemptId'),
    experimentPlanId: strictOptionalText(value.experimentPlanId, 'pathRun.experimentPlanId'),
    correlationId: strictOptionalText(value.correlationId, 'pathRun.correlationId'),
    method: asText(value.method ?? 'GET', 'pathRun.method'),
    contentType: strictOptionalText(value.contentType, 'pathRun.contentType'),
    requestSummary: strictOptionalText(value.requestSummary, 'pathRun.requestSummary'),
    outcomeClass: asText(value.outcomeClass, 'pathRun.outcomeClass'),
    httpStatus: typeof value.httpStatus === 'number' ? value.httpStatus : -1,
    entryHit: typeof value.entryHit === 'boolean' ? value.entryHit : null,
    parameterBound: typeof value.parameterBound === 'boolean' ? value.parameterBound : null,
    sqlEvents,
    stopReason: strictOptionalText(value.stopReason, 'pathRun.stopReason'),
    verificationStatus: statusOf(value.verificationStatus, 'pathRun.verificationStatus'),
    evidenceRefs: evidenceRefsOf(value.evidenceRefs, 'pathRun.evidenceRefs'),
    identityProvenance: strictOptionalText(value.identityProvenance, 'pathRun.identityProvenance'),
    identityPrecondition: strictOptionalText(value.identityPrecondition, 'pathRun.identityPrecondition'),
    branchHitMap: parseBranchHitMap(value.branchHitMap),
    postureKind: strictOptionalText(value.postureKind, 'pathRun.postureKind'),
    postureProvenance: strictOptionalText(value.postureProvenance, 'pathRun.postureProvenance'),
    forcedGuardRefs: Array.isArray(value.forcedGuardRefs)
      ? value.forcedGuardRefs.filter((item): item is string => typeof item === 'string')
      : undefined,
    tracePlanId: strictOptionalText(value.tracePlanId, 'pathRun.tracePlanId'),
    pathTraceId: strictOptionalText(
      value.pathTraceId ?? nestedTrace?.pathTraceId, 'pathRun.pathTraceId'),
    worldPackId: strictOptionalText(
      value.worldPackId ?? nestedTrace?.worldPackId, 'pathRun.worldPackId'),
    worldPackDependencyMode: strictOptionalText(value.worldPackDependencyMode, 'pathRun.worldPackDependencyMode'),
    exitReason: strictOptionalText(
      value.exitReason ?? nestedTrace?.exitReason, 'pathRun.exitReason'),
    legacyIncomplete: value.legacyIncomplete === true ? true : value.legacyIncomplete === false ? false : undefined,
    authRequirement: strictOptionalText(value.authRequirement, 'pathRun.authRequirement'),
    parameterFlow: (() => {
      const raw = Array.isArray(value.parameterFlow)
        ? value.parameterFlow
        : Array.isArray(nestedTrace?.parameterFlow) ? nestedTrace.parameterFlow : undefined
      if (raw === undefined) return undefined
      return raw.map((item) => {
        if (!isRecord(item)) throw new Error('invalid pathRun.parameterFlow')
        return {
          source: strictOptionalText(item.source, 'pathRun.parameterFlow.source'),
          boundTo: strictOptionalText(item.boundTo, 'pathRun.parameterFlow.boundTo'),
          flowedTo: strictOptionalText(item.flowedTo, 'pathRun.parameterFlow.flowedTo'),
          effectRef: strictOptionalText(item.effectRef, 'pathRun.parameterFlow.effectRef')
        }
      })
    })(),
    lastBusinessHop: strictOptionalText(
      value.lastBusinessHop ?? nestedTrace?.lastBusinessHop, 'pathRun.lastBusinessHop'),
    effectRefs: (() => {
      const raw = Array.isArray(value.effectRefs)
        ? value.effectRefs
        : Array.isArray(nestedTrace?.effectRefs) ? nestedTrace.effectRefs : undefined
      return raw === undefined
        ? undefined
        : raw.filter((item): item is string => typeof item === 'string')
    })()
  }
}

const unwrap = (value: unknown, key: string): unknown => isRecord(value) && value[key] !== undefined ? value[key] : value

export const parseProject = (value: unknown): ProjectDto => {
  const body = unwrap(value, 'project')
  if (!isRecord(body)) throw new Error('invalid project response')
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : undefined, 'project.schemaVersion'),
    projectId: asText(body.projectId ?? body.id, 'project.projectId'),
    name: asText(body.name, 'project.name'),
    createdAt: asText(body.createdAt, 'project.createdAt'),
    verificationStatus: body.verificationStatus === undefined ? undefined : statusOf(body.verificationStatus, 'project.verificationStatus'),
    dependencyMode: optionalText(body.dependencyMode),
    evidenceRefs: evidenceRefsOf(body.evidenceRefs, 'project.evidenceRefs'),
    artifacts: body.artifacts === undefined
      ? undefined
      : Array.isArray(body.artifacts) ? body.artifacts.map(parseArtifact) : (() => { throw new Error('invalid project.artifacts') })()
  }
}

export const parseArtifact = (value: unknown): ArtifactDto => {
  const body = unwrap(value, 'artifact')
  if (!isRecord(body)) throw new Error('invalid artifact response')
  const status = statusOf(body.verificationStatus ?? body.status, 'artifact.verificationStatus')
  const artifactId = asText(body.artifactId ?? body.id, 'artifact.artifactId')
  const originalFileName = optionalText(body.originalFileName) ?? optionalText(body.fileName)
  const displayName = optionalText(body.displayName) ?? originalFileName ?? artifactId
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : undefined, 'artifact.schemaVersion'),
    artifactId,
    type: asText(body.type ?? body.artifactType, 'artifact.type').toUpperCase(),
    artifactType: asText(body.type ?? body.artifactType, 'artifact.type').toUpperCase(),
    artifactDigest: asText(body.artifactDigest ?? body.sha256, 'artifact.artifactDigest'),
    sizeBytes: asSafeInteger(body.sizeBytes, 'artifact.sizeBytes', 0),
    staticOnly: asBoolean(body.staticOnly, 'artifact.staticOnly'),
    verificationStatus: status,
    dependencyMode: optionalText(body.dependencyMode),
    evidenceRefs: evidenceRefsOf(body.evidenceRefs, 'artifact.evidenceRefs'),
    projectId: optionalText(body.projectId),
    registeredAt: optionalText(body.registeredAt),
    originalFileName,
    fileName: originalFileName,
    displayName
  }
}

export const parseEntries = (value: unknown): EntryDto[] => {
  if (!isRecord(value)) throw new Error('invalid entries response')
  const rawEntries = value.entries ?? value.items
  if (!Array.isArray(rawEntries)) throw new Error('invalid entries response')
  const version = schemaVersion(value.schemaVersion, 'entries.schemaVersion')
  const projectId = optionalText(value.projectId)
  const artifactDigest = optionalText(value.artifactDigest)
  return rawEntries.map((item) => parseEntry(item, { schemaVersion: version, projectId, artifactDigest }))
}

export const parseScan = (value: unknown): ScanDto => {
  const body = unwrap(value, 'scan')
  if (!isRecord(body)) throw new Error('invalid scan response')
  const version = schemaVersion(isRecord(value) ? value.schemaVersion : undefined, 'scan.schemaVersion')
  const projectId = asText(body.projectId, 'scan.projectId')
  const artifactDigest = asText(body.artifactDigest, 'scan.artifactDigest')
  const scanId = asText(body.scanId ?? body.id, 'scan.scanId')
  const completedAt = optionalText(body.completedAt)
  const entries = body.entries === undefined
    ? undefined
    : Array.isArray(body.entries) ? body.entries.map((item) => parseEntry(item, { schemaVersion: version, projectId, artifactDigest })) : (() => { throw new Error('invalid scan.entries') })()
  const findings = body.findings === undefined
    ? undefined
    : Array.isArray(body.findings) ? body.findings.map((item) => parseFinding(item, { schemaVersion: version, projectId, artifactDigest, scanId })) : (() => { throw new Error('invalid scan.findings') })()
  const hypotheses = body.hypotheses === undefined
    ? undefined
    : Array.isArray(body.hypotheses)
      ? body.hypotheses.map(parseSecurityHypothesis)
      : (() => { throw new Error('invalid scan.hypotheses') })()
  const paths = body.paths === undefined
    ? undefined
    : Array.isArray(body.paths) ? body.paths.flatMap((item) => isRecord(item) && Array.isArray(item.steps) ? item.steps.map(parsePath) : [parsePath(item)]) : (() => { throw new Error('invalid scan.paths') })()
  return {
    schemaVersion: version,
    scanId,
    projectId,
    artifactDigest,
    status: asText(body.status, 'scan.status'),
    verificationStatus: statusOf(body.verificationStatus ?? body.status, 'scan.verificationStatus'),
    dependencyMode: asText(body.dependencyMode, 'scan.dependencyMode'),
    createdAt: asText(body.createdAt, 'scan.createdAt'),
    // The Java DTO calls the terminal timestamp completedAt. Keep a stable
    // updatedAt projection for the UI while accepting in-flight snapshots.
    updatedAt: asText(body.updatedAt ?? completedAt ?? body.createdAt, 'scan.updatedAt'),
    evidenceRefs: evidenceRefsOf(body.evidenceRefs, 'scan.evidenceRefs', false),
    completedAt,
    entries,
    findings,
    hypotheses,
    paths
  }
}

export const parseDynamicTask = (value: unknown): DynamicTaskDto => {
  if (!isRecord(value)) throw new Error('invalid dynamic task response')
  const capability = workerCapabilityOf(value.requiredCapability, 'dynamicTask.requiredCapability')
  if (capability !== 'TRUSTED_DOCKER'
      || value.verificationStatus !== 'DYNAMIC_SUSPECTED') {
    throw new Error('invalid trusted Docker artifact task')
  }
  return {
    schemaVersion: schemaVersion(value.schemaVersion, 'dynamicTask.schemaVersion'),
    projectId: asText(value.projectId, 'dynamicTask.projectId'),
    artifactDigest: asText(value.artifactDigest, 'dynamicTask.artifactDigest'),
    scanId: asText(value.scanId, 'dynamicTask.scanId'),
    taskId: asText(value.taskId, 'dynamicTask.taskId'),
    status: asText(value.status, 'dynamicTask.status'),
    verificationStatus: 'DYNAMIC_SUSPECTED',
    requiredCapability: 'TRUSTED_DOCKER',
    dynamicExecutionMode: asText(value.dynamicExecutionMode, 'dynamicTask.dynamicExecutionMode'),
    stopReason: optionalText(value.stopReason),
    failureCode: optionalText(value.failureCode),
    failureDiagnostic: optionalText(value.failureDiagnostic),
    progressDetail: optionalText(value.progressDetail),
    updatedAt: asText(value.updatedAt, 'dynamicTask.updatedAt')
  }
}

export const parseEvidence = (value: unknown): EvidenceDto => {
  const body = unwrap(value, 'evidence')
  if (!isRecord(body)) throw new Error('invalid evidence response')
  const version = schemaVersion(isRecord(value) ? value.schemaVersion : undefined, 'evidence.schemaVersion')
  return {
    schemaVersion: version,
    evidenceId: asText(body.evidenceId ?? body.id, 'evidence.evidenceId'),
    projectId: optionalText(body.projectId),
    artifactDigest: optionalText(body.artifactDigest),
    scanId: optionalText(body.scanId),
    kind: asText(body.kind ?? body.provenanceKind, 'evidence.kind'),
    provenanceKind: body.provenanceKind === undefined ? undefined : provenanceKindOf(body.provenanceKind, 'evidence.provenanceKind'),
    verificationStatus: body.verificationStatus === undefined ? undefined : statusOf(body.verificationStatus, 'evidence.verificationStatus'),
    source: asText(body.source, 'evidence.source'),
    confidence: asFiniteNumber(body.confidence, 'evidence.confidence', 0, 1),
    summary: asText(body.summary, 'evidence.summary'),
    observedAt: optionalText(body.observedAt),
    toolVersion: optionalText(body.toolVersion),
    modelVersion: optionalText(body.modelVersion),
    snapshotRef: optionalText(body.snapshotRef)
  }
}

const parseList = <T>(value: unknown, key: string, parser: (item: unknown) => T): T[] => {
  const body = isRecord(value) && value[key] !== undefined ? value[key] : value
  if (!Array.isArray(body)) throw new Error(`invalid ${key} response`)
  return body.map(parser)
}

export const parseProvider = (value: unknown): ProviderDto => {
  const body = unwrap(value, 'provider')
  if (!isRecord(body)) throw new Error('invalid provider response')
  const kind = asText(body.kind, 'provider.kind') as ProviderKind
  if (!['OPENAI_CHAT', 'ANTHROPIC_MESSAGES', 'OPENAI_COMPATIBLE', 'AZURE_OPENAI', 'LOCAL'].includes(kind)) {
    throw new Error('invalid provider.kind')
  }
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : body.schemaVersion, 'provider.schemaVersion', false),
    providerId: asText(body.providerId ?? body.id, 'provider.providerId'),
    name: asText(body.name, 'provider.name'),
    kind,
    baseUrl: optionalText(body.baseUrl),
    model: optionalText(body.model),
    enabled: body.enabled === undefined ? true : asBoolean(body.enabled, 'provider.enabled'),
    hasCredential: body.hasCredential === undefined ? false : asBoolean(body.hasCredential, 'provider.hasCredential'),
    updatedAt: optionalText(body.updatedAt)
  }
}

export const parseProviderModelInventory = (value: unknown): ProviderModelInventoryDto => {
  if (!isRecord(value) || !Array.isArray(value.models)) throw new Error('invalid provider inventory response')
  const protocol = asText(value.protocol, 'providerInventory.protocol')
  if (protocol !== 'OPENAI_CHAT' && protocol !== 'ANTHROPIC_MESSAGES') {
    throw new Error('invalid providerInventory.protocol')
  }
  if (value.semantics !== 'REMOTE_INVENTORY_ONLY') {
    throw new Error('invalid providerInventory.semantics')
  }
  const providerId = asText(value.providerId, 'providerInventory.providerId')
  return {
    schemaVersion: schemaVersion(value.schemaVersion, 'providerInventory.schemaVersion'),
    workspaceId: asText(value.workspaceId, 'providerInventory.workspaceId'),
    providerId,
    protocol,
    semantics: 'REMOTE_INVENTORY_ONLY',
    fetchedAt: asText(value.fetchedAt, 'providerInventory.fetchedAt'),
    models: value.models.map((item) => {
      if (!isRecord(item)
          || item.providerId !== providerId
          || item.enabled !== false
          || item.contextWindowTokens !== 0) {
        throw new Error('invalid providerInventory.models')
      }
      return {
        schemaVersion: schemaVersion(item.schemaVersion, 'providerInventory.model.schemaVersion'),
        modelId: asText(item.modelId, 'providerInventory.model.modelId'),
        providerId,
        providerModelName: asText(item.providerModelName, 'providerInventory.model.providerModelName'),
        contextWindowTokens: 0,
        enabled: false
      }
    })
  }
}

export const parseRoleAssignment = (value: unknown): RoleAssignmentDto => {
  const body = unwrap(value, 'roleAssignment')
  if (!isRecord(body)) throw new Error('invalid role assignment response')
  const role = asText(body.role, 'roleAssignment.role') as AiRole
  if (!['PRE_ANALYSIS', 'AUTH_ANALYSIS', 'PATH_EXPLORATION', 'DYNAMIC_VERIFICATION', 'VULNERABILITY_TRIAGE', 'REPORT_GENERATION'].includes(role)) throw new Error('invalid roleAssignment.role')
  // Control plane emits schemaVersion 2 once promptZh/promptEn are on the wire (V010+).
  const rawSchema = isRecord(value) && value.schemaVersion !== undefined
    ? value.schemaVersion
    : body.schemaVersion
  const assignmentSchema = rawSchema === undefined
    ? 2
    : Number.isSafeInteger(rawSchema) && (rawSchema === 1 || rawSchema === 2)
      ? rawSchema
      : (() => { throw new Error('unsupported roleAssignment.schemaVersion') })()
  return {
    schemaVersion: assignmentSchema,
    projectId: asText(body.projectId, 'roleAssignment.projectId'),
    role,
    providerId: asText(body.providerId, 'roleAssignment.providerId'),
    model: optionalText(body.model),
    updatedAt: optionalText(body.updatedAt),
    promptZh: optionalText(body.promptZh),
    promptEn: optionalText(body.promptEn)
  }
}

export const parseAiJob = (value: unknown): AiJobDto => {
  const body = unwrap(value, 'aiJob')
  if (!isRecord(body)) throw new Error('invalid ai job response')
  const role = asText(body.role, 'aiJob.role') as AiRole
  if (!['PRE_ANALYSIS', 'AUTH_ANALYSIS', 'PATH_EXPLORATION', 'DYNAMIC_VERIFICATION', 'VULNERABILITY_TRIAGE', 'REPORT_GENERATION'].includes(role)) throw new Error('invalid aiJob.role')
  let policySnapshot: Record<string, unknown> | undefined
  if (body.policySnapshot !== undefined) {
    if (isRecord(body.policySnapshot)) {
      policySnapshot = body.policySnapshot
    } else if (typeof body.policySnapshot === 'string') {
      try {
        const decoded: unknown = JSON.parse(body.policySnapshot)
        if (!isRecord(decoded)) throw new Error('invalid aiJob.policySnapshot')
        policySnapshot = decoded
      } catch (cause) {
        throw new Error('invalid aiJob.policySnapshot', { cause })
      }
    } else {
      throw new Error('invalid aiJob.policySnapshot')
    }
  }
  const directLanguage = body.outputLanguage === undefined ? undefined : outputLanguageOf(body.outputLanguage, 'aiJob.outputLanguage')
  const snapshotLanguage = policySnapshot?.outputLanguage === undefined ? undefined : outputLanguageOf(policySnapshot.outputLanguage, 'aiJob.policySnapshot.outputLanguage')
  if (directLanguage !== undefined && snapshotLanguage !== undefined && directLanguage !== snapshotLanguage) {
    throw new Error('conflicting aiJob.outputLanguage')
  }
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : body.schemaVersion, 'aiJob.schemaVersion', false),
    aiJobId: asText(body.aiJobId ?? body.id, 'aiJob.aiJobId'),
    projectId: asText(body.projectId, 'aiJob.projectId'),
    scanId: optionalText(body.scanId),
    artifactDigest: optionalText(body.artifactDigest),
    role,
    providerId: optionalText(body.providerId),
    model: optionalText(body.model),
    status: asText(body.status, 'aiJob.status'),
    createdAt: asText(body.createdAt, 'aiJob.createdAt'),
    updatedAt: optionalText(body.updatedAt),
    errorCode: optionalText(body.errorCode),
    outputLanguage: directLanguage ?? snapshotLanguage
  }
}

export const parseAuditRun = (value: unknown): AuditRunDto => {
  if (!isRecord(value)) throw new Error('invalid audit run response')
  const version = schemaVersion(value.schemaVersion, 'auditRun.schemaVersion')
  const scan = parseScan(value.scan)
  const preAnalysisJob = parseAiJob(value.preAnalysisJob)
  const projectId = asText(value.projectId, 'auditRun.projectId')
  const scanId = asText(value.scanId, 'auditRun.scanId')
  const artifactDigest = asText(value.artifactDigest, 'auditRun.artifactDigest')
  if (scan.projectId !== projectId || scan.scanId !== scanId || scan.artifactDigest !== artifactDigest
      || preAnalysisJob.projectId !== projectId || preAnalysisJob.scanId !== scanId
      || preAnalysisJob.role !== 'PRE_ANALYSIS') {
    throw new Error('invalid audit run scope')
  }
  return {
    schemaVersion: version,
    auditRunId: asText(value.auditRunId, 'auditRun.auditRunId'),
    projectId,
    artifactDigest,
    scanId,
    status: asText(value.status, 'auditRun.status'),
    scan,
    preAnalysisJob
  }
}

export const parseAiJobEvent = (value: unknown): AiJobEventDto => {
  if (!isRecord(value)) throw new Error('invalid AI job event response')
  const sequence = asSafeInteger(value.sequence, 'aiJobEvent.sequence', 1, 128)
  const stage = asText(value.stage, 'aiJobEvent.stage')
  const status = asText(value.status, 'aiJobEvent.status') as AiJobEventStatus
  if (!/^[A-Z0-9_]{1,64}$/.test(stage)
      || !['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED'].includes(status)) {
    throw new Error('invalid AI job event code field')
  }
  const boundedOptionalText = (field: string, maxLength: number): string | undefined => {
    const text = strictOptionalText(value[field], `aiJobEvent.${field}`)
    if (text !== undefined && (text.length > maxLength || /[\u0000-\u001f\u007f-\u009f]/.test(text))) {
      throw new Error(`invalid aiJobEvent.${field}`)
    }
    return text
  }
  const boundedRequiredText = (field: string, maxLength: number): string => {
    const text = asText(value[field], `aiJobEvent.${field}`)
    if (text.length > maxLength || /[\u0000-\u001f\u007f-\u009f]/.test(text)) {
      throw new Error(`invalid aiJobEvent.${field}`)
    }
    return text
  }
  const aiJobId = boundedRequiredText('aiJobId', 128)
  const projectId = boundedRequiredText('projectId', 128)
  const providerRequestSummary = boundedOptionalText('providerRequestSummary', 2048)
  const providerResultSummary = boundedOptionalText('providerResultSummary', 2048)
  const toolCallName = boundedOptionalText('toolCallName', 128)
  const toolArgumentsSummary = boundedOptionalText('toolArgumentsSummary', 1024)
  const toolResultStatus = boundedOptionalText('toolResultStatus', 64)
  const modelInferenceSummary = strictOptionalText(value.modelInferenceSummary, 'aiJobEvent.modelInferenceSummary')
  if (modelInferenceSummary !== undefined
      && (modelInferenceSummary.length > 16_384
        || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(modelInferenceSummary))) {
    throw new Error('invalid aiJobEvent.modelInferenceSummary')
  }
  const failureDiagnostic = boundedOptionalText('failureDiagnostic', 1024)
  if (toolCallName !== undefined && !/^[A-Za-z0-9_-]{1,128}$/.test(toolCallName)
      || toolResultStatus !== undefined && !/^[A-Z0-9_]{1,64}$/.test(toolResultStatus)
      || status === 'FAILED' && failureDiagnostic === undefined) {
    throw new Error('invalid AI job event detail')
  }
  const createdAt = asText(value.createdAt, 'aiJobEvent.createdAt')
  if (createdAt.length > 64 || Number.isNaN(Date.parse(createdAt))) throw new Error('invalid aiJobEvent.createdAt')
  return {
    schemaVersion: schemaVersion(value.schemaVersion, 'aiJobEvent.schemaVersion'),
    aiJobId,
    sequence,
    projectId,
    stage,
    status,
    providerRequestSummary,
    providerResultSummary,
    toolCallName,
    toolArgumentsSummary,
    toolResultStatus,
    modelInferenceSummary,
    failureDiagnostic,
    createdAt
  }
}

export const parseAiJobEvents = (value: unknown): AiJobEventDto[] => {
  if (!isRecord(value) || !Array.isArray(value.aiJobEvents)) throw new Error('invalid AI job events response')
  schemaVersion(value.schemaVersion, 'aiJobEvents.schemaVersion')
  const aiJobId = asText(value.aiJobId, 'aiJobEvents.aiJobId')
  const projectId = asText(value.projectId, 'aiJobEvents.projectId')
  if (value.aiJobEvents.length > 128) throw new Error('invalid aiJobEvents bound')
  return value.aiJobEvents.map((item, index) => {
    const event = parseAiJobEvent(item)
    if (event.aiJobId !== aiJobId || event.projectId !== projectId || event.sequence !== index + 1) {
      throw new Error('invalid AI job event scope or order')
    }
    return event
  })
}

export const parseScanEvent = (value: unknown, eventName?: string): ScanEvent => {
  if (!isRecord(value)) throw new Error('invalid scan event')
  const eventType = value.eventType ?? eventName
  // The Java SSE writer keeps the scope in a nested `context` object while
  // the public contract also permits flattened fields. Accept both forms,
  // but require the scoped values before handing an event to the UI.
  const context = isRecord(value.context) ? value.context : {}
  const projectId = value.projectId ?? context.projectId
  const artifactDigest = value.artifactDigest ?? context.artifactDigest
  const scanId = value.scanId ?? context.scanId
  const taskId = value.taskId ?? context.taskId
  const payload = value.payload === undefined ? {} : value.payload
  const eventSchema = typeof value.schemaVersion === 'number' ? value.schemaVersion : NaN
  if (!Number.isSafeInteger(eventSchema) || !supportedEventSchemaVersions.has(eventSchema)) throw new Error('unsupported event.schemaVersion')
  return {
    eventId: asText(value.eventId ?? value.id, 'event.eventId'),
    eventType: asText(eventType, 'event.eventType'),
    schemaVersion: eventSchema,
    occurredAt: asText(value.occurredAt, 'event.occurredAt'),
    projectId: asText(projectId, 'event.projectId'),
    artifactDigest: asText(artifactDigest, 'event.artifactDigest'),
    scanId: asText(scanId, 'event.scanId'),
    taskId: optionalText(taskId),
    idempotencyKey: typeof value.idempotencyKey === 'string'
      ? value.idempotencyKey
      : isRecord(value.idempotencyKey) && typeof value.idempotencyKey.scope === 'string' && typeof value.idempotencyKey.value === 'string'
        ? { scope: value.idempotencyKey.scope, value: value.idempotencyKey.value }
        : undefined,
    payload,
    context: isRecord(value.context)
      ? { projectId: asText(context.projectId, 'event.context.projectId'), artifactDigest: asText(context.artifactDigest, 'event.context.artifactDigest'), scanId: asText(context.scanId, 'event.context.scanId'), taskId: optionalText(context.taskId) }
      : undefined
  }

}

const demoSnapshot: DashboardSnapshot = {
  schemaVersion: 1,
  projectId: 'project-01',
  scanId: 'scan-07f2',
  dependencyMode: 'MOCK',
  entries: [
    { id: 'e-01', route: '/api/upload', method: 'POST', module: 'attachment', protocol: 'HTTP', precondition: '登录用户', status: 'DYNAMIC_SUSPECTED', coverage: 86 },
    { id: 'e-02', route: '/api/info', method: 'GET', module: 'diagnostics', protocol: 'HTTP', precondition: '同租户', status: 'VERIFIED', coverage: 94 },
    { id: 'e-03', route: '/api/run', method: 'POST', module: 'executor', protocol: 'HTTP', precondition: 'ROLE_ADMIN', status: 'STATIC_INFERRED', coverage: 61 },
    { id: 'e-04', route: '/ws/events', method: 'CONNECT', module: 'events', protocol: 'WebSocket', precondition: '未探索', status: 'UNREACHED', coverage: 0 }
  ],
  findings: [
    { id: 'f-01', title: '上传路径可控', severity: 'high', status: 'VERIFIED', entry: '/api/upload', sink: 'FileOutputStream', dependency: 'attachment.path', evidence: 12, hypothesisId: 'hyp-demo-df', securityProperty: 'DATAFLOW' },
    { id: 'f-02', title: '服务器路径信息泄露', severity: 'medium', status: 'VERIFIED', entry: '/api/info', sink: 'HTTP response', dependency: 'filesystem', evidence: 7 },
    { id: 'f-03', title: '文件内容进入执行器', severity: 'critical', status: 'DYNAMIC_SUSPECTED', entry: '/api/run', sink: 'ProcessBuilder', dependency: 'ROLE_ADMIN', evidence: 4 }
  ],
  hypotheses: [
    {
      schemaVersion: 1,
      hypothesisId: 'hyp-demo-df',
      scanId: 'scan-07f2',
      securityProperty: 'DATAFLOW',
      family: 'DATAFLOW',
      lifecycle: 'CANDIDATE',
      detectorVersion: 'demo/0.1',
      supportingEvidenceRefs: [],
      contradictingEvidenceRefs: [],
      coverageGapRefs: [],
      source: 'param:filename',
      effect: 'FileOutputStream'
    }
  ],
  paths: [],
  pathRuns: [],
  sqlExperimentCards: [],
  experimentPlans: [],
  experimentShapes: [],
  analysisPacks: [],
  probeBudget: { maxProbes: 0, plannedProbes: 0, unreachedEntries: 0, strategy: '', entryTrackPlans: [] },
  rankedSinks: [],
  ledgerDiff: { newlyMatched: [], regressions: [], unchangedCount: 0, coverageDelta: 0, summary: '' },
  verifiedFindings: [],
  path: [
    { label: 'POST /api/upload', detail: 'filename = ${safe-probe}', kind: 'entry', state: 'done' },
    { label: 'UploadService.save', detail: 'URLDecode → path concat', kind: 'transform', state: 'done' },
    { label: 'attachment.path', detail: 'table=attachment · mode=MOCK', kind: 'dependency', state: 'done' },
    { label: '路径限制分支', detail: 'synthetic user · branch covered', kind: 'branch', state: 'active' },
    { label: 'FileOutputStream', detail: '副作用已在临时工作区重放', kind: 'sink', state: 'active' }
  ]
}

const jsonHeaders = (token?: string): HeadersInit => {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  return headers
}

let idempotencySequence = 0
const generatedIdempotencyKey = (): string => {
  const randomUuid = globalThis.crypto?.randomUUID?.()
  if (randomUuid) return `gui-${randomUuid}`
  idempotencySequence = (idempotencySequence + 1) % 1_000_000
  return `gui-${Date.now().toString(36)}-${idempotencySequence.toString(36)}`
}

const idempotencyKeyFor = (candidate?: string): string => {
  if (candidate === undefined) return generatedIdempotencyKey()
  if (typeof candidate !== 'string' || candidate.trim() === '' || candidate.length > 256 || /\s/.test(candidate)) throw new Error('invalid idempotencyKey')
  return candidate
}

const mutationHeaders = (token: string | undefined, idempotencyKey: string): HeadersInit => ({
  ...jsonHeaders(token),
  'Content-Type': 'application/json',
  'Idempotency-Key': idempotencyKey
})

type FetchLike = typeof fetch

const sha256Hex = async (blob: Blob): Promise<string> => {
  if (!globalThis.crypto?.subtle) throw new Error('当前浏览器不支持 Web Crypto SHA-256')
  const digest = await globalThis.crypto.subtle.digest('SHA-256', await blob.arrayBuffer())
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

const boundedErrorText = async (response: Response, maxBytes = 8192): Promise<string | undefined> => {
  const declaredLength = Number(response.headers.get('content-length'))
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) return undefined
  if (!response.body) {
    const text = await response.text()
    return text.length <= maxBytes ? text : undefined
  }
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let total = 0
  let text = ''
  try {
    while (true) {
      const part = await reader.read()
      if (part.done) break
      total += part.value.byteLength
      if (total > maxBytes) {
        await reader.cancel()
        return undefined
      }
      text += decoder.decode(part.value, { stream: true })
    }
    text += decoder.decode()
    return text
  } catch {
    return undefined
  } finally {
    reader.releaseLock()
  }
}

const safeErrorField = (value: unknown, maxLength: number): string | undefined => {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || /[\u0000-\u001f\u007f-\u009f]/.test(value)) return undefined
  return value
}

const parseAllowlistedError = async (response: Response): Promise<{ code?: string; message?: string; requestId?: string }> => {
  if (response.status < 400 || response.status >= 500
      || !response.headers.get('content-type')?.toLowerCase().includes('application/json')) return {}
  const text = await boundedErrorText(response)
  if (!text) return {}
  try {
    const value: unknown = JSON.parse(text)
    if (!isRecord(value)) return {}
    const code = safeErrorField(value.code, 64)
    const message = safeErrorField(value.message, 512)
    const requestId = safeErrorField(value.requestId, 128)
    return {
      code: code && /^[A-Za-z0-9_.-]+$/.test(code) ? code : undefined,
      message,
      requestId: requestId && /^[A-Za-z0-9_.:-]+$/.test(requestId) ? requestId : undefined
    }
  } catch {
    return {}
  }
}

const uploadTask = (promise: Promise<ArtifactDto>, controller: AbortController): UploadTask =>
  Object.assign(promise, { cancel: () => controller.abort() })

export class HttpSentinelApi implements SentinelApi {
  readonly mode: ApiMode = 'control-plane'
  private readonly fetchFn: FetchLike
  private readonly token?: string

  constructor(private readonly baseUrl: string, private readonly projectId = '', options: { token?: string; fetchFn?: FetchLike; fetch?: FetchLike } = {}) {
    // projectId is optional at construction: workspace home can list/create projects
    // before any workspace is selected. Per-project calls still require an explicit id.
    if (!baseUrl) throw new Error('Control Plane baseUrl is required')
    const fetchFn = options.fetchFn ?? options.fetch ?? fetch
    // Keep native fetch detached from this API instance. Calling a stored
    // browser fetch as this.fetchFn(...) gives it the wrong receiver and
    // Chrome rejects the call before any network request is sent.
    this.fetchFn = (input, init) => fetchFn(input, init)
    this.token = options.token ?? import.meta.env.VITE_API_TOKEN
  }

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/$/, '')}/${path.replace(/^\//, '')}`
  }

  private async request(path: string, init: RequestInit, operation: string): Promise<unknown> {
    let response: Response
    try {
      response = await this.fetchFn(this.url(path), init)
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw new UploadCancelledError()
      throw new ApiUnavailableError(operation, undefined, { cause: error })
    }
    if (response.ok === false || (typeof response.status === 'number' && response.status >= 400)) {
      // Only a small, allowlisted JSON shape from client/validation failures is
      // safe to render. HTML, 5xx diagnostics, and arbitrary fields are never
      // propagated.
      const detail = await parseAllowlistedError(response)
      if ([404, 405, 501, 502, 503, 504].includes(response.status)) throw new ApiUnavailableError(operation, response.status)
      const requestSuffix = detail.requestId ? `（请求 ${detail.requestId}）` : ''
      const codeSuffix = detail.code ? ` [${detail.code}]` : ''
      if (detail.code === 'AUTHORIZATION_REQUIRED') {
        throw new ApiRequestError(
          `本地授权令牌缺失或已失效${codeSuffix}${requestSuffix}。请用 Start-Veyrion.ps1 同时重启控制面与界面（不要只开前端）；启动器会把令牌写入 frontend/.env.local。`,
          response.status,
          detail.code,
          detail.requestId
        )
      }
      if (detail.code === 'DYNAMIC_TASK_BUSY') {
        throw new ApiRequestError(
          `该扫描仍有进行中的动态任务${codeSuffix}${requestSuffix}。请稍候任务结束，或在「审计执行」对「断网容器按轨动态观察」点重试（服务端会取消卡住的任务后再排队）。请求不会回退到演示数据。`,
          response.status,
          detail.code,
          detail.requestId
        )
      }
      throw new ApiRequestError(detail.message ? `${detail.message}${codeSuffix}${requestSuffix}` : `${operation} failed: ${response.status}`, response.status, detail.code, detail.requestId)
    }
    if (response.status === 204) return {}
    try {
      return await response.json()
    } catch (error) {
      throw new Error(`${operation} failed: invalid JSON response`, { cause: error })
    }
  }

  async loadDashboard(projectId = this.projectId, scanId?: string): Promise<DashboardSnapshot> {
    const query = scanId && scanId !== 'unscanned'
      ? `?scanId=${encodeURIComponent(asText(scanId, 'scanId'))}`
      : ''
    const body = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/dashboard${query}`, {
      credentials: 'include',
      headers: jsonHeaders(this.token)
    }, 'dashboard request')
    return parseDashboard(body)
  }

  async retryAuditStage(projectId: string, request: RetryAuditStageRequest): Promise<RetryAuditStageResult> {
    const body: Record<string, unknown> = {
      scanId: request.scanId,
      stage: request.stage,
      authorized: true
    }
    if (request.aiAuthorized) body.aiAuthorized = true
    if (request.outputLanguage) body.outputLanguage = request.outputLanguage
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/audit-stage-retries`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: JSON.stringify(body)
    }, 'retry audit stage')
    if (!isRecord(response)) throw new Error('invalid audit stage retry response')
    return {
      schemaVersion: schemaVersion(response.schemaVersion, 'retry.schemaVersion'),
      projectId: asText(response.projectId, 'retry.projectId'),
      scanId: asText(response.scanId, 'retry.scanId'),
      stage: asText(response.stage, 'retry.stage'),
      pipelineArmed: asBoolean(response.pipelineArmed, 'retry.pipelineArmed'),
      aiJob: response.aiJob === undefined ? undefined : parseAiJob(response.aiJob),
      dynamicTask: response.dynamicTask === undefined ? undefined : parseDynamicTask(response.dynamicTask)
    }
  }

  async listProjects(): Promise<ProjectDto[]> {
    const response = await this.request('projects', { credentials: 'include', headers: jsonHeaders(this.token) }, 'list projects')
    return parseList(response, 'projects', parseProject)
  }

  async getProject(projectId: string): Promise<ProjectDto> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'get project')
    return parseProject(response)
  }

  async createProject(request: CreateProjectRequest | string): Promise<ProjectDto> {
    const body: CreateProjectRequest = typeof request === 'string' ? { name: request } : request
    if (!body || typeof body.name !== 'string' || body.name.trim() === '') throw new Error('project name is required')
    const { idempotencyKey, ...wireBody } = body
    const requestKey = idempotencyKeyFor(idempotencyKey)
    const response = await this.request('projects', {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, requestKey), body: JSON.stringify(wireBody)
    }, 'create project')
    return parseProject(response)
  }

  async updateProject(projectId: string, request: UpdateProjectRequest): Promise<ProjectDto> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'update project')
    return parseProject(response)
  }

  async deleteProject(projectId: string): Promise<void> {
    await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete project')
  }

  async listArtifacts(projectId: string): Promise<ArtifactDto[]> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifacts`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'list artifacts')
    return parseList(response, 'artifacts', parseArtifact)
  }

  async registerArtifact(request: RegisterArtifactRequest | string, projectId = this.projectId): Promise<ArtifactDto> {
    const body: RegisterArtifactRequest = typeof request === 'string' ? { path: request } : request
    if (!body || typeof body.path !== 'string' || body.path.trim() === '') throw new Error('artifact path is required')
    const { idempotencyKey, ...wireBody } = body
    const requestKey = idempotencyKeyFor(idempotencyKey)
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifacts`, {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, requestKey), body: JSON.stringify(wireBody)
    }, 'register artifact')
    return parseArtifact(response)
  }

  uploadArtifact(file: File, projectId: string, onProgress: UploadProgressHandler): UploadTask {
    const controller = new AbortController()
    const promise = this.performArtifactUpload(file, projectId, onProgress, controller.signal)
    return uploadTask(promise, controller)
  }

  private async performArtifactUpload(file: File, projectId: string, onProgress: UploadProgressHandler, signal: AbortSignal): Promise<ArtifactDto> {
    if (!(file instanceof File)) throw new Error('请选择要上传的制品文件')
    const type = file.name.split('.').pop()?.toUpperCase()
    if (type !== 'JAR' && type !== 'WAR' && type !== 'CLASS') throw new Error('仅支持 .jar、.war 或 .class 文件')
    if (file.size <= 0) throw new Error('不能上传空文件')
    if (file.size > MAX_BROWSER_HASH_BYTES) throw new Error(`文件超过浏览器摘要上限 ${MAX_BROWSER_HASH_BYTES / 1024 / 1024} MiB；请使用高级/兼容方式登记`)
    if (typeof onProgress !== 'function') throw new Error('upload progress handler is required')

    let uploadId: string | undefined
    let completed = false
    try {
      if (signal.aborted) throw new UploadCancelledError()
      onProgress(0)
      const fileSha256 = await sha256Hex(file)
      if (signal.aborted) throw new UploadCancelledError()
      const initialized = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifact-uploads`, {
        method: 'POST',
        credentials: 'include',
        headers: mutationHeaders(this.token, generatedIdempotencyKey()),
        body: JSON.stringify({ fileName: file.name, sizeBytes: file.size, sha256: fileSha256 }),
        signal
      }, 'initialize artifact upload')
      const session = unwrap(initialized, 'upload')
      if (!isRecord(session)) throw new Error('invalid artifact upload response')
      uploadId = asText(session.uploadId, 'upload.uploadId')
      if (session.recommendedChunkBytes !== undefined && asSafeInteger(session.recommendedChunkBytes, 'upload.recommendedChunkBytes', 1) !== ARTIFACT_UPLOAD_CHUNK_BYTES) {
        throw new Error('unsupported artifact upload chunk size')
      }
      const uploadPath = `projects/${encodeURIComponent(projectId)}/artifact-uploads/${encodeURIComponent(uploadId)}`

      for (let offset = 0; offset < file.size; offset += ARTIFACT_UPLOAD_CHUNK_BYTES) {
        if (signal.aborted) throw new UploadCancelledError()
        const chunk = file.slice(offset, Math.min(offset + ARTIFACT_UPLOAD_CHUNK_BYTES, file.size))
        const chunkSha256 = await sha256Hex(chunk)
        await this.request(`${uploadPath}?offset=${offset}`, {
          method: 'PUT',
          credentials: 'include',
          headers: {
            ...jsonHeaders(this.token),
            'Content-Type': 'application/octet-stream',
            'X-Chunk-SHA256': chunkSha256
          },
          body: chunk,
          signal
        }, 'upload artifact chunk')
        onProgress(Math.min(99, Math.round(((offset + chunk.size) / file.size) * 100)))
      }

      const result = await this.request(`${uploadPath}/complete`, {
        method: 'POST',
        credentials: 'include',
        headers: mutationHeaders(this.token, generatedIdempotencyKey()),
        body: JSON.stringify({ authorized: true }),
        signal
      }, 'complete artifact upload')
      completed = true
      onProgress(100)
      return parseArtifact(result)
    } finally {
      if (uploadId && !completed) {
        try {
          await this.request(`projects/${encodeURIComponent(projectId)}/artifact-uploads/${encodeURIComponent(uploadId)}`, {
            method: 'DELETE',
            credentials: 'include',
            headers: mutationHeaders(this.token, generatedIdempotencyKey())
          }, 'cancel artifact upload')
        } catch {
          // Cancellation is best-effort and must not hide the original error.
        }
      }
    }
  }

  async updateArtifact(projectId: string, artifactId: string, request: UpdateArtifactRequest): Promise<ArtifactDto> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifacts/${encodeURIComponent(asText(artifactId, 'artifactId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'update artifact')
    return parseArtifact(response)
  }

  async deleteArtifact(projectId: string, artifactId: string): Promise<void> {
    await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifacts/${encodeURIComponent(asText(artifactId, 'artifactId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete artifact')
  }

  async listScans(projectId: string): Promise<ScanDto[]> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/scans`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'list scans')
    return parseList(response, 'scans', parseScan)
  }

  async createScan(request: CreateScanRequest | string = {}, projectId = this.projectId): Promise<ScanDto> {
    const normalizedRequest: CreateScanRequest = typeof request === 'string' ? { artifactDigest: request } : request
    const { policy, idempotencyKey, ...scanFields } = normalizedRequest
    const requestKey = idempotencyKeyFor(idempotencyKey)
    const body: Record<string, unknown> = { ...scanFields }
    // Keep the wire contract explicit. Unknown values from a policy editor
    // are not forwarded to the server and cannot widen its authorization or
    // sandbox policy by accident.
    if (policy) {
      const policyKeys = ['authorized', 'networkMode', 'dangerousActionMode', 'networkAllowlist', 'maxWallClockSeconds', 'maxMemoryBytes', 'maxDiskBytes'] as const
      for (const key of policyKeys) if (body[key] === undefined && policy[key] !== undefined) body[key] = policy[key]
    }
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/scans`, {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, requestKey), body: JSON.stringify(body)
    }, 'create scan')
    return parseScan(response)
  }

  async startAudit(projectId: string, request: StartAuditRequest): Promise<AuditRunDto> {
    const { policy, idempotencyKey, ...auditFields } = request
    const body: Record<string, unknown> = { ...auditFields }
    if (policy) {
      const policyKeys = ['authorized', 'networkMode', 'dangerousActionMode', 'networkAllowlist', 'maxWallClockSeconds', 'maxMemoryBytes', 'maxDiskBytes'] as const
      for (const key of policyKeys) if (body[key] === undefined && policy[key] !== undefined) body[key] = policy[key]
    }
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/audit-runs`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, idempotencyKeyFor(idempotencyKey)),
      body: JSON.stringify(body)
    }, 'start audit')
    return parseAuditRun(response)
  }

  async createDynamicTask(scanId: string): Promise<DynamicTaskDto> {
    const response = await this.request(`scans/${encodeURIComponent(asText(scanId, 'scanId'))}/dynamic-tasks`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: JSON.stringify({ authorized: true })
    }, 'create trusted Docker artifact task')
    return parseDynamicTask(response)
  }

  async listDynamicTasks(scanId: string): Promise<DynamicTaskDto[]> {
    const response = await this.request(`scans/${encodeURIComponent(asText(scanId, 'scanId'))}/dynamic-tasks`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'list dynamic tasks')
    return parseList(response, 'dynamicTasks', parseDynamicTask)
  }

  async replayFinding(findingId: string): Promise<FindingReplayDto> {
    const response = await this.request(`findings/${encodeURIComponent(asText(findingId, 'findingId'))}/replay`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: JSON.stringify({ authorized: true })
    }, 'replay finding')
    return parseFindingReplay(response)
  }

  async focusEntryProbe(scanId: string, entryId: string, body?: FocusEntryProbeRequest): Promise<FocusEntryProbeDto> {
    const payload: FocusEntryProbeRequest = { ...body, authorized: true }
    const response = await this.request(
      `scans/${encodeURIComponent(asText(scanId, 'scanId'))}/entries/${encodeURIComponent(asText(entryId, 'entryId'))}/focus-probe`,
      {
        method: 'POST',
        credentials: 'include',
        headers: mutationHeaders(this.token, generatedIdempotencyKey()),
        body: JSON.stringify(payload)
      },
      'focus entry probe'
    )
    return parseFocusEntryProbe(response)
  }

  async replaySqlExperimentCard(scanId: string, cardId: string): Promise<FocusEntryProbeDto> {
    const response = await this.request(
      `scans/${encodeURIComponent(asText(scanId, 'scanId'))}/experiment-cards/${encodeURIComponent(asText(cardId, 'cardId'))}/replay`,
      {
        method: 'POST',
        credentials: 'include',
        headers: mutationHeaders(this.token, generatedIdempotencyKey()),
        body: JSON.stringify({ authorized: true })
      },
      'replay sql experiment card'
    )
    return parseFocusEntryProbe(response)
  }

  async updateScan(scanId: string, request: UpdateScanRequest): Promise<ScanDto> {
    const response = await this.request(`scans/${encodeURIComponent(asText(scanId, 'scanId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'update scan')
    return parseScan(response)
  }

  async deleteScan(scanId: string): Promise<void> {
    await this.request(`scans/${encodeURIComponent(asText(scanId, 'scanId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete scan')
  }

  async listProviders(): Promise<ProviderDto[]> {
    const response = await this.request('providers', { credentials: 'include', headers: jsonHeaders(this.token) }, 'list providers')
    return parseList(response, 'providers', parseProvider)
  }

  async createProvider(request: SaveProviderRequest): Promise<ProviderDto> {
    const response = await this.request('providers', {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'create provider')
    return parseProvider(response)
  }

  async updateProvider(providerId: string, request: Partial<SaveProviderRequest>): Promise<ProviderDto> {
    const response = await this.request(`providers/${encodeURIComponent(asText(providerId, 'providerId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'update provider')
    return parseProvider(response)
  }

  async deleteProvider(providerId: string): Promise<void> {
    await this.request(`providers/${encodeURIComponent(asText(providerId, 'providerId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete provider')
  }

  async refreshProviderModels(providerId: string): Promise<ProviderModelInventoryDto> {
    const response = await this.request(`providers/${encodeURIComponent(asText(providerId, 'providerId'))}/models/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: '{}'
    }, 'refresh provider models')
    return parseProviderModelInventory(response)
  }

  async listRoleAssignments(projectId: string): Promise<RoleAssignmentDto[]> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/role-assignments`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'list role assignments')
    return parseList(response, 'roleAssignments', parseRoleAssignment)
  }

  async saveRoleAssignment(projectId: string, role: AiRole, request: SaveRoleAssignmentRequest): Promise<RoleAssignmentDto> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/role-assignments/${encodeURIComponent(role)}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'save role assignment')
    return parseRoleAssignment(response)
  }

  async deleteRoleAssignment(projectId: string, role: AiRole): Promise<void> {
    await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/role-assignments/${encodeURIComponent(role)}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete role assignment')
  }

  async listAiJobs(projectId: string): Promise<AiJobDto[]> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/ai-jobs`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'list ai jobs')
    return parseList(response, 'aiJobs', parseAiJob)
  }

  async createAiJob(projectId: string, request: CreateAiJobRequest): Promise<AiJobDto> {
    const body: CreateAiJobRequest = {
      role: request.role,
      authorized: request.authorized,
      scanId: request.scanId,
      outputLanguage: request.outputLanguage
    }
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/ai-jobs`, {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(body)
    }, 'create ai job')
    return parseAiJob(response)
  }

  async getAiJob(aiJobId: string): Promise<AiJobDto> {
    const response = await this.request(`ai-jobs/${encodeURIComponent(asText(aiJobId, 'aiJobId'))}`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'get ai job')
    return parseAiJob(response)
  }

  async listAiJobEvents(aiJobId: string): Promise<AiJobEventDto[]> {
    const response = await this.request(`ai-jobs/${encodeURIComponent(asText(aiJobId, 'aiJobId'))}/events`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'list AI job events')
    return parseAiJobEvents(response)
  }

  async updateAiJob(aiJobId: string, action: 'cancel' | 'retry'): Promise<AiJobDto> {
    const response = await this.request(`ai-jobs/${encodeURIComponent(asText(aiJobId, 'aiJobId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify({ action })
    }, 'update ai job')
    return parseAiJob(response)
  }

  async deleteAiJob(aiJobId: string): Promise<void> {
    await this.request(`ai-jobs/${encodeURIComponent(asText(aiJobId, 'aiJobId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete ai job')
  }

  async getEntries(projectId = this.projectId, scanId?: string): Promise<EntryDto[]> {
    const query = scanId ? `?scanId=${encodeURIComponent(asText(scanId, 'scanId'))}` : ''
    const response = await this.request(`projects/${encodeURIComponent(projectId)}/entries${query}`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'entries request')
    return parseEntries(response)
  }

  async getScan(scanId: string): Promise<ScanDto> {
    const id = asText(scanId, 'scanId')
    const response = await this.request(`scans/${encodeURIComponent(id)}`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'scan request')
    return parseScan(response)
  }

  async getScanCoverage(scanId: string): Promise<CoverageMatrixDto> {
    const id = asText(scanId, 'scanId')
    const response = await this.request(`scans/${encodeURIComponent(id)}/coverage`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'scan coverage request')
    return parseCoverageMatrix(response)
  }

  async getEvidenceGraph(scanId: string): Promise<EvidenceGraphDto> {
    const id = asText(scanId, 'scanId')
    const response = await this.request(`scans/${encodeURIComponent(id)}/evidence-graph`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'evidence graph request')
    return parseEvidenceGraph(response)
  }

  async getScanHypotheses(scanId: string): Promise<ScanHypothesesDto> {
    const id = asText(scanId, 'scanId')
    const response = await this.request(`scans/${encodeURIComponent(id)}/hypotheses`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'scan hypotheses request')
    return parseScanHypotheses(response)
  }

  async getEvidence(evidenceId: string): Promise<EvidenceDto> {
    const id = asText(evidenceId, 'evidenceId')
    const response = await this.request(`evidence/${encodeURIComponent(id)}`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'evidence request')
    return parseEvidence(response)
  }

  subscribe(scanId: string, onEvent: (event: ScanEvent) => void, options: SubscribeOptions = {}): () => void {
    const id = asText(scanId, 'scanId')
    // EventSource is intentionally cookie/credential based. Browsers do not
    // allow custom Authorization headers on EventSource; deployments should
    // use an HttpOnly same-origin session for the SSE endpoint.
    if (typeof EventSource === 'undefined') {
      const error = new Error('SSE is unavailable in this browser')
      options.onError?.(error)
      return () => undefined
    }
    const source = new EventSource(this.url(`scans/${encodeURIComponent(id)}/events`), { withCredentials: true })
    let closed = false
    let reconciling = false
    // EventSource may replay the last event after a reconnect, and a server
    // can legally emit both a named event and a default message. Keep a
    // bounded idempotency window so the UI does not double-count findings.
    const seenEventIds = new Set<string>()
    const seenOrder: string[] = []
    const reconcile = () => {
      if (closed || reconciling) return
      reconciling = true
      void this.getScan(id).then((scan) => options.onReconcile?.(scan)).catch((error) => options.onError?.(error)).finally(() => { reconciling = false })
    }
    const handle = (message: MessageEvent<unknown>, eventName?: string) => {
      try {
        // MessageEvent.data is normally a string. Accept an object for test
        // adapters and browser polyfills without weakening validation.
        const decoded = typeof message.data === 'string' ? JSON.parse(message.data) as unknown : message.data
        const inferredName = eventName ?? (typeof message.type === 'string' && message.type !== 'message' ? message.type : undefined)
        const event = parseScanEvent(decoded, inferredName)
        if (seenEventIds.has(event.eventId)) return
        seenEventIds.add(event.eventId)
        seenOrder.push(event.eventId)
        if (seenOrder.length > 512) {
          const expired = seenOrder.shift()
          if (expired) seenEventIds.delete(expired)
        }
        onEvent(event)
        reconcile()
        if (event.eventType === 'ScanCompleted' || event.eventType === 'TaskStopped') {
          // The server closes finite replay streams after a terminal event;
          // close the browser side as well so EventSource does not reconnect
          // forever and re-fetch an already immutable scan.
          closed = true
          source.close()
        }
      } catch (error) {
        options.onError?.(error)
      }
    }
    source.onmessage = (message) => handle(message)
    source.onopen = () => reconcile()
    source.onerror = (error) => {
      if (closed) return
      // EventSource automatically retries while OPEN/CONNECTING. Reconcile on
      // each error so a terminal state is not hidden if the final event was lost.
      options.onError?.(error)
      reconcile()
    }
    const eventNames: ScanEventType[] = ['ScanCreated', 'TaskLeased', 'TraceCommitted', 'FindingUpdated', 'TaskStopped', 'ScanCompleted']
    const listeners: Array<{ name: string; listener: EventListener }> = []
    if (typeof source.addEventListener === 'function') {
      for (const name of eventNames) {
        const listener: EventListener = (event) => handle(event as MessageEvent<unknown>, name)
        source.addEventListener(name, listener)
        listeners.push({ name, listener })
      }
    }
    return () => {
      closed = true
      if (typeof source.removeEventListener === 'function') {
        for (const { name, listener } of listeners) source.removeEventListener(name, listener)
      }
      source.close()
    }
  }
}

export class MockSentinelApi implements SentinelApi {
  readonly mode: ApiMode = 'demo'
  private unavailable(operation: string): never {
    throw new ApiUnavailableError(`${operation} (demo adapter)`)
  }

  async loadDashboard(_projectId?: string, _scanId?: string): Promise<DashboardSnapshot> {
    return structuredClone(demoSnapshot)
  }

  async retryAuditStage(): Promise<RetryAuditStageResult> {
    return this.unavailable('retry audit stage')
  }

  async listProjects(): Promise<ProjectDto[]> {
    return [{ schemaVersion: 1, projectId: 'project-01', name: 'Demo workspace', createdAt: new Date(0).toISOString() }]
  }

  async getProject(projectId: string): Promise<ProjectDto> {
    const project = (await this.listProjects()).find((item) => item.projectId === projectId)
    if (!project) return this.unavailable('get project')
    return project
  }

  async createProject(request: CreateProjectRequest | string): Promise<ProjectDto> {
    const name = typeof request === 'string' ? request : request.name
    return { schemaVersion: 1, projectId: 'demo-project', name, createdAt: new Date(0).toISOString() }
  }

  async updateProject(): Promise<ProjectDto> { return this.unavailable('update project') }
  async deleteProject(): Promise<void> { return this.unavailable('delete project') }
  async listArtifacts(): Promise<ArtifactDto[]> {
    return [{
      schemaVersion: 1,
      artifactId: 'demo-artifact',
      type: 'JAR',
      artifactDigest: '0'.repeat(64),
      sizeBytes: 1_048_576,
      staticOnly: true,
      verificationStatus: 'STATIC_INFERRED',
      registeredAt: new Date(0).toISOString(),
      projectId: 'project-01',
      originalFileName: 'demo-springblade-sample.jar',
      fileName: 'demo-springblade-sample.jar',
      displayName: 'demo-springblade-sample.jar'
    }]
  }

  async registerArtifact(request: RegisterArtifactRequest | string, _projectId?: string): Promise<ArtifactDto> {
    const path = typeof request === 'string' ? request : request.path
    const baseName = path.replace(/\\/g, '/').split('/').filter(Boolean).pop() || 'demo-sample.jar'
    return {
      schemaVersion: 1,
      artifactId: 'demo-artifact',
      type: 'JAR',
      artifactDigest: '0'.repeat(64),
      sizeBytes: 0,
      staticOnly: true,
      verificationStatus: 'STATIC_INFERRED',
      registeredAt: new Date(0).toISOString(),
      projectId: 'project-01',
      originalFileName: baseName,
      fileName: baseName,
      displayName: baseName
    }
  }

  uploadArtifact(): UploadTask {
    const controller = new AbortController()
    return uploadTask(Promise.reject(new ApiUnavailableError('artifact upload (demo adapter)')), controller)
  }

  async updateArtifact(): Promise<ArtifactDto> { return this.unavailable('update artifact') }
  async deleteArtifact(): Promise<void> { return this.unavailable('delete artifact') }
  async listScans(): Promise<ScanDto[]> { return [] }

  async createScan(_request: CreateScanRequest | string = {}, _projectId?: string): Promise<ScanDto> {
    return { schemaVersion: 1, scanId: 'scan-07f2', projectId: 'project-01', artifactDigest: '0'.repeat(64), status: 'COMPLETED', verificationStatus: 'STATIC_INFERRED', dependencyMode: 'MOCK', createdAt: new Date(0).toISOString(), updatedAt: new Date(0).toISOString(), evidenceRefs: [] }
  }

  async startAudit(projectId: string, _request: StartAuditRequest): Promise<AuditRunDto> {
    const scan = await this.createScan({}, projectId)
    return {
      schemaVersion: 1,
      auditRunId: 'audit-07f2',
      projectId,
      artifactDigest: scan.artifactDigest,
      scanId: scan.scanId,
      status: 'PRE_ANALYSIS_BLOCKED',
      scan,
      preAnalysisJob: {
        schemaVersion: 1,
        aiJobId: 'ai-job-demo',
        projectId,
        scanId: scan.scanId,
        artifactDigest: scan.artifactDigest,
        role: 'PRE_ANALYSIS',
        status: 'BLOCKED',
        createdAt: new Date(0).toISOString(),
        errorCode: 'DEMO_MODE_UNAVAILABLE'
      }
    }
  }

  async createDynamicTask(): Promise<DynamicTaskDto> { return this.unavailable('create dynamic artifact task') }
  async listDynamicTasks(): Promise<DynamicTaskDto[]> { return [] }
  async updateScan(): Promise<ScanDto> { return this.unavailable('update scan') }
  async deleteScan(): Promise<void> { return this.unavailable('delete scan') }
  async listProviders(): Promise<ProviderDto[]> { return [] }
  async createProvider(): Promise<ProviderDto> { return this.unavailable('create provider') }
  async updateProvider(): Promise<ProviderDto> { return this.unavailable('update provider') }
  async deleteProvider(): Promise<void> { return this.unavailable('delete provider') }
  async refreshProviderModels(): Promise<ProviderModelInventoryDto> { return this.unavailable('refresh provider models') }
  async listRoleAssignments(): Promise<RoleAssignmentDto[]> { return [] }
  async saveRoleAssignment(): Promise<RoleAssignmentDto> { return this.unavailable('save role assignment') }
  async deleteRoleAssignment(): Promise<void> { return this.unavailable('delete role assignment') }
  async listAiJobs(): Promise<AiJobDto[]> {
    return [{
      schemaVersion: 1,
      aiJobId: 'ai-job-demo-report',
      projectId: 'project-01',
      scanId: 'scan-07f2',
      artifactDigest: '0'.repeat(64),
      role: 'REPORT_GENERATION',
      status: 'COMPLETED',
      providerId: 'demo-provider',
      model: 'demo-report',
      outputLanguage: 'ZH_CN',
      createdAt: new Date(0).toISOString()
    }]
  }
  async createAiJob(): Promise<AiJobDto> { return this.unavailable('create ai job') }
  async getAiJob(): Promise<AiJobDto> { return this.unavailable('get ai job') }
  async listAiJobEvents(aiJobId: string): Promise<AiJobEventDto[]> {
    if (aiJobId !== 'ai-job-demo-report') return []
    return [{
      schemaVersion: 1,
      aiJobId,
      sequence: 1,
      projectId: 'project-01',
      stage: 'MODEL_INFERENCE',
      status: 'COMPLETED',
      createdAt: new Date(0).toISOString(),
      modelInferenceSummary: [
        '# 溯脉 · Veyrion 演示报告',
        '',
        '本页为**演示模式**最终报告主视图。结论均为受证据约束的模型推断，**不等于 VERIFIED**。',
        '',
        '## 摘要',
        '',
        '- 演示扫描 `scan-07f2` 含上传路径与信息泄露等发现样本。',
        '- PathRun / Sink 排序 / 对照账本等请通过审计结果子页面查看。',
        '- 动态确认若出现，仍为 MOCK SQL 证据，不得宣传为生产实库已证实。',
        '',
        '## 限制',
        '',
        '演示适配器不连接控制面；下载与重放能力可能不可用。'
      ].join('\n')
    }]
  }
  async updateAiJob(): Promise<AiJobDto> { return this.unavailable('update ai job') }
  async deleteAiJob(): Promise<void> { return this.unavailable('delete ai job') }

  async replayFinding(): Promise<FindingReplayDto> { return this.unavailable('replay finding') }

  async focusEntryProbe(): Promise<FocusEntryProbeDto> { return this.unavailable('focus entry probe') }
  async replaySqlExperimentCard(): Promise<FocusEntryProbeDto> { return this.unavailable('replay sql experiment card') }

  async getEntries(): Promise<EntryDto[]> {
    return (await this.loadDashboard()).entries
  }

  async getScan(_scanId: string): Promise<ScanDto> {
    return this.createScan()
  }

  async getScanCoverage(scanId: string): Promise<CoverageMatrixDto> {
    return {
      schemaVersion: 1,
      scanId,
      artifactUniverseSummary: {
        classCount: 0,
        methodCount: 0,
        fieldCount: 0,
        dependencyCount: 0,
        incomplete: true,
        note: 'DEMO_ONLY'
      },
      entryFamilies: [],
      callResolution: {
        DIRECT: 0,
        CHA: 0,
        UNRESOLVED: 0,
        unresolvedIsGap: true
      },
      detectors: [],
      dynamicExperiments: {
        pathRunCount: 0,
        effectiveAttemptCount: 0,
        unreachedCount: 0,
        stopReasonSamples: []
      },
      stopReasons: [],
      gaps: { unknown: 0, unresolved: 0, truncated: 0, unreached: 0, total: 0, countedAsCovered: false },
      honestyFlags: {
        neverTreatSuccessAsSafe: true,
        gapsNeverCountAsCovered: true,
        scanSuccessMeans: 'analysis_finished_not_safe'
      },
      checksum: '0'.repeat(64)
    }
  }

  async getEvidenceGraph(scanId: string): Promise<EvidenceGraphDto> {
    return {
      schemaVersion: 1,
      scanId,
      nodes: [{
        id: 'program:module:demo-lang:demo.mod',
        kind: 'PROGRAM',
        language: 'demo-lang',
        symbol: 'demo.mod',
        location: 'demo/mod.ts:1',
        evidenceRefs: ['ev-demo-1'],
        provenanceKind: 'FACT',
        extensions: { 'demo-lang': { note: 'unknown language extension sample' } }
      }],
      edges: [],
      truncated: false,
      maxNodes: 2000,
      maxEdges: 4000,
      nodeCount: 1,
      edgeCount: 0,
      compatibilityGap: {
        entryDtoCount: 0,
        entryNodeCount: 0,
        filteredEntryIds: [],
        notes: ['DEMO_ONLY']
      }
    }
  }

  async getScanHypotheses(scanId: string): Promise<ScanHypothesesDto> {
    const dashboard = await this.loadDashboard()
    const hypotheses = dashboard.hypotheses ?? []
    return { schemaVersion: 1, scanId, hypotheses, count: hypotheses.length }
  }

  async getEvidence(evidenceId: string): Promise<EvidenceDto> {
    return { schemaVersion: 1, evidenceId, kind: 'DEMO', source: 'demo', confidence: 0, summary: 'Demo evidence; not a real scan.', observedAt: new Date(0).toISOString(), toolVersion: 'demo', modelVersion: 'none', snapshotRef: 'demo://evidence' }
  }

  subscribe(_scanId: string, _onEvent: (event: ScanEvent) => void, _options?: SubscribeOptions): () => void {
    return () => undefined
  }
}

// Demo mode must be explicit. An unset flag now uses the real Control Plane
// adapter, preventing a production build from silently showing mock results.
const demoMode = import.meta.env.VITE_DEMO_MODE === 'true'
export const api: SentinelApi = demoMode
  ? new MockSentinelApi()
  : new HttpSentinelApi(import.meta.env.VITE_API_BASE_URL || '/api/v1', import.meta.env.VITE_PROJECT_ID || '')

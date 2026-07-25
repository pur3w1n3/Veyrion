/**
 * The only boundary between the GUI and the Java Control Plane.
 *
 * The UI deliberately consumes DTOs instead of Java records.  Runtime
 * validation here is important: a malformed response must never be rendered
 * as a verified security result.  The demo adapter uses the same UI-shaped
 * values, but is selected only when VITE_DEMO_MODE=true.
 */

export type VerificationStatus = 'VERIFIED' | 'DYNAMIC_SUSPECTED' | 'STATIC_INFERRED' | 'UNREACHED'
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
  path: PathStep[]
  paths: PathTrace[]
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
}
export type Artifact = ArtifactDto

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
  paths?: PathStep[]
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

export type AiRole = 'PRE_ANALYSIS' | 'PATH_EXPLORATION' | 'VULNERABILITY_TRIAGE' | 'REPORT_GENERATION'
export type RoleAssignmentDto = {
  schemaVersion: number
  projectId: string
  role: AiRole
  providerId: string
  model?: string
  updatedAt?: string
}
export type SaveRoleAssignmentRequest = {
  providerId: string
  model?: string
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
  loadDashboard(projectId?: string): Promise<DashboardSnapshot>
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
  getEvidence(evidenceId: string): Promise<EvidenceDto>
  subscribe(scanId: string, onEvent: (event: ScanEvent) => void, options?: SubscribeOptions): () => void
}

const statuses = new Set<VerificationStatus>(['VERIFIED', 'DYNAMIC_SUSPECTED', 'STATIC_INFERRED', 'UNREACHED'])
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
  if (value === undefined) return undefined
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
  if (value === undefined && optional) return []
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) throw new Error(`invalid ${field}`)
  return value as string[]
}

const evidenceRefsOf = (value: unknown, field: string, optional = true): EvidenceRef[] => {
  if (value === undefined && optional) return []
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
  if (value === 'resource' || value === 'database') return 'dependency'
  if (value === 'source') return 'entry'
  throw new Error('invalid path step kind')
}

const pathState = (value: unknown): PathStep['state'] => {
  if (value === 'blocked' || value === 'active' || value === 'done') return value
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

export const parseFinding = (item: unknown, context?: { schemaVersion?: number; projectId?: string; artifactDigest?: string; scanId?: string }): Finding => {
  if (!isRecord(item)) throw new Error('invalid finding')
  const refs = evidenceRefsOf(item.evidenceRefs, 'finding.evidenceRefs')
  const findingStatus = statusOf(item.verificationStatus ?? item.status, 'finding.verificationStatus')
  const evidenceValue = item.evidence === undefined
    ? item.evidenceCount === undefined ? refs.length : asSafeInteger(item.evidenceCount, 'finding.evidenceCount', 0)
    : asSafeInteger(item.evidence, 'finding.evidence', 0)
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
    confidence: item.confidence === undefined ? undefined : asFiniteNumber(item.confidence, 'finding.confidence', 0, 1)
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
    preconditions: listOfText(item.preconditions, 'dashboard.paths.preconditions'),
    steps: item.steps.map(parsePath),
    evidenceRefs: evidenceRefsOf(item.evidenceRefs, 'dashboard.paths.evidenceRefs'),
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
    path: pathValue.map(parsePath),
    paths: richPaths
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
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : undefined, 'artifact.schemaVersion'),
    artifactId: asText(body.artifactId ?? body.id, 'artifact.artifactId'),
    type: asText(body.type ?? body.artifactType, 'artifact.type').toUpperCase(),
    artifactType: asText(body.type ?? body.artifactType, 'artifact.type').toUpperCase(),
    artifactDigest: asText(body.artifactDigest ?? body.sha256, 'artifact.artifactDigest'),
    sizeBytes: asSafeInteger(body.sizeBytes, 'artifact.sizeBytes', 0),
    staticOnly: asBoolean(body.staticOnly, 'artifact.staticOnly'),
    verificationStatus: status,
    dependencyMode: optionalText(body.dependencyMode),
    evidenceRefs: evidenceRefsOf(body.evidenceRefs, 'artifact.evidenceRefs'),
    projectId: optionalText(body.projectId),
    registeredAt: optionalText(body.registeredAt)
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
  if (!['PRE_ANALYSIS', 'PATH_EXPLORATION', 'VULNERABILITY_TRIAGE', 'REPORT_GENERATION'].includes(role)) throw new Error('invalid roleAssignment.role')
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : body.schemaVersion, 'roleAssignment.schemaVersion', false),
    projectId: asText(body.projectId, 'roleAssignment.projectId'),
    role,
    providerId: asText(body.providerId, 'roleAssignment.providerId'),
    model: optionalText(body.model),
    updatedAt: optionalText(body.updatedAt)
  }
}

export const parseAiJob = (value: unknown): AiJobDto => {
  const body = unwrap(value, 'aiJob')
  if (!isRecord(body)) throw new Error('invalid ai job response')
  const role = asText(body.role, 'aiJob.role') as AiRole
  if (!['PRE_ANALYSIS', 'PATH_EXPLORATION', 'VULNERABILITY_TRIAGE', 'REPORT_GENERATION'].includes(role)) throw new Error('invalid aiJob.role')
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
    { id: 'f-01', title: '上传路径可控', severity: 'high', status: 'VERIFIED', entry: '/api/upload', sink: 'FileOutputStream', dependency: 'attachment.path', evidence: 12 },
    { id: 'f-02', title: '服务器路径信息泄露', severity: 'medium', status: 'VERIFIED', entry: '/api/info', sink: 'HTTP response', dependency: 'filesystem', evidence: 7 },
    { id: 'f-03', title: '文件内容进入执行器', severity: 'critical', status: 'DYNAMIC_SUSPECTED', entry: '/api/run', sink: 'ProcessBuilder', dependency: 'ROLE_ADMIN', evidence: 4 }
  ],
  paths: [],
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

  constructor(private readonly baseUrl: string, private readonly projectId: string, options: { token?: string; fetchFn?: FetchLike; fetch?: FetchLike } = {}) {
    if (!baseUrl || !projectId) throw new Error('Control Plane baseUrl and projectId are required')
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
      throw new ApiRequestError(detail.message ? `${detail.message}${codeSuffix}${requestSuffix}` : `${operation} failed: ${response.status}`, response.status, detail.code, detail.requestId)
    }
    if (response.status === 204) return {}
    try {
      return await response.json()
    } catch (error) {
      throw new Error(`${operation} failed: invalid JSON response`, { cause: error })
    }
  }

  async loadDashboard(projectId = this.projectId): Promise<DashboardSnapshot> {
    const body = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/dashboard`, {
      credentials: 'include',
      headers: jsonHeaders(this.token)
    }, 'dashboard request')
    return parseDashboard(body)
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

  async loadDashboard(): Promise<DashboardSnapshot> {
    return structuredClone(demoSnapshot)
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
  async listArtifacts(): Promise<ArtifactDto[]> { return [] }

  async registerArtifact(request: RegisterArtifactRequest | string, _projectId?: string): Promise<ArtifactDto> {
    const path = typeof request === 'string' ? request : request.path
    return { schemaVersion: 1, artifactId: 'demo-artifact', type: 'JAR', artifactDigest: '0'.repeat(64), sizeBytes: 0, staticOnly: true, verificationStatus: 'STATIC_INFERRED', registeredAt: new Date(0).toISOString(), projectId: 'project-01' }
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
  async listAiJobs(): Promise<AiJobDto[]> { return [] }
  async createAiJob(): Promise<AiJobDto> { return this.unavailable('create ai job') }
  async getAiJob(): Promise<AiJobDto> { return this.unavailable('get ai job') }
  async listAiJobEvents(): Promise<AiJobEventDto[]> { return [] }
  async updateAiJob(): Promise<AiJobDto> { return this.unavailable('update ai job') }
  async deleteAiJob(): Promise<void> { return this.unavailable('delete ai job') }

  async getEntries(): Promise<EntryDto[]> {
    return (await this.loadDashboard()).entries
  }

  async getScan(_scanId: string): Promise<ScanDto> {
    return this.createScan()
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
  : new HttpSentinelApi(import.meta.env.VITE_API_BASE_URL || '/api/v1', import.meta.env.VITE_PROJECT_ID || 'default')

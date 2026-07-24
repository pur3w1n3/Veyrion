/**
 * The only boundary between the GUI and the Java Control Plane.
 *
 * The UI deliberately consumes DTOs instead of Java records.  Runtime
 * validation here is important: a malformed response must never be rendered
 * as a verified security result.  The demo adapter uses the same UI-shaped
 * values, but is selected only when VITE_DEMO_MODE=true.
 */

export type VerificationStatus = 'VERIFIED' | 'DYNAMIC_SUSPECTED' | 'STATIC_INFERRED' | 'UNREACHED'

export type DependencyMode = 'MOCK' | 'REPLAY' | 'LIVE_DISABLED' | 'LIVE' | string
export type ProvenanceKind = 'FACT' | 'INFERENCE' | 'SIMULATION' | 'RUNTIME_OBSERVED' | 'APPLICATION_REPORTED'
export type WorkerCapability = 'STATIC_ONLY' | 'FIXTURE_RUNC' | 'HARDENED_GVISOR' | 'HARDENED_KATA'

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
  fixtureOnly?: boolean
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
  loadDashboard(): Promise<DashboardSnapshot>
  createProject(request: CreateProjectRequest | string): Promise<ProjectDto>
  registerArtifact(request: RegisterArtifactRequest | string, projectId?: string): Promise<ArtifactDto>
  createScan(request?: CreateScanRequest | string, projectId?: string): Promise<ScanDto>
  getEntries(projectId?: string, scanId?: string): Promise<EntryDto[]>
  getScan(scanId: string): Promise<ScanDto>
  getEvidence(evidenceId: string): Promise<EvidenceDto>
  subscribe(scanId: string, onEvent: (event: ScanEvent) => void, options?: SubscribeOptions): () => void
}

const statuses = new Set<VerificationStatus>(['VERIFIED', 'DYNAMIC_SUSPECTED', 'STATIC_INFERRED', 'UNREACHED'])
const provenanceKinds = new Set<ProvenanceKind>(['FACT', 'INFERENCE', 'SIMULATION', 'RUNTIME_OBSERVED', 'APPLICATION_REPORTED'])
const workerCapabilities = new Set<WorkerCapability>(['STATIC_ONLY', 'FIXTURE_RUNC', 'HARDENED_GVISOR', 'HARDENED_KATA'])
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
    fixtureOnly: item.fixtureOnly === undefined ? undefined : asBoolean(item.fixtureOnly, 'dashboard.paths.fixtureOnly'),
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

export class HttpSentinelApi implements SentinelApi {
  readonly mode: ApiMode = 'control-plane'
  private readonly fetchFn: FetchLike
  private readonly token?: string

  constructor(private readonly baseUrl: string, private readonly projectId: string, options: { token?: string; fetchFn?: FetchLike; fetch?: FetchLike } = {}) {
    if (!baseUrl || !projectId) throw new Error('Control Plane baseUrl and projectId are required')
    this.fetchFn = options.fetchFn ?? options.fetch ?? fetch
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
      throw new Error(`${operation} failed: network error`, { cause: error })
    }
    if (response.ok === false || (typeof response.status === 'number' && response.status >= 400)) {
      // Do not include response bodies: they may contain source, credentials or
      // unsanitized model output. Status is enough for the UI and audit log.
      throw new Error(`${operation} failed: ${response.status}`)
    }
    if (response.status === 204) return {}
    try {
      return await response.json()
    } catch (error) {
      throw new Error(`${operation} failed: invalid JSON response`, { cause: error })
    }
  }

  async loadDashboard(): Promise<DashboardSnapshot> {
    const body = await this.request(`projects/${encodeURIComponent(this.projectId)}/dashboard`, {
      credentials: 'include',
      headers: jsonHeaders(this.token)
    }, 'dashboard request')
    return parseDashboard(body)
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

  async loadDashboard(): Promise<DashboardSnapshot> {
    return structuredClone(demoSnapshot)
  }

  async createProject(request: CreateProjectRequest | string): Promise<ProjectDto> {
    const name = typeof request === 'string' ? request : request.name
    return { schemaVersion: 1, projectId: 'demo-project', name, createdAt: new Date(0).toISOString() }
  }

  async registerArtifact(request: RegisterArtifactRequest | string, _projectId?: string): Promise<ArtifactDto> {
    const path = typeof request === 'string' ? request : request.path
    return { schemaVersion: 1, artifactId: 'demo-artifact', type: 'JAR', artifactDigest: '0'.repeat(64), sizeBytes: 0, staticOnly: true, verificationStatus: 'STATIC_INFERRED', registeredAt: new Date(0).toISOString(), projectId: 'project-01' }
  }

  async createScan(_request: CreateScanRequest | string = {}, _projectId?: string): Promise<ScanDto> {
    return { schemaVersion: 1, scanId: 'scan-07f2', projectId: 'project-01', artifactDigest: '0'.repeat(64), status: 'COMPLETED', verificationStatus: 'STATIC_INFERRED', dependencyMode: 'MOCK', createdAt: new Date(0).toISOString(), updatedAt: new Date(0).toISOString(), evidenceRefs: [] }
  }

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

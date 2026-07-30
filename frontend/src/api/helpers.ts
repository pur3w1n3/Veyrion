import type {
  VerificationStatus,
  ProvenanceKind,
  WorkerCapability,
  OutputLanguage,
  EvidenceRef,
  PathStep,
} from './types'

export const statuses = new Set<VerificationStatus>([
  'VERIFIED',
  'DYNAMIC_CONFIRMED',
  'DYNAMIC_SUSPECTED',
  'STATIC_INFERRED',
  'UNREACHED'
])
export const provenanceKinds = new Set<ProvenanceKind>(['FACT', 'INFERENCE', 'SIMULATION', 'RUNTIME_OBSERVED', 'AGENT_INSTRUMENTED', 'APPLICATION_REPORTED'])
export const workerCapabilities = new Set<WorkerCapability>(['STATIC_ONLY', 'TRUSTED_DOCKER', 'HARDENED_GVISOR', 'HARDENED_KATA'])
export const outputLanguages = new Set<OutputLanguage>(['ZH_CN', 'EN'])
export const supportedSchemaVersion = 1
export const supportedEventSchemaVersions = new Set([1, 2])

export const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null

export const asText = (value: unknown, field: string): string => {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`invalid ${field}`)
  return value
}

export const optionalText = (value: unknown): string | undefined => typeof value === 'string' ? value : undefined

export const strictOptionalText = (value: unknown, field: string): string | undefined => {
  // JSON null 与空字符串视为缺失的可选字段。
  if (value === undefined || value === null || value === '') return undefined
  return asText(value, field)
}

export const asFiniteNumber = (value: unknown, field: string, min = Number.NEGATIVE_INFINITY, max = Number.POSITIVE_INFINITY): number => {
  if (typeof value !== 'number') throw new Error(`invalid ${field}`)
  const number = value
  if (!Number.isFinite(number) || number < min || number > max) throw new Error(`invalid ${field}`)
  return number
}

export const asSafeInteger = (value: unknown, field: string, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER): number => {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw new Error(`invalid ${field}`)
  return value as number
}

export const asBoolean = (value: unknown, field: string): boolean => {
  if (typeof value !== 'boolean') throw new Error(`invalid ${field}`)
  return value
}

export const schemaVersion = (value: unknown, field: string, required = true): number => {
  if (value === undefined && !required) return supportedSchemaVersion
  if (!Number.isSafeInteger(value) || value !== supportedSchemaVersion) throw new Error(`unsupported ${field}`)
  return value
}

export const statusOf = (value: unknown, field: string): VerificationStatus => {
  if (typeof value !== 'string' || !statuses.has(value as VerificationStatus)) throw new Error(`invalid ${field}`)
  return value as VerificationStatus
}

export const provenanceKindOf = (value: unknown, field: string): ProvenanceKind => {
  if (typeof value !== 'string' || !provenanceKinds.has(value as ProvenanceKind)) throw new Error(`invalid ${field}`)
  return value as ProvenanceKind
}

export const workerCapabilityOf = (value: unknown, field: string): WorkerCapability => {
  if (typeof value !== 'string' || !workerCapabilities.has(value as WorkerCapability)) throw new Error(`invalid ${field}`)
  return value as WorkerCapability
}

export const outputLanguageOf = (value: unknown, field: string): OutputLanguage => {
  if (typeof value !== 'string' || !outputLanguages.has(value as OutputLanguage)) throw new Error(`invalid ${field}`)
  return value as OutputLanguage
}

export const listOfText = (value: unknown, field: string, optional = false): string[] => {
  // JSON null 与省略字段对可选数组等价。
  if ((value === undefined || value === null) && optional) return []
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) throw new Error(`invalid ${field}`)
  return value as string[]
}

export const evidenceRefsOf = (value: unknown, field: string, optional = true): EvidenceRef[] => {
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

export const pathKind = (value: unknown): PathStep['kind'] => {
  if (value === 'entry' || value === 'transform' || value === 'branch' || value === 'dependency' || value === 'sink') return value
  // 服务端 trace 偶用节点名。保持投影安全。
  if (value === 'resource' || value === 'database' || value === 'jdbc' || value === 'file') return 'dependency'
  if (value === 'source' || value === 'http') return 'entry'
  // ProbePlan 步骤 IDENTITY_UNAVAILABLE；视为决策/分支节点。
  if (value === 'identity' || value === 'auth' || value === 'precondition') return 'branch'
  if (value === 'call' || value === 'param' || value === 'return' || value === 'sanitizer' || value === 'guard') {
    return 'transform'
  }
  // 未知 kind 不得使整个扫描视图失败（frontend AGENTS：降级）。
  if (typeof value === 'string' && value.trim() !== '') return 'transform'
  throw new Error('invalid path step kind')
}

export const pathState = (value: unknown): PathStep['state'] => {
  if (value === 'blocked' || value === 'active' || value === 'done') return value
  // 未知 state：优先 blocked，避免 dashboard 崩溃。
  if (typeof value === 'string' && value.trim() !== '') return 'blocked'
  throw new Error('invalid path step state')
}


export const unwrap = (value: unknown, key: string): unknown => isRecord(value) && value[key] !== undefined ? value[key] : value

export const parseList = <T>(value: unknown, key: string, parser: (item: unknown) => T): T[] => {
  const body = isRecord(value) && value[key] !== undefined ? value[key] : value
  if (!Array.isArray(body)) throw new Error(`invalid ${key} response`)
  return body.map(parser)
}


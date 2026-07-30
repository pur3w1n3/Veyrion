import type {
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
  strictOptionalText,
  asSafeInteger,
  schemaVersion,
  isRecord,
  outputLanguageOf,
  unwrap,
} from './helpers'
import { parseScan, parseDynamicTask } from './scans'

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


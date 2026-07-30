import type {
  PathRunDto,
  SqlExperimentCardDto,
  ExperimentPlanDto,
  ExperimentShapeDto,
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

export const parseBranchHitMap = (value: unknown): Record<string, number[]> | undefined => {
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

export const parseExperimentShape = (value: unknown): ExperimentShapeDto => {
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

export const parseSqlExperimentCard = (value: unknown): SqlExperimentCardDto => {
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

export const parseExperimentPlan = (value: unknown): ExperimentPlanDto => {
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

export const parseProbeBudget = (value: unknown): ProbeBudgetDto => {
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

export const parseAnalysisPack = (value: unknown): AnalysisPackDto => {
  if (!isRecord(value)) throw new Error('invalid analysisPack')
  return {
    packId: asText(value.packId, 'analysisPack.packId'),
    destructive: value.destructive === true,
    jwtSecretHint: strictOptionalText(value.jwtSecretHint, 'analysisPack.jwtSecretHint'),
    templates: Array.isArray(value.templates) ? value.templates.map(parseExperimentPlan) : []
  }
}

export const parsePathDebugTrackSummary = (value: unknown): PathDebugTrackSummary => {
  if (!isRecord(value)) throw new Error('invalid pathDebug track summary')
  return {
    track: optionalText(value.track),
    postureKind: optionalText(value.postureKind),
    postureProvenance: optionalText(value.postureProvenance),
    exitReason: optionalText(value.exitReason),
    lastBusinessHop: optionalText(value.lastBusinessHop),
    // 旧版/无 trace 行省略这些数组；缺失视为空。
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

export const parsePathDebugEntrySummary = (value: unknown): PathDebugEntrySummary => {
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

export const parsePathRun = (value: unknown): PathRunDto => {
  if (!isRecord(value)) throw new Error('invalid pathRun')
  // PathTrace enrichment 可能嵌套在 pathTrace 下；优先顶层，回退嵌套。
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


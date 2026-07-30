import type {
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
  WorkerCapability,
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
  supportedEventSchemaVersions,
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

export const severityOf = (value: unknown): Finding['severity'] => {
  if (typeof value !== 'string') throw new Error('invalid finding.severity')
  const normalized = value.toLowerCase()
  if (normalized !== 'critical' && normalized !== 'high' && normalized !== 'medium' && normalized !== 'low' && normalized !== 'info') throw new Error('invalid finding.severity')
  return normalized
}

export const parseRootCause = (value: unknown, field: string): RootCauseDto | undefined => {
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
          // 后端 copyRootCause 在 label 为 null 时可能输出 ""。
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

export const parseRankedSink = (value: unknown): RankedSinkDto => {
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

export const parseLedgerDiff = (value: unknown): LedgerDiffDto => {
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

export const parseVerifiedFinding = (value: unknown): VerifiedFindingDto => {
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

export const knownEvidenceNodeKinds = new Set<string>(EVIDENCE_NODE_KINDS)

export const normalizeEvidenceNodeKind = (raw: unknown): EvidenceNodeKind => {
  if (typeof raw !== 'string' || raw.trim() === '') return 'UNKNOWN'
  const upper = raw.trim().toUpperCase()
  return knownEvidenceNodeKinds.has(upper) ? upper as EvidenceNodeKind : 'UNKNOWN'
}

export const stringRefList = (value: unknown, field: string): string[] => {
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
    securityProperty: optionalText(item.securityProperty),
    pathRunRefs: item.pathRunRefs === undefined
      ? undefined
      : listOfText(item.pathRunRefs, 'finding.pathRunRefs', true),
    postureProvenance: optionalText(item.postureProvenance),
    postureKind: optionalText(item.postureKind)
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
  // GET dashboard 仍为权威。存在时优先其紧凑投影，同时保留每条 rich path，并仅用第一条 path 作为仍消费 `path` 的视图的兼容投影。
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
    // Java DTO 将终态时间戳称为 completedAt。为 UI 保持稳定的 updatedAt 投影，同时接受进行中快照。
    updatedAt: asText(body.updatedAt ?? completedAt ?? body.createdAt, 'scan.updatedAt'),
    evidenceRefs: evidenceRefsOf(body.evidenceRefs, 'scan.evidenceRefs', false),
    completedAt,
    entries,
    findings,
    hypotheses,
    paths,
    pipelineArmed: typeof body.pipelineArmed === 'boolean' ? body.pipelineArmed : undefined,
    pipelineStage: optionalText(body.pipelineStage),
    pipelineStopReason: optionalText(body.pipelineStopReason),
    pipelineStatus: optionalText(body.pipelineStatus)
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


export const parseScanEvent = (value: unknown, eventName?: string): ScanEvent => {
  if (!isRecord(value)) throw new Error('invalid scan event')
  const eventType = value.eventType ?? eventName
  // Java SSE writer 将 scope 放在嵌套 `context` 中，公开合同也允许扁平字段。两种形式均接受，但交给 UI 前必须有 scope 值。
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


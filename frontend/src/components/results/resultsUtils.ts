import {
  HYPOTHESIS_FAMILIES,
  normalizeHypothesisFamily,
  type CoverageMatrixDto,
  type DashboardSnapshot,
  type Entry,
  type EvidenceGraphNodeDto,
  type ExperimentPlanDto,
  type Finding,
  type HypothesisFamily,
  type PathRunDto,
  type RankedSinkDto,
  type SecurityHypothesisDto,
  type SqlExperimentCardDto
} from '../../api'

export function isAuthGapFinding(finding: { title?: string; sink?: string; sinkId?: string }): boolean {
  const sinkId = (finding.sinkId ?? '').toLocaleLowerCase()
  const sink = (finding.sink ?? '').toLocaleLowerCase()
  const title = finding.title ?? ''
  return sinkId.startsWith('sink-auth-gap')
    || sink.startsWith('sink-auth-gap')
    || title.includes('鉴权缺口')
    || title.toLocaleLowerCase().includes('auth gap')
}

export function isDiagnosticPathRun(run: PathRunDto): boolean {
  return run.httpStatus === -1
    || run.outcomeClass === 'UNKNOWN'
    || run.verificationStatus === 'UNREACHED'
}

const SEVERITY_RANK: Record<Finding['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
}

const STATUS_RANK: Record<Finding['status'], number> = {
  STATIC_INFERRED: 0,
  DYNAMIC_CONFIRMED: 1,
  DYNAMIC_SUSPECTED: 2,
  VERIFIED: 3,
  UNREACHED: 9
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const statusDelta = STATUS_RANK[left.status] - STATUS_RANK[right.status]
    if (statusDelta !== 0) return statusDelta
    const severityDelta = SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity]
    if (severityDelta !== 0) return severityDelta
    return left.title.localeCompare(right.title)
  })
}

export function familyOfFinding(
  finding: { hypothesisId?: string; securityProperty?: string; sinkId?: string; sink?: string; title?: string },
  hypothesisById: Map<string, SecurityHypothesisDto>
): HypothesisFamily {
  const linked = finding.hypothesisId ? hypothesisById.get(finding.hypothesisId) : undefined
  if (linked) return linked.family
  if (finding.securityProperty) {
    const prop = finding.securityProperty.toUpperCase()
    if ((HYPOTHESIS_FAMILIES as readonly string[]).includes(prop)) return prop as HypothesisFamily
    if (prop.includes('GUARD') || prop.includes('AUTH')) return 'GUARD_COVERAGE'
    if (prop.includes('DATAFLOW') || prop.includes('TAINT')) return 'DATAFLOW'
  }
  if (isAuthGapFinding(finding)) return 'GUARD_COVERAGE'
  return 'UNKNOWN'
}

export type SummaryCounts = {
  staticFindings: number
  dynamicSupported: number
  dynamicFailed: number
  coverageGaps: number
  highRiskSinks: number
}

export function deriveSummaryCounts(
  snapshot: DashboardSnapshot | null,
  pathRuns: PathRunDto[],
  findings: Finding[],
  coverage?: CoverageMatrixDto
): SummaryCounts {
  const staticFindings = findings.filter((item) => item.status === 'STATIC_INFERRED').length
  const diagnosticRuns = pathRuns.filter(isDiagnosticPathRun)
  const sessionRuns = pathRuns.filter((run) => !isDiagnosticPathRun(run))

  const dynamicSupported = snapshot?.dynamicSupportedPathRuns
    ?? sessionRuns.filter((run) =>
      run.verificationStatus === 'DYNAMIC_CONFIRMED' || run.verificationStatus === 'DYNAMIC_SUSPECTED').length

  const dynamicFailed = snapshot?.dynamicFailedPathRuns ?? diagnosticRuns.length

  const coverageGaps = coverage?.gaps?.total
    ?? coverage?.gaps?.unreached
    ?? findings.filter((item) => item.status === 'UNREACHED').length

  const highRiskSinks = (snapshot?.rankedSinks ?? [])
    .filter((sink) => sink.rank <= 5).length

  return { staticFindings, dynamicSupported, dynamicFailed, coverageGaps, highRiskSinks }
}

export function formatCoverageDelta(delta: number): string {
  const percent = delta * 100
  const sign = percent > 0 ? '+' : ''
  return `${sign}${percent.toFixed(0)}%`
}

/** Resolve HTTP/method+route (or entryRef) for a finding without inventing routes. */
export function resolveFindingApi(
  finding: Finding,
  entries: Entry[]
): { api: string; entryRef?: string; source: 'entry' | 'finding.entry' | 'entrypointId' | 'none' } {
  if (finding.entrypointId) {
    const byId = entries.find((entry) => entry.id === finding.entrypointId)
    if (byId) {
      return {
        api: `${byId.method} ${byId.route}`,
        entryRef: byId.id,
        source: 'entry'
      }
    }
  }
  const entryText = (finding.entry ?? '').trim()
  if (entryText) {
    const matched = entries.find((entry) =>
      entryText === entry.id
      || entryText === `${entry.method} ${entry.route}`
      || entryText.includes(entry.route)
      || entry.route.includes(entryText))
    if (matched) {
      return {
        api: `${matched.method} ${matched.route}`,
        entryRef: matched.id,
        source: 'entry'
      }
    }
    return {
      api: entryText,
      entryRef: finding.entrypointId,
      source: finding.entrypointId ? 'entrypointId' : 'finding.entry'
    }
  }
  if (finding.entrypointId) {
    return { api: finding.entrypointId, entryRef: finding.entrypointId, source: 'entrypointId' }
  }
  return { api: '—', source: 'none' }
}

export type FindingPocHint = {
  kind: 'sql_card' | 'experiment_plan' | 'path_run' | 'root_cause' | 'none'
  /** Honest provenance label — never claims VERIFIED exploit. */
  provenance: string
  summary: string
  detailLines: string[]
}

function entryRefMatches(ref: string | undefined, finding: Finding, api: string, entryRef?: string): boolean {
  if (!ref) return false
  const needles = [entryRef, finding.entrypointId, finding.entry, api]
    .filter((value): value is string => typeof value === 'string' && value.length > 0)
  return needles.some((needle) => ref === needle || ref.includes(needle) || needle.includes(ref))
}

/**
 * Best-effort PoC / reproduction hint from persisted materials only.
 * Missing material → kind none (UI shows honest empty state).
 */
export function resolveFindingPoc(
  finding: Finding,
  api: string,
  entryRef: string | undefined,
  experimentPlans: ExperimentPlanDto[],
  sqlCards: SqlExperimentCardDto[],
  pathRuns: PathRunDto[]
): FindingPocHint {
  const card = sqlCards.find((item) => entryRefMatches(item.entrypointRef, finding, api, entryRef))
  if (card) {
    return {
      kind: 'sql_card',
      provenance: `${card.verificationStatus} · SQL experiment card`,
      summary: `${card.track} · ${card.stopCondition}`,
      detailLines: [
        `benign: ${card.benignInput}`,
        `meta: ${card.metaInput}`,
        card.structureInfluenced ? 'structureInfluenced: true' : 'structureInfluenced: false'
      ]
    }
  }

  const plan = experimentPlans.find((item) => entryRefMatches(item.entrypointRef, finding, api, entryRef))
  if (plan && (plan.candidateInputs.length > 0 || plan.method)) {
    return {
      kind: 'experiment_plan',
      provenance: plan.boundForExecution
        ? 'EXPERIMENT_PLAN (server-gated)'
        : 'EXPERIMENT_PLAN (static / draft)',
      summary: `${plan.method} · ${plan.track}${plan.contentType ? ` · ${plan.contentType}` : ''}`,
      detailLines: plan.candidateInputs.length > 0
        ? plan.candidateInputs.slice(0, 4).map((input, index) => `candidate[${index}]: ${input}`)
        : ['(no candidateInputs persisted)']
    }
  }

  const relatedRuns = pathRuns.filter((run) =>
    entryRefMatches(run.entrypointRef, finding, api, entryRef)
    || (finding.pathRunRefs?.includes(run.pathRunId) ?? false))
  const usefulRun = relatedRuns.find((run) => (run.requestSummary ?? '').trim().length > 0)
    ?? relatedRuns[0]
  if (usefulRun) {
    const posture = finding.postureProvenance ?? usefulRun.postureKind ?? usefulRun.track
    return {
      kind: 'path_run',
      provenance: `${usefulRun.verificationStatus}${posture ? ` · ${posture}` : ''}`,
      summary: usefulRun.requestSummary?.trim()
        || `${usefulRun.track} · HTTP ${usefulRun.httpStatus < 0 ? '—' : usefulRun.httpStatus}`,
      detailLines: [
        usefulRun.outcomeClass ? `outcome: ${usefulRun.outcomeClass}` : '',
        usefulRun.stopReason ? `stop: ${usefulRun.stopReason}` : '',
        usefulRun.pathRunId ? `pathRunId: ${usefulRun.pathRunId}` : ''
      ].filter(Boolean)
    }
  }

  const attack = finding.rootCause?.attackPath ?? []
  if (attack.length > 0 || (finding.rootCause?.rootCauseStatement ?? '').trim()) {
    return {
      kind: 'root_cause',
      provenance: `${finding.status} · rootCause (inference)`,
      summary: finding.rootCause?.rootCauseStatement?.trim()
        || attack.map((step) => step.label).filter(Boolean).join(' → '),
      detailLines: attack.slice(0, 5).map((step) =>
        `${step.layer}: ${step.label}${step.evidenceRefs?.length ? ` [${step.evidenceRefs.join(', ')}]` : ''}`)
    }
  }

  return {
    kind: 'none',
    provenance: finding.status,
    summary: '',
    detailLines: []
  }
}

export type EvidenceSelection =
  | { kind: 'finding'; finding: Finding }
  | { kind: 'pathRun'; pathRun: PathRunDto }
  | { kind: 'hypothesis'; hypothesis: SecurityHypothesisDto }
  | { kind: 'hypothesisFamily'; family: HypothesisFamily; items: SecurityHypothesisDto[] }
  | { kind: 'rankedSink'; sink: RankedSinkDto }
  | { kind: 'entry'; entry: Entry }
  | { kind: 'graphNode'; node: EvidenceGraphNodeDto }
  | null

/** Whether the right inspector should render for this view + selection (no empty placeholder). */
export function selectionMatchesView(selection: EvidenceSelection, activeView: string): boolean {
  if (!selection) return false
  switch (activeView) {
    case 'findings':
      return selection.kind === 'finding' || selection.kind === 'hypothesis' || selection.kind === 'hypothesisFamily'
    case 'pathRuns':
      return selection.kind === 'pathRun'
    case 'hypotheses':
      return selection.kind === 'hypothesis' || selection.kind === 'hypothesisFamily'
    case 'entryExploration':
      return selection.kind === 'entry'
    case 'contrast':
      return selection.kind === 'rankedSink'
    case 'evidenceGraph':
      return selection.kind === 'graphNode'
    case 'downloads':
    case 'verified':
    case 'report':
    case 'diagnostics':
    case 'experiments':
    case 'coverage':
      return false
    default:
      return false
  }
}

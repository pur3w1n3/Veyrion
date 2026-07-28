import {
  HYPOTHESIS_FAMILIES,
  normalizeHypothesisFamily,
  type CoverageMatrixDto,
  type DashboardSnapshot,
  type Entry,
  type Finding,
  type HypothesisFamily,
  type PathRunDto,
  type SecurityHypothesisDto
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

export type EvidenceSelection =
  | { kind: 'finding'; finding: Finding }
  | { kind: 'pathRun'; pathRun: PathRunDto }
  | { kind: 'hypothesis'; hypothesis: SecurityHypothesisDto }
  | { kind: 'entry'; entry: Entry }
  | null

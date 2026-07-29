import { useEffect, useMemo, useState } from 'react'
import {
  api,
  HYPOTHESIS_FAMILIES,
  normalizeHypothesisFamily,
  type AiJobDto,
  type CoverageMatrixDto,
  type DashboardSnapshot,
  type EvidenceGraphDto,
  type Finding,
  type FindingReplayDto,
  type FocusEntryProbeDto,
  type HypothesisFamily,
  type OutputLanguage,
  type PathRunDto,
  type SecurityHypothesisDto
} from '../api'
import {
  DOWNLOAD_ARTIFACTS,
  RESULTS_VIEW_IDS,
  RESULTS_VIEW_META,
  downloadFilename,
  type ResultsViewId
} from '../guiSemantics'
import { errorMessage, PageHeader } from './Common'
import { CoverageGapsView, EvidenceGraphView } from './results/EvidenceGraphView'
import { DynamicDiagnosticsView } from './results/DynamicDiagnosticsView'
import { DownloadsView } from './results/DownloadsView'
import { EntryParameterExplorerView } from './results/EntryParameterExplorerView'
import { ExperimentReplayView } from './results/ExperimentReplayView'
import { FinalReportView } from './results/FinalReportView'
import { FindingsView } from './results/FindingsView'
import { HypothesesView } from './results/HypothesesView'
import { PathRunsView } from './results/PathRunsView'
import { ResultsShell } from './results/ResultsShell'
import { ContrastView, VerifiedView } from './results/VerifiedView'
import {
  deriveSummaryCounts,
  familyOfFinding,
  isAuthGapFinding,
  type EvidenceSelection
} from './results/resultsUtils'

type ResultsView = ResultsViewId
const RESULTS_VIEWS: ResultsView[] = [...RESULTS_VIEW_IDS]

export function ResultsPage({ projectId, snapshot, language }: { projectId: string; snapshot: DashboardSnapshot | null; language: OutputLanguage }) {
  const english = language === 'EN'
  const findings = snapshot?.findings ?? []
  const hypotheses = snapshot?.hypotheses ?? []
  const entries = snapshot?.entries ?? []
  const pathRuns = snapshot?.pathRuns ?? []
  const sqlCards = snapshot?.sqlExperimentCards ?? []
  const experimentPlans = snapshot?.experimentPlans ?? []
  const analysisPacks = snapshot?.analysisPacks ?? []
  const probeBudget = snapshot?.probeBudget
  const rankedSinks = snapshot?.rankedSinks ?? []
  const verifiedFindings = snapshot?.verifiedFindings ?? []
  const authGapFindingCount = snapshot?.authGapFindingCount ?? findings.filter(isAuthGapFinding).length
  const authGapSinkCount = snapshot?.authGapSinkCount

  const [activeView, setActiveView] = useState<ResultsView>('report')
  const [selection, setSelection] = useState<EvidenceSelection>(null)
  const [reportJob, setReportJob] = useState<AiJobDto>()
  const [reportSummary, setReportSummary] = useState<string>()
  const [reportError, setReportError] = useState<string>()
  const [reportLoading, setReportLoading] = useState(false)
  const [findingQuery, setFindingQuery] = useState('')
  const [findingStatus, setFindingStatus] = useState<'ALL' | Finding['status']>('ALL')
  const [findingFamily, setFindingFamily] = useState<'ALL' | HypothesisFamily>('ALL')
  const [showAuthGap, setShowAuthGap] = useState(false)
  const [selectedFindingId, setSelectedFindingId] = useState<string>()
  const [selectedEntryId, setSelectedEntryId] = useState<string>()
  const [selectedStepIndex, setSelectedStepIndex] = useState(0)
  const [replayLoading, setReplayLoading] = useState(false)
  const [replayError, setReplayError] = useState<string>()
  const [replayResult, setReplayResult] = useState<FindingReplayDto>()
  const [cardReplayLoading, setCardReplayLoading] = useState<string>()
  const [cardReplayError, setCardReplayError] = useState<string>()
  const [cardReplayNotice, setCardReplayNotice] = useState<string>()
  const [coverage, setCoverage] = useState<CoverageMatrixDto>()
  const [coverageError, setCoverageError] = useState<string>()
  const [coverageLoading, setCoverageLoading] = useState(false)
  const [evidenceGraph, setEvidenceGraph] = useState<EvidenceGraphDto>()
  const [evidenceGraphError, setEvidenceGraphError] = useState<string>()
  const [evidenceGraphLoading, setEvidenceGraphLoading] = useState(false)

  const secondaryFindingCount = findings.filter((item) => !isAuthGapFinding(item)).length

  useEffect(() => {
    setActiveView('report')
    setSelection(null)
    setSelectedFindingId(undefined)
    setSelectedEntryId(undefined)
    setSelectedStepIndex(0)
    setFindingQuery('')
    setFindingStatus('ALL')
    setFindingFamily('ALL')
    setShowAuthGap(false)
  }, [projectId, snapshot?.scanId])

  useEffect(() => {
    let active = true
    setCoverage(undefined)
    setCoverageError(undefined)
    setEvidenceGraph(undefined)
    setEvidenceGraphError(undefined)
    if (!snapshot?.scanId || snapshot.scanId === 'unscanned') return () => { active = false }
    if (activeView === 'coverage') {
      setCoverageLoading(true)
      void api.getScanCoverage(snapshot.scanId).then((matrix) => {
        if (active) setCoverage(matrix)
      }).catch((cause) => {
        if (active) setCoverageError(errorMessage(cause))
      }).finally(() => {
        if (active) setCoverageLoading(false)
      })
    }
    if (activeView === 'evidenceGraph') {
      setEvidenceGraphLoading(true)
      void api.getEvidenceGraph(snapshot.scanId).then((graph) => {
        if (active) setEvidenceGraph(graph)
      }).catch((cause) => {
        if (active) setEvidenceGraphError(errorMessage(cause))
      }).finally(() => {
        if (active) setEvidenceGraphLoading(false)
      })
    }
    return () => { active = false }
  }, [activeView, snapshot?.scanId])

  useEffect(() => {
    let active = true
    setReportJob(undefined)
    setReportSummary(undefined)
    setReportError(undefined)
    if (!projectId || !snapshot?.scanId || snapshot.scanId === 'unscanned') return () => { active = false }
    setReportLoading(true)
    void api.listAiJobs(projectId).then(async (jobs) => {
      const report = jobs
        .filter((job) => job.scanId === snapshot.scanId && job.role === 'REPORT_GENERATION')
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt))[0]
      if (!active || !report) return
      setReportJob(report)
      if (report.status !== 'COMPLETED') return
      const events = await api.listAiJobEvents(report.aiJobId)
      if (!active) return
      setReportSummary([...events].reverse().find((event) =>
        event.stage === 'MODEL_INFERENCE' && event.status === 'COMPLETED')?.modelInferenceSummary)
    }).catch((cause) => {
      if (active) setReportError(errorMessage(cause))
    }).finally(() => {
      if (active) setReportLoading(false)
    })
    return () => { active = false }
  }, [projectId, snapshot?.scanId])

  const hypothesisById = useMemo(() => {
    const map = new Map<string, SecurityHypothesisDto>()
    for (const item of hypotheses) map.set(item.hypothesisId, item)
    return map
  }, [hypotheses])

  const hypothesesByFamily = useMemo(() => {
    const buckets = new Map<HypothesisFamily, SecurityHypothesisDto[]>()
    for (const family of HYPOTHESIS_FAMILIES) buckets.set(family, [])
    for (const item of hypotheses) {
      buckets.get(normalizeHypothesisFamily(item.family))?.push(item)
    }
    return buckets
  }, [hypotheses])

  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId)
  const selectedPath = snapshot?.paths.find((path) => path.entrypointId === selectedFinding?.entrypointId)
    ?? snapshot?.paths[0]

  const summaryCounts = deriveSummaryCounts(snapshot, pathRuns, findings, coverage)

  const replaySelectedFinding = async () => {
    const target = findings.find((finding) => finding.id === selectedFindingId)
    if (!target?.id || replayLoading) return
    setReplayLoading(true)
    setReplayError(undefined)
    setReplayResult(undefined)
    try {
      setReplayResult(await api.replayFinding(target.findingId ?? target.id))
    } catch (cause) {
      setReplayError(errorMessage(cause))
    } finally {
      setReplayLoading(false)
    }
  }

  const focusEntry = async (entryId: string): Promise<FocusEntryProbeDto> => {
    if (!snapshot?.scanId || snapshot.scanId === 'unscanned') {
      throw new Error(english ? 'No scan is available for a focused probe.' : '当前没有可用于焦点探针的扫描。')
    }
    return api.focusEntryProbe(snapshot.scanId, entryId, { authorized: true, maxRequests: 1 })
  }

  const replaySqlCard = async (cardId: string) => {
    if (!snapshot?.scanId || snapshot.scanId === 'unscanned' || cardReplayLoading) return
    setCardReplayLoading(cardId)
    setCardReplayError(undefined)
    setCardReplayNotice(undefined)
    try {
      const result = await api.replaySqlExperimentCard(snapshot.scanId, cardId)
      setCardReplayNotice(english
        ? `D3 card replay task ${result.taskId} is ${result.lifecycle} (${result.verificationStatus}, ${result.dependencyMode}).`
        : `D3 实验卡重放任务 ${result.taskId} 当前为 ${result.lifecycle}（${result.verificationStatus}，${result.dependencyMode}）。`)
    } catch (cause) {
      setCardReplayError(errorMessage(cause))
    } finally {
      setCardReplayLoading(undefined)
    }
  }

  const downloadFile = (filename: string, content: string, type: string) => {
    const url = URL.createObjectURL(new Blob([content], { type }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  const downloadReport = () => {
    if (!reportSummary || !snapshot?.scanId) return
    downloadFile(downloadFilename('reportMarkdown', snapshot.scanId), reportSummary, 'text/markdown;charset=utf-8')
  }

  const downloadJson = () => {
    if (!snapshot?.scanId) return
    downloadFile(downloadFilename('dashboardJson', snapshot.scanId), JSON.stringify(snapshot, null, 2), 'application/json;charset=utf-8')
  }

  const downloadHtml = () => {
    if (!snapshot?.scanId) return
    const esc = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char] ?? char))
    const rows = findings.map((finding) => `<tr><td>${esc(finding.severity)}</td><td>${esc(finding.title)}</td><td>${esc(familyOfFinding(finding, hypothesisById))}</td><td>${esc(finding.entry)}</td><td>${esc(finding.sink)}</td><td>${esc(finding.status)}</td></tr>`).join('')
    const familyRows = HYPOTHESIS_FAMILIES.map((family) => {
      const items = hypothesesByFamily.get(family) ?? []
      return `<tr><td>${esc(family)}</td><td>${items.length}</td><td>${esc(items.map((item) => item.hypothesisId).join(', ') || (english ? '(empty)' : '（空）'))}</td></tr>`
    }).join('')
    const html = `<!doctype html><html lang="${english ? 'en' : 'zh-CN'}"><head><meta charset="utf-8"><title>Veyrion findings ${esc(snapshot.scanId)}</title><style>body{font:14px system-ui,sans-serif;color:#172033;margin:32px}h1{font-size:24px}small{color:#667085}table{border-collapse:collapse;width:100%;margin-top:24px}th,td{border:1px solid #dfe5ee;padding:8px;text-align:left}th{background:#f0f4fa}</style></head><body><h1>Veyrion findings summary</h1><small>${esc(DOWNLOAD_ARTIFACTS.findingsHtml.id)} · ${esc(snapshot.scanId)} · ${esc(snapshot.verificationStatus)} · ${esc(snapshot.dependencyMode)}</small><p>${english ? 'This HTML is a findings summary export, not the final report Markdown and not the dashboard JSON snapshot.' : '本 HTML 为发现摘要导出，不等于最终报告 Markdown，也不等于仪表盘 JSON 快照。'}</p><h2>Hypothesis families</h2><table><thead><tr><th>Family</th><th>Count</th><th>Ids</th></tr></thead><tbody>${familyRows}</tbody></table><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Family</th><th>Entry</th><th>Sink</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></body></html>`
    downloadFile(downloadFilename('findingsHtml', snapshot.scanId), html, 'text/html;charset=utf-8')
  }

  const viewMeta = (view: ResultsView) => {
    const meta = RESULTS_VIEW_META[view]
    const label = english ? meta.en : meta.zh
    const blurb = english ? meta.blurbEn : meta.blurbZh
    switch (view) {
      case 'report':
        return { label, count: reportSummary ? 1 : 0, blurb }
      case 'findings':
        return { label, count: secondaryFindingCount, blurb }
      case 'entryExploration':
        return { label, count: entries.length, blurb }
      case 'pathRuns':
        return { label, count: pathRuns.length, blurb }
      case 'evidenceGraph':
        return { label, count: evidenceGraph?.nodes.length ?? evidenceGraph?.nodeCount ?? 0, blurb }
      case 'coverage':
        return { label, count: coverage?.gaps?.total ?? coverage?.gaps?.unreached ?? 0, blurb }
      case 'diagnostics':
        return { label, count: summaryCounts.dynamicFailed, blurb }
      case 'experiments':
        return { label, count: sqlCards.length + experimentPlans.length, blurb }
      case 'downloads':
        return { label, count: 3, blurb }
      case 'hypotheses':
        return { label, count: hypotheses.length, blurb }
      case 'contrast':
        return { label, count: rankedSinks.length, blurb }
      case 'verified':
        return { label, count: verifiedFindings.length, blurb }
    }
  }

  const reportEmpty = !reportLoading && !reportSummary
  const scanUnreached = snapshot?.verificationStatus === 'UNREACHED'

  const handleSelectFinding = (finding: Finding) => {
    setSelectedFindingId(finding.id)
    setSelection({ kind: 'finding', finding })
  }

  const handleSelectPathRun = (pathRun: PathRunDto) => {
    setSelection({ kind: 'pathRun', pathRun })
  }

  const handleSelectEntry = (entry: import('../api').Entry) => {
    setSelectedEntryId(entry.id)
    setSelection({ kind: 'entry', entry })
  }

  const handleSelectHypothesis = (hypothesis: SecurityHypothesisDto) => {
    setSelection({ kind: 'hypothesis', hypothesis })
  }

  const handleSelectGraphNode = (node: import('../api').EvidenceGraphNodeDto) => {
    setSelection({ kind: 'graphNode', node })
  }

  return <>
    <PageHeader eyebrow={snapshot?.scanId ?? (english ? 'NO SCAN' : '尚无扫描')} title={english ? 'Audit results' : '审计结果'}>
      {english
        ? 'Evidence workbench — report, findings, PathRuns, coverage and diagnostics share one scan scope.'
        : '证据工作台 — 报告、发现、PathRun、覆盖与诊断共享同一扫描作用域。'}
      {(authGapFindingCount > 0 || authGapSinkCount != null) && (
        <small>{english ? `AUTH_GAP rows ${authGapFindingCount}${authGapSinkCount != null ? ` / sinks ${authGapSinkCount}` : ''}` : `AUTH_GAP 行 ${authGapFindingCount}${authGapSinkCount != null ? ` / sink ${authGapSinkCount}` : ''}`}</small>
      )}
    </PageHeader>

    <ResultsShell
      snapshot={snapshot}
      english={english}
      reportJobStatus={reportJob?.status}
      reportErrorCode={reportJob?.errorCode}
      summaryCounts={summaryCounts}
      activeView={activeView}
      onViewChange={setActiveView}
      viewMeta={viewMeta}
      selection={selection}
      hypothesisById={hypothesisById}
    >
      {activeView === 'report' && (
        <FinalReportView
          english={english}
          reportJob={reportJob}
          reportSummary={reportSummary}
          reportError={reportError}
          reportLoading={reportLoading}
          reportEmpty={reportEmpty}
          scanUnreached={scanUnreached}
          onDownloadReport={downloadReport}
          onDownloadHtml={downloadHtml}
          onNavigate={setActiveView}
        />
      )}

      {activeView === 'findings' && (
        <FindingsView
          english={english}
          findings={findings}
          hypotheses={hypotheses}
          hypothesisById={hypothesisById}
          selectedFindingId={selectedFindingId}
          onSelectFinding={handleSelectFinding}
          findingQuery={findingQuery}
          onFindingQueryChange={setFindingQuery}
          findingStatus={findingStatus}
          onFindingStatusChange={setFindingStatus}
          findingFamily={findingFamily}
          onFindingFamilyChange={setFindingFamily}
          showAuthGap={showAuthGap}
          onShowAuthGapChange={setShowAuthGap}
          selectedPath={selectedPath}
          selectedStepIndex={selectedStepIndex}
          onSelectStepIndex={setSelectedStepIndex}
          replayLoading={replayLoading}
          replayError={replayError}
          replayResult={replayResult}
          onReplayFinding={() => void replaySelectedFinding()}
          evidencePath={snapshot?.path ?? []}
        />
      )}

      {activeView === 'entryExploration' && (
        <EntryParameterExplorerView
          english={english}
          entries={entries}
          experimentPlans={experimentPlans}
          selectedEntryId={selectedEntryId}
          onSelectEntry={handleSelectEntry}
        />
      )}

      {activeView === 'pathRuns' && (
        <PathRunsView
          pathRuns={pathRuns}
          entries={entries}
          scanId={snapshot?.scanId}
          english={english}
          onFocusEntry={focusEntry}
          onSelectPathRun={handleSelectPathRun}
        />
      )}

      {activeView === 'evidenceGraph' && (
        <EvidenceGraphView
          graph={evidenceGraph}
          loading={evidenceGraphLoading}
          error={evidenceGraphError}
          english={english}
          language={language}
          onSelectNode={handleSelectGraphNode}
        />
      )}

      {activeView === 'coverage' && (
        <CoverageGapsView
          coverage={coverage}
          loading={coverageLoading}
          error={coverageError}
          english={english}
        />
      )}

      {activeView === 'diagnostics' && (
        <DynamicDiagnosticsView english={english} pathRuns={pathRuns} probeBudget={probeBudget} />
      )}

      {activeView === 'experiments' && (
        <ExperimentReplayView
          english={english}
          sqlCards={sqlCards}
          experimentPlans={experimentPlans}
          analysisPacks={analysisPacks}
          probeBudget={probeBudget}
          cardReplayLoading={cardReplayLoading}
          cardReplayError={cardReplayError}
          cardReplayNotice={cardReplayNotice}
          onReplayCard={(cardId) => void replaySqlCard(cardId)}
        />
      )}

      {activeView === 'downloads' && (
        <DownloadsView
          english={english}
          snapshot={snapshot}
          hasReport={!!reportSummary}
          onDownloadReport={downloadReport}
          onDownloadHtml={downloadHtml}
          onDownloadJson={downloadJson}
        />
      )}

      {activeView === 'hypotheses' && (
        <HypothesesView hypotheses={hypotheses} english={english} onSelectHypothesis={handleSelectHypothesis} />
      )}

      {activeView === 'contrast' && (
        <ContrastView english={english} snapshot={snapshot} />
      )}

      {activeView === 'verified' && (
        <VerifiedView english={english} verifiedFindings={verifiedFindings} />
      )}
    </ResultsShell>

    {/* Contract anchors: RESULTS_VIEW_IDS / DOWNLOAD_ARTIFACTS / downloadFilename / getScanCoverage / getEvidenceGraph */}
    <span hidden aria-hidden="true">{RESULTS_VIEWS.join(' ')} {DOWNLOAD_ARTIFACTS.reportMarkdown.id}</span>
  </>
}

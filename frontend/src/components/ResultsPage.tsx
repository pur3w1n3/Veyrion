import { useEffect, useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, type AiJobDto, type DashboardSnapshot, type FindingReplayDto, type FocusEntryProbeDto, type OutputLanguage } from '../api'
import { dependencyModeLabel, jobStatusLabel } from '../labels'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'
import { PathRunPanel } from './PathRunPanel'

type ResultsView =
  | 'report'
  | 'pathRuns'
  | 'contrast'
  | 'findings'
  | 'verified'
  | 'experiments'

const RESULTS_VIEWS: ResultsView[] = ['report', 'pathRuns', 'contrast', 'findings', 'verified', 'experiments']

export function ResultsPage({ projectId, snapshot, language }: { projectId: string; snapshot: DashboardSnapshot | null; language: OutputLanguage }) {
  const english = language === 'EN'
  const findings = snapshot?.findings ?? []
  const entries = snapshot?.entries ?? []
  const [activeView, setActiveView] = useState<ResultsView>('report')
  const [reportJob, setReportJob] = useState<AiJobDto>()
  const [reportSummary, setReportSummary] = useState<string>()
  const [reportError, setReportError] = useState<string>()
  const [reportLoading, setReportLoading] = useState(false)
  const [findingQuery, setFindingQuery] = useState('')
  const [findingStatus, setFindingStatus] = useState<'ALL' | 'STATIC_INFERRED' | 'DYNAMIC_SUSPECTED' | 'DYNAMIC_CONFIRMED' | 'VERIFIED' | 'UNREACHED'>('ALL')
  const [showAuthGap, setShowAuthGap] = useState(false)
  const pathRuns = snapshot?.pathRuns ?? []
  const authGapFindingCount = snapshot?.authGapFindingCount ?? findings.filter(isAuthGapFinding).length
  const authGapSinkCount = snapshot?.authGapSinkCount
  const [selectedFindingId, setSelectedFindingId] = useState<string>()
  const [selectedStepIndex, setSelectedStepIndex] = useState(0)
  const [replayLoading, setReplayLoading] = useState(false)
  const [replayError, setReplayError] = useState<string>()
  const [replayResult, setReplayResult] = useState<FindingReplayDto>()
  const sqlCards = snapshot?.sqlExperimentCards ?? []
  const experimentPlans = snapshot?.experimentPlans ?? []
  const analysisPacks = snapshot?.analysisPacks ?? []
  const probeBudget = snapshot?.probeBudget
  const rankedSinks = snapshot?.rankedSinks ?? []
  const ledgerDiff = snapshot?.ledgerDiff
  const verifiedFindings = snapshot?.verifiedFindings ?? []
  const topRankedSinks = rankedSinks.slice(0, 12)
  const [cardReplayLoading, setCardReplayLoading] = useState<string>()
  const [cardReplayError, setCardReplayError] = useState<string>()
  const [cardReplayNotice, setCardReplayNotice] = useState<string>()

  const secondaryFindingCount = findings.filter((item) => !isAuthGapFinding(item)).length
  const dynamicConfirmedCount = pathRuns.filter((item) => item.verificationStatus === 'DYNAMIC_CONFIRMED').length
  const dynamicSuspectedCount = pathRuns.filter((item) => item.verificationStatus === 'DYNAMIC_SUSPECTED').length
    + findings.filter((item) => item.status === 'DYNAMIC_SUSPECTED').length

  useEffect(() => {
    setActiveView('report')
  }, [projectId, snapshot?.scanId])

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

  const filteredFindings = useMemo(() => {
    const query = findingQuery.trim().toLocaleLowerCase()
    return findings.filter((finding) => {
      if (!showAuthGap && isAuthGapFinding(finding)) return false
      if (findingStatus !== 'ALL' && finding.status !== findingStatus) return false
      if (!query) return true
      return [finding.title, finding.entry, finding.sink, finding.dependency]
        .some((value) => value.toLocaleLowerCase().includes(query))
    })
  }, [findings, findingQuery, findingStatus, showAuthGap])

  const selectedFinding = filteredFindings.find((finding) => finding.id === selectedFindingId)
    ?? filteredFindings[0]
  const selectedPath = snapshot?.paths.find((path) => path.entrypointId === selectedFinding?.entrypointId)
    ?? snapshot?.paths[0]
  const selectedStep = selectedPath?.steps[Math.min(selectedStepIndex, Math.max(0, (selectedPath?.steps.length ?? 1) - 1))]

  const replaySelectedFinding = async () => {
    if (!selectedFinding?.id || replayLoading) return
    setReplayLoading(true)
    setReplayError(undefined)
    setReplayResult(undefined)
    try {
      setReplayResult(await api.replayFinding(selectedFinding.findingId ?? selectedFinding.id))
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

  useEffect(() => {
    if (selectedFinding && selectedFinding.id !== selectedFindingId) setSelectedFindingId(selectedFinding.id)
    if (!selectedFinding) setSelectedFindingId(undefined)
    setSelectedStepIndex(0)
  }, [selectedFinding?.id, selectedFindingId])

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
    const safeScanId = snapshot.scanId.replace(/[^A-Za-z0-9._-]/g, '_')
    downloadFile(`veyrion-report-${safeScanId}.md`, reportSummary, 'text/markdown;charset=utf-8')
  }

  const downloadJson = () => {
    if (!snapshot?.scanId) return
    const safeScanId = snapshot.scanId.replace(/[^A-Za-z0-9._-]/g, '_')
    downloadFile(`veyrion-scan-${safeScanId}.json`, JSON.stringify(snapshot, null, 2), 'application/json;charset=utf-8')
  }

  const downloadHtml = () => {
    if (!snapshot?.scanId) return
    const safeScanId = snapshot.scanId.replace(/[^A-Za-z0-9._-]/g, '_')
    const esc = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char] ?? char))
    const rows = findings.map((finding) => `<tr><td>${esc(finding.severity)}</td><td>${esc(finding.title)}</td><td>${esc(finding.entry)}</td><td>${esc(finding.sink)}</td><td>${esc(finding.status)}</td></tr>`).join('')
    const html = `<!doctype html><html lang="${english ? 'en' : 'zh-CN'}"><head><meta charset="utf-8"><title>Veyrion ${esc(snapshot.scanId)}</title><style>body{font:14px system-ui,sans-serif;color:#172033;margin:32px}h1{font-size:24px}small{color:#667085}table{border-collapse:collapse;width:100%;margin-top:24px}th,td{border:1px solid #dfe5ee;padding:8px;text-align:left}th{background:#f0f4fa}</style></head><body><h1>Veyrion audit report</h1><small>${esc(snapshot.scanId)} · ${esc(snapshot.verificationStatus)} · ${esc(snapshot.dependencyMode)}</small><table><thead><tr><th>Severity</th><th>Finding</th><th>Entry</th><th>Sink</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></body></html>`
    downloadFile(`veyrion-report-${safeScanId}.html`, html, 'text/html;charset=utf-8')
  }

  const viewMeta = (view: ResultsView): { label: string; eyebrow: string; count: number; blurb: string } => {
    switch (view) {
      case 'report':
        return {
          label: english ? 'Final report' : '最终报告',
          eyebrow: english ? 'PRIMARY' : '主视图',
          count: reportSummary ? 1 : 0,
          blurb: english ? 'REPORT_GENERATION markdown summary' : 'REPORT_GENERATION 最终报告正文'
        }
      case 'pathRuns':
        return {
          label: english ? 'PathRuns' : 'PathRun 会话',
          eyebrow: english ? 'SESSIONS' : '路径会话',
          count: pathRuns.length,
          blurb: english ? 'Entry × identity-track sessions' : '入口 × 身份轨会话证据'
        }
      case 'contrast':
        return {
          label: english ? 'Sinks & ledger' : 'Sink 与对照账本',
          eyebrow: english ? 'TRIAGE' : '研判对照',
          count: rankedSinks.length,
          blurb: english ? 'Ranked sinks and contrast ledger diff' : '候选 Sink 排序与对照差分'
        }
      case 'findings':
        return {
          label: english ? 'Findings & chain' : '发现与攻击链',
          eyebrow: english ? 'EVIDENCE' : '证据详情',
          count: secondaryFindingCount,
          blurb: english ? 'Secondary findings, entries, attack chain' : '次级发现、入口覆盖与攻击链'
        }
      case 'verified':
        return {
          label: english ? 'Verified' : '已验证',
          eyebrow: english ? 'GATED' : '门禁',
          count: verifiedFindings.length,
          blurb: english ? 'Fail-closed verified_findings rows' : 'VerifiedStatusGate 门禁结果'
        }
      case 'experiments':
        return {
          label: english ? 'Experiments' : '实验计划',
          eyebrow: english ? 'D3 / PLANS' : '实验卡',
          count: sqlCards.length + experimentPlans.length,
          blurb: english ? 'SQL D3 cards and accepted plans' : 'SQL D3 实验卡与已接受计划'
        }
    }
  }

  const reportEmpty = !reportLoading && !reportSummary
  const scanUnreached = snapshot?.verificationStatus === 'UNREACHED'

  return <section>
    <PageHeader eyebrow={snapshot?.scanId ?? (english ? 'NO SCAN' : '尚无扫描')} title={english ? 'Audit results' : '审计结果'}>
      {english
        ? 'Default view is the final report. PathRuns, sinks, findings, and experiments open as evidence sub-views — every conclusion keeps its evidence status.'
        : '默认主视图为最终报告；PathRun、Sink、发现与实验等作为子页面点击查看。每项结论保留独立证据状态。'}
    </PageHeader>

    <div className="metrics-grid">
      <article className="metric"><span>{english ? 'PathRuns' : 'PathRun'}</span><strong>{pathRuns.length}</strong><small>{english ? 'Session evidence' : '路径会话证据'}</small></article>
      <article className="metric"><span>{english ? 'Dynamic confirmed' : '动态确认'}</span><strong>{dynamicConfirmedCount}</strong><small>{english ? 'SQL H3 (MOCK)' : 'SQL H3（MOCK）'}</small></article>
      <article className="metric"><span>{english ? 'Dynamic suspected' : '动态疑似'}</span><strong>{dynamicSuspectedCount}</strong><small>{english ? 'Needs closed loop' : '需闭环'}</small></article>
      <article className="metric"><span>{english ? 'Secondary findings' : '次级发现'}</span><strong>{secondaryFindingCount}</strong><small title={english ? 'authGapFindingCount = demoted finding rows; authGapSinkCount = AUTH_GAP sinks' : 'authGapFindingCount=降级 finding 行；authGapSinkCount=AUTH_GAP sink 数'}>{english ? `AUTH_GAP rows ${authGapFindingCount}${authGapSinkCount != null ? ` / sinks ${authGapSinkCount}` : ''}` : `AUTH_GAP 行 ${authGapFindingCount}${authGapSinkCount != null ? ` / sink ${authGapSinkCount}` : ''}`}</small></article>
    </div>

    <nav className="results-subnav" aria-label={english ? 'Results sub-views' : '审计结果子页面'}>
      {RESULTS_VIEWS.map((view) => {
        const meta = viewMeta(view)
        return <button
          key={view}
          type="button"
          className={activeView === view ? 'active' : ''}
          aria-current={activeView === view ? 'page' : undefined}
          onClick={() => setActiveView(view)}
        >
          <strong>{meta.label}</strong>
          <small>{meta.count}</small>
        </button>
      })}
    </nav>

    {activeView === 'report' && (
      <article className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{english ? 'FINAL REPORT' : '最终报告'}</p>
            <h2>{english ? 'Final report' : '最终报告'}</h2>
          </div>
          <div className="button-row">
            <span className="inference-badge">{english ? 'MODEL INFERENCE' : '模型推断'}</span>
            {reportSummary && <>
              <button type="button" className="secondary-button" onClick={downloadReport}>{english ? 'Download .md' : '下载 .md'}</button>
              <button type="button" className="secondary-button" onClick={downloadHtml}>{english ? 'Export .html' : '导出 .html'}</button>
            </>}
            {snapshot && <button type="button" className="secondary-button" onClick={downloadJson}>{english ? 'Export .json' : '导出 .json'}</button>}
          </div>
        </div>
        {reportError && <Notice kind="error">{reportError}</Notice>}
        {reportLoading && <p className="empty-state">{english ? 'Loading report events for this scan…' : '正在加载当前扫描的报告事件…'}</p>}
        {!reportLoading && reportSummary && <>
          <div className="ai-report"><ReactMarkdown skipHtml remarkPlugins={[remarkGfm]}>{reportSummary}</ReactMarkdown></div>
          <p className="form-help">{reportJob?.aiJobId} · {reportJob?.providerId} · {reportJob?.model} · {reportJob?.outputLanguage === 'ZH_CN' ? '简体中文' : (reportJob?.outputLanguage ?? (english ? 'UNKNOWN' : '未知'))}。{english ? 'This is evidence-grounded model inference, not VERIFIED evidence.' : '该内容是受证据约束的模型推断，不等于已验证。'}</p>
        </>}
        {reportEmpty && (
          <div className="results-empty-report">
            {reportJob ? (
              <p className="empty-state">
                {english
                  ? `Report job ${reportJob.aiJobId} is ${reportJob.status}${reportJob.errorCode ? ` · ${reportJob.errorCode}` : ''}; no final inference summary is available.`
                  : `报告任务 ${reportJob.aiJobId} 当前为 ${jobStatusLabel(reportJob.status)}${reportJob.errorCode ? ` · ${reportJob.errorCode}` : ''}，尚无最终推断摘要。`}
              </p>
            ) : !reportError ? (
              <p className="empty-state">
                {scanUnreached
                  ? (english
                    ? 'Scan verification status is UNREACHED — no final report body is available yet.'
                    : '当前扫描验证状态为 UNREACHED，尚无最终报告正文。')
                  : (english
                    ? 'No REPORT_GENERATION summary for this scan yet. The dashboard has no dedicated reportMarkdown field; the GUI loads the completed job’s MODEL_INFERENCE summary.'
                    : '当前扫描尚未生成 REPORT_GENERATION 摘要。Dashboard 无独立 reportMarkdown 字段；界面从已完成任务的 MODEL_INFERENCE 摘要加载。')}
              </p>
            ) : null}
            <p className="form-help">
              {english
                ? 'Open evidence sub-views below while the report is empty or incomplete.'
                : '报告为空或不完整时，可先查看下方证据子页面。'}
            </p>
            <div className="results-view-cards">
              {RESULTS_VIEWS.filter((view) => view !== 'report').map((view) => {
                const meta = viewMeta(view)
                return <button key={view} type="button" className="results-view-card" onClick={() => setActiveView(view)}>
                  <span>{meta.eyebrow}</span>
                  <strong>{meta.label}</strong>
                  <small>{meta.blurb}</small>
                  <b>{meta.count}</b>
                </button>
              })}
            </div>
          </div>
        )}
        {!reportEmpty && (
          <div className="results-view-cards section-gap" aria-label={english ? 'Open evidence sub-views' : '打开证据子页面'}>
            {RESULTS_VIEWS.filter((view) => view !== 'report').map((view) => {
              const meta = viewMeta(view)
              return <button key={view} type="button" className="results-view-card" onClick={() => setActiveView(view)}>
                <span>{meta.eyebrow}</span>
                <strong>{meta.label}</strong>
                <small>{meta.blurb}</small>
                <b>{meta.count}</b>
              </button>
            })}
          </div>
        )}
      </article>
    )}

    {activeView === 'pathRuns' && (
      <PathRunPanel
        pathRuns={pathRuns}
        entries={entries}
        scanId={snapshot?.scanId}
        english={english}
        onFocusEntry={focusEntry}
      />
    )}

    {activeView === 'contrast' && (
      <div className="result-grid">
        <article className="panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">{english ? 'RANKED SINKS' : 'Sink 排序'}</p>
              <h2>{english ? 'Candidate sink ranking' : '候选 Sink 排序'}</h2>
            </div>
            <span>{rankedSinks.length}</span>
          </div>
          <p className="form-help">
            {english
              ? 'Deterministic CandidateRanker scores for PRE_ANALYSIS / triage focus. Score is a heuristic, not exploitability proof.'
              : 'CandidateRanker 确定性排序，供前置建模与研判聚焦；分数为启发式，不等于可利用证明。'}
          </p>
          <div className="card-list">
            {topRankedSinks.map((sink) => (
              <div className="list-card" key={sink.sinkId}>
                <div className="severity severity-medium">#{sink.rank}</div>
                <div>
                  <strong>{sink.symbol || sink.sinkId}</strong>
                  <small>{sink.category || '—'} · {english ? 'score' : '分数'} {sink.score.toFixed(2)}</small>
                  <small>{sink.rankReasons.length > 0 ? sink.rankReasons.join(' · ') : (english ? 'No rank reasons' : '无排序理由')}</small>
                </div>
              </div>
            ))}
            {rankedSinks.length === 0 && <p className="empty-state">{english ? 'No ranked sinks yet for this scan.' : '当前扫描尚无 Sink 排序结果。'}</p>}
          </div>
        </article>
        <article className="panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">{english ? 'LEDGER DIFF' : '对照账本差分'}</p>
              <h2>{english ? 'Contrast ledger delta' : '静态·动态对照差分'}</h2>
            </div>
            <span>{snapshot?.contrastRoundIndex != null ? `R${snapshot.contrastRoundIndex}` : '—'}</span>
          </div>
          <p className="form-help">
            {ledgerDiff?.summary
              || (english
                ? 'Compares prior PathRun coverage join against the current ContrastLedger (includes DYNAMIC_REACHED hits).'
                : '对比上一轮与当前 ContrastLedger（含 DYNAMIC_REACHED 命中）。')}
          </p>
          <dl className="ledger-diff-stats">
            <div><dt>{english ? 'Newly matched' : '本轮新命中'}</dt><dd>{ledgerDiff?.newlyMatched.length ?? 0}</dd></div>
            <div><dt>{english ? 'Regressions' : '回退'}</dt><dd>{ledgerDiff?.regressions.length ?? 0}</dd></div>
            <div><dt>{english ? 'Unchanged' : '未变'}</dt><dd>{ledgerDiff?.unchangedCount ?? 0}</dd></div>
            <div><dt>{english ? 'Coverage Δ' : '覆盖率变化'}</dt><dd>{formatCoverageDelta(ledgerDiff?.coverageDelta ?? 0)}</dd></div>
          </dl>
          {(ledgerDiff?.newlyMatched.length ?? 0) > 0 && (
            <p className="form-help">{english ? 'New hits' : '新命中'}：{ledgerDiff!.newlyMatched.slice(0, 8).join(', ')}{ledgerDiff!.newlyMatched.length > 8 ? '…' : ''}</p>
          )}
          {(ledgerDiff?.regressions.length ?? 0) > 0 && (
            <p className="form-help">{english ? 'Regressions' : '回退'}：{ledgerDiff!.regressions.slice(0, 8).join(', ')}{ledgerDiff!.regressions.length > 8 ? '…' : ''}</p>
          )}
          {snapshot?.contrastSnapshotId && (
            <p className="form-help">snapshot · {snapshot.contrastSnapshotId}</p>
          )}
        </article>
      </div>
    )}

    {activeView === 'verified' && (
      <article className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{english ? 'VERIFIED FINDINGS' : '已验证发现'}</p>
            <h2>{english ? 'Verified findings (gated)' : '已验证发现（门禁）'}</h2>
          </div>
          <span>{verifiedFindings.length}</span>
        </div>
        <p className="form-help">
          {english
            ? 'MVP-6 scaffolding: VerifiedStatusGate is fail-closed. Empty means no VERIFIED promotion yet — not a claim of zero risk. DYNAMIC_CONFIRMED remains in secondary findings.'
            : 'MVP-6 脚手架：VerifiedStatusGate 仍 fail-closed。空列表表示尚未升格 VERIFIED，不等于无风险。DYNAMIC_CONFIRMED 仍在次级发现中。'}
        </p>
        <div className="card-list">
          {verifiedFindings.map((item) => (
            <div className={`list-card verified-finding-card status-tone-${item.verificationStatus.toLowerCase()}`} key={item.findingId}>
              <div className={`severity severity-${item.severity ?? 'info'}`}>{item.severity ?? 'info'}</div>
              <div>
                <strong>{item.title || item.findingId}</strong>
                <small>{[item.entry, item.sink].filter(Boolean).join(' → ') || item.findingId}</small>
                {item.rootCause?.rootCauseStatement && <small>{item.rootCause.rootCauseStatement}</small>}
                {item.attestationRef && <small>attestation · {item.attestationRef}</small>}
              </div>
              <StatusPill status={item.verificationStatus} />
            </div>
          ))}
          {verifiedFindings.length === 0 && (
            <p className="empty-state">
              {english
                ? 'No verified_findings rows. Gate remains closed until escape attestation and replay evidence qualify.'
                : '尚无 verified_findings 行。在逃逸认证与可重放证据齐备前，门禁保持关闭。'}
            </p>
          )}
        </div>
      </article>
    )}

    {activeView === 'experiments' && (
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">{english ? 'SQL D3 CARDS' : 'SQL D3 实验卡'}</p><h2>{english ? 'Replayable SQL experiment cards' : '可重放 SQL 实验卡'}</h2></div><span>{sqlCards.length}</span></div>
        <p className="form-help">{english ? 'Built from benign vs meta PathRun pairs. Replay stays MOCK / DYNAMIC_SUSPECTED and never VERIFIED.' : '由良性 vs 元字符 PathRun 对生成；重放保持 MOCK / DYNAMIC_SUSPECTED，永不 VERIFIED。'}</p>
        {cardReplayError && <Notice kind="error">{cardReplayError}</Notice>}
        {cardReplayNotice && <Notice kind="info">{cardReplayNotice}</Notice>}
        <div className="card-list">{sqlCards.map((card) => <div className="list-card" key={card.cardId}><div><strong>{card.entrypointRef} · {card.track}</strong><small>{english ? 'Before' : '前'}：{card.sqlBefore}</small><small>{english ? 'After' : '后'}：{card.sqlAfter}</small><small>{card.dependencyMode} · {card.verificationStatus}{card.structureInfluenced ? (english ? ' · structure influenced' : ' · 结构受影响') : ''}</small></div><div className="button-row"><StatusPill status={card.verificationStatus} /><button type="button" className="secondary-button" disabled={!card.replayable || !!cardReplayLoading || card.verificationStatus === 'VERIFIED'} onClick={() => void replaySqlCard(card.cardId)}>{cardReplayLoading === card.cardId ? (english ? 'Replaying…' : '重放中…') : (english ? 'Replay card' : '重放实验卡')}</button></div></div>)}{sqlCards.length === 0 && <p className="empty-state">{english ? 'No D3 cards yet; need a benign + meta SQL PathRun pair.' : '尚无 D3 实验卡；需要良性与元字符 SQL PathRun 对。'}</p>}</div>
        {(probeBudget || experimentPlans.length > 0 || analysisPacks.length > 0) && <div className="section-gap"><small>{probeBudget ? (english ? `Probe budget: planned ${probeBudget.plannedProbes}/${probeBudget.maxProbes}, unreached ${probeBudget.unreachedEntries}. ${probeBudget.strategy}` : `探针预算：已规划 ${probeBudget.plannedProbes}/${probeBudget.maxProbes}，未达 ${probeBudget.unreachedEntries}。${probeBudget.strategy}`) : null}</small>{experimentPlans.length > 0 && <small>{english ? `Accepted experiment plans: ${experimentPlans.length}` : `已接受实验计划：${experimentPlans.length}`}</small>}{analysisPacks.length > 0 && <small>{english ? `Matched packs: ${analysisPacks.map((pack) => pack.packId).join(', ')} (non-destructive)` : `匹配语义包：${analysisPacks.map((pack) => pack.packId).join('、')}（无破坏）`}</small>}</div>}
        {experimentPlans.some((plan) => plan.fuzzStrategyJson || plan.fuzzStrategy) && (
          <div className="card-list section-gap">
            {experimentPlans.filter((plan) => plan.fuzzStrategyJson || plan.fuzzStrategy).map((plan) => (
              <div className="list-card" key={plan.planId}>
                <div>
                  <strong>{plan.planId} · {plan.track}</strong>
                  <small>{plan.method} {plan.entrypointRef}</small>
                  <small className="fuzz-strategy-line">{english ? 'Fuzz strategy' : 'Fuzz 策略'}：{(plan.fuzzStrategyJson || plan.fuzzStrategy || '').slice(0, 240)}</small>
                </div>
              </div>
            ))}
          </div>
        )}
      </article>
    )}

    {activeView === 'findings' && <>
      <div className="result-grid">
        <article className="panel">
          <div className="panel-head"><div><p className="eyebrow">{english ? 'SECONDARY FINDINGS' : '次级发现'}</p><h2>{english ? 'Findings (secondary)' : '发现（次级）'}</h2></div><span>{filteredFindings.length}</span></div>
          <div className="finding-toolbar"><label className="field"><span>{english ? 'Filter findings' : '筛选发现'}</span><input value={findingQuery} onChange={(event) => setFindingQuery(event.target.value)} placeholder={english ? 'Title, entry, sink...' : '标题、入口或 sink…'} /></label><label className="field"><span>{english ? 'Evidence status' : '证据状态'}</span><select value={findingStatus} onChange={(event) => setFindingStatus(event.target.value as typeof findingStatus)}><option value="ALL">{english ? 'All statuses' : '全部状态'}</option><option value="STATIC_INFERRED">STATIC_INFERRED</option><option value="DYNAMIC_SUSPECTED">DYNAMIC_SUSPECTED</option><option value="DYNAMIC_CONFIRMED">DYNAMIC_CONFIRMED</option><option value="VERIFIED">VERIFIED</option><option value="UNREACHED">UNREACHED</option></select></label><label className="field checkbox-field"><span>{english ? 'Show AUTH_GAP' : '显示 AUTH_GAP'}</span><input type="checkbox" checked={showAuthGap} onChange={(event) => setShowAuthGap(event.target.checked)} /></label></div>
          <div className="card-list">{filteredFindings.map((finding) => <button type="button" className={`finding-card finding-card-button status-tone-${finding.status.toLowerCase()} ${finding.id === selectedFinding?.id ? 'selected' : ''}`} key={finding.id} onClick={() => { setSelectedFindingId(finding.id); setSelectedStepIndex(0) }}><div className={`severity severity-${finding.severity}`}>{finding.severity}</div><div><strong>{finding.title}</strong><small>{finding.entry} → {finding.sink}</small><small>{finding.evidence} {english ? 'evidence items' : '条证据'} · {finding.dependency === 'none' && !english ? '无外部依赖记录' : finding.dependency}</small></div><StatusPill status={finding.status} /></button>)}{filteredFindings.length === 0 && <p className="empty-state">{english ? 'No findings match the current filter.' : '没有符合当前筛选条件的发现。'}</p>}</div>
        </article>
        <article className="panel">
          <div className="panel-head"><div><p className="eyebrow">{english ? 'ENTRY COVERAGE' : '入口覆盖'}</p><h2>{english ? 'Entries and coverage' : '入口与覆盖'}</h2></div><span>{dependencyModeLabel(snapshot?.dependencyMode)}</span></div>
          <div className="card-list">{entries.map((entry) => <div className="list-card" key={entry.id}><div><strong>{entry.method} {entry.route}</strong><small>{entry.module} · {entry.precondition} · {english ? `coverage ${entry.coverage}%` : `覆盖 ${entry.coverage}%`}</small></div><StatusPill status={entry.status} /></div>)}{entries.length === 0 && <p className="empty-state">{english ? 'No entries are available; this does not imply an empty attack surface.' : '暂无入口；这不表示攻击面为空。'}</p>}</div>
        </article>
      </div>
      <div className="chain-layout section-gap">
        <article className="panel chain-panel">
          <div className="panel-head"><div><p className="eyebrow">{english ? 'ATTACK CHAIN' : '攻击链'}</p><h2>{english ? 'Evidence path' : '证据链路'}</h2></div><span>{selectedPath ? `${selectedPath.steps.length} ${english ? 'nodes' : '个节点'}` : (english ? 'No path' : '暂无路径')}</span></div>
          {selectedPath ? <div className="chain-board" role="list" aria-label={english ? 'Evidence path nodes' : '证据路径节点'}>{selectedPath.steps.map((step, index) => <div className="chain-node-wrap" key={`${step.label}-${index}`}><button type="button" role="listitem" className={`chain-node chain-node-${step.kind} ${index === selectedStepIndex ? 'selected' : ''}`} onClick={() => setSelectedStepIndex(index)}><span>{index + 1}</span><strong>{step.label}</strong><small>{step.kind} · {step.state}</small></button>{index < selectedPath.steps.length - 1 && <span className="chain-connector" aria-hidden="true">→</span>}</div>)}</div> : <p className="empty-state">{english ? 'Select a finding with a path to inspect its evidence chain.' : '选择带有路径的发现以查看证据链。'}</p>}
        </article>
        <article className="panel detail-panel">
          <div className="panel-head"><div><p className="eyebrow">{english ? 'SELECTED EVIDENCE' : '选中证据'}</p><h2>{selectedFinding ? selectedFinding.title : (english ? 'No finding selected' : '尚未选择发现')}</h2></div>{selectedFinding && <StatusPill status={selectedFinding.status} />}</div>
          {selectedFinding ? <div className="evidence-detail"><div className="button-row"><button type="button" className="secondary-button" onClick={() => void replaySelectedFinding()} disabled={replayLoading || selectedFinding.status === 'VERIFIED'}>{replayLoading ? (english ? 'Requesting…' : '正在请求…') : (english ? 'Request sandbox replay' : '请求沙箱重放')}</button><span className="form-help">{english ? 'The server owns the sandbox policy; this does not mark VERIFIED.' : '由服务端固定沙箱策略；重放不会直接标记为 VERIFIED。'}</span></div>{replayError && <Notice kind="error">{replayError}</Notice>}{replayResult && <Notice kind="info">{english ? `Replay task ${replayResult.taskId} is ${replayResult.lifecycle}.` : `重放任务 ${replayResult.taskId} 当前为 ${replayResult.lifecycle}。`}</Notice>}<dl><div><dt>{english ? 'Entry' : '入口'}</dt><dd>{selectedFinding.entry}</dd></div><div><dt>{english ? 'Sink' : 'Sink'}</dt><dd>{selectedFinding.sink}</dd></div><div><dt>{english ? 'Dependency' : '依赖'}</dt><dd>{selectedFinding.dependency}</dd></div><div><dt>{english ? 'Evidence refs' : '证据引用'}</dt><dd>{selectedFinding.evidenceRefs?.length ?? selectedFinding.evidence}</dd></div><div><dt>{english ? 'Evidence status' : '证据状态'}</dt><dd><StatusPill status={selectedFinding.status} />{selectedFinding.status === 'DYNAMIC_CONFIRMED' ? (english ? ' · MOCK SQL confirm, not VERIFIED' : ' · MOCK SQL 确认，非 VERIFIED') : null}{selectedFinding.status === 'VERIFIED' ? (english ? ' · gated replay attestation' : ' · 需门禁可重放认证') : null}</dd></div></dl>{selectedFinding.rootCause && <section className="root-cause-block"><h3>{english ? 'Root cause' : '根因'}</h3>{selectedFinding.rootCause.rootCauseStatement && <p>{selectedFinding.rootCause.rootCauseStatement}</p>}{(selectedFinding.rootCause.cweId || selectedFinding.rootCause.affectedComponent) && <small>{[selectedFinding.rootCause.cweId, selectedFinding.rootCause.affectedComponent].filter(Boolean).join(' · ')}</small>}{selectedFinding.rootCause.attackPath.length > 0 && <ol className="attack-step-list">{selectedFinding.rootCause.attackPath.map((step, index) => <li key={`${step.label}-${index}`}><strong>{step.layer}</strong> {step.label}<small>{step.evidenceRefs.join(', ')}</small></li>)}</ol>}{selectedFinding.rootCause.fixSuggestion && <p className="form-help">{english ? 'Fix' : '修复建议'}：{selectedFinding.rootCause.fixSuggestion}</p>}</section>}{selectedStep && <section><h3>{selectedStep.label}</h3><p>{selectedStep.detail}</p><small>{selectedStep.provenanceKind ?? 'INFERENCE'} · {selectedStep.eventType ?? 'STATIC_ANALYSIS'} · {selectedStep.verificationStatus ?? selectedPath?.verificationStatus}</small></section>}</div> : <p className="empty-state">{english ? 'Findings are evidence-bound and remain static until runtime proof exists.' : '发现必须绑定证据；没有运行时证明时仍保持静态推断。'}</p>}
        </article>
      </div>
      <article className="panel section-gap">
        <div className="panel-head"><div><p className="eyebrow">{english ? 'EVIDENCE PATH' : '证据路径'}</p><h2>{english ? 'Evidence timeline' : '证据时间线'}</h2></div><span>{english ? `${snapshot?.path.length ?? 0} steps` : `${snapshot?.path.length ?? 0} 步`}</span></div>
        <ol className="evidence-timeline">{snapshot?.path.map((step, index) => <li key={`${step.label}-${index}`}><span>{index + 1}</span><div><strong>{step.label}</strong><small>{step.detail}</small></div>{step.verificationStatus && <StatusPill status={step.verificationStatus} />}</li>)}{!snapshot?.path.length && <p className="empty-state">{english ? 'No evidence path is available.' : '尚无证据路径。'}</p>}</ol>
      </article>
    </>}
  </section>
}

function isAuthGapFinding(finding: { title?: string; sink?: string; sinkId?: string }): boolean {
  const sinkId = (finding.sinkId ?? '').toLocaleLowerCase()
  const sink = (finding.sink ?? '').toLocaleLowerCase()
  const title = finding.title ?? ''
  return sinkId.startsWith('sink-auth-gap')
    || sink.startsWith('sink-auth-gap')
    || title.includes('鉴权缺口')
    || title.toLocaleLowerCase().includes('auth gap')
}

function formatCoverageDelta(delta: number): string {
  const percent = delta * 100
  const sign = percent > 0 ? '+' : ''
  return `${sign}${percent.toFixed(0)}%`
}

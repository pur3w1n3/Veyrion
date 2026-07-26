import { useEffect, useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, type AiJobDto, type DashboardSnapshot, type FindingReplayDto, type OutputLanguage } from '../api'
import { dependencyModeLabel, jobStatusLabel } from '../labels'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'
import { PathRunPanel } from './PathRunPanel'

export function ResultsPage({ projectId, snapshot, language }: { projectId: string; snapshot: DashboardSnapshot | null; language: OutputLanguage }) {
  const english = language === 'EN'
  const findings = snapshot?.findings ?? []
  const entries = snapshot?.entries ?? []
  const [reportJob, setReportJob] = useState<AiJobDto>()
  const [reportSummary, setReportSummary] = useState<string>()
  const [reportError, setReportError] = useState<string>()
  const [reportLoading, setReportLoading] = useState(false)
  const [findingQuery, setFindingQuery] = useState('')
  const [findingStatus, setFindingStatus] = useState<'ALL' | 'STATIC_INFERRED' | 'DYNAMIC_SUSPECTED' | 'DYNAMIC_CONFIRMED' | 'VERIFIED' | 'UNREACHED'>('ALL')
  const [showAuthGap, setShowAuthGap] = useState(false)
  const pathRuns = snapshot?.pathRuns ?? []
  const authGapFindingCount = snapshot?.authGapFindingCount ?? findings.filter(isAuthGapFinding).length
  const [selectedFindingId, setSelectedFindingId] = useState<string>()
  const [selectedStepIndex, setSelectedStepIndex] = useState(0)
  const [replayLoading, setReplayLoading] = useState(false)
  const [replayError, setReplayError] = useState<string>()
  const [replayResult, setReplayResult] = useState<FindingReplayDto>()

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

  return <section>
    <PageHeader eyebrow={snapshot?.scanId ?? (english ? 'NO SCAN' : '尚无扫描')} title={english ? 'Audit results' : '审计结果'}>
      {english ? 'Every conclusion retains its evidence status. Static signals without runtime evidence must not be described as exploitable vulnerabilities.' : '每项结论保留独立证据状态；无动态证据时不得将静态命中描述为可利用漏洞。'}
    </PageHeader>
    <div className="metrics-grid">
      <article className="metric"><span>{english ? 'PathRuns' : 'PathRun'}</span><strong>{pathRuns.length}</strong><small>{english ? 'Primary session view' : '路径会话主视图'}</small></article>
      <article className="metric"><span>{english ? 'Dynamic confirmed' : '动态确认'}</span><strong>{pathRuns.filter((item) => item.verificationStatus === 'DYNAMIC_CONFIRMED').length}</strong><small>{english ? 'SQL H3 (MOCK)' : 'SQL H3（MOCK）'}</small></article>
      <article className="metric"><span>{english ? 'Dynamic suspected' : '动态疑似'}</span><strong>{pathRuns.filter((item) => item.verificationStatus === 'DYNAMIC_SUSPECTED').length + findings.filter((item) => item.status === 'DYNAMIC_SUSPECTED').length}</strong><small>{english ? 'Needs closed loop' : '需闭环'}</small></article>
      <article className="metric"><span>{english ? 'Secondary findings' : '次级发现'}</span><strong>{findings.filter((item) => !isAuthGapFinding(item)).length}</strong><small>{english ? `AUTH_GAP hidden: ${authGapFindingCount}` : `已隐藏 AUTH_GAP: ${authGapFindingCount}`}</small></article>
    </div>
    <PathRunPanel pathRuns={pathRuns} english={english} />
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">{english ? 'FINAL REPORT' : '最终报告'}</p><h2>{english ? 'Final report' : '最终报告'}</h2></div><div className="button-row"><span className="inference-badge">{english ? 'MODEL INFERENCE' : '模型推断'}</span>{reportSummary && <><button type="button" className="secondary-button" onClick={downloadReport}>{english ? 'Download .md' : '下载 .md'}</button><button type="button" className="secondary-button" onClick={downloadHtml}>{english ? 'Export .html' : '导出 .html'}</button></>}{snapshot && <button type="button" className="secondary-button" onClick={downloadJson}>{english ? 'Export .json' : '导出 .json'}</button>}</div></div>
      {reportError && <Notice kind="error">{reportError}</Notice>}
      {reportLoading && <p className="empty-state">{english ? 'Loading report events for this scan…' : '正在加载当前扫描的报告事件…'}</p>}
      {!reportLoading && reportSummary && <>
        <div className="ai-report"><ReactMarkdown skipHtml remarkPlugins={[remarkGfm]}>{reportSummary}</ReactMarkdown></div>
        <p className="form-help">{reportJob?.aiJobId} · {reportJob?.providerId} · {reportJob?.model} · {reportJob?.outputLanguage === 'ZH_CN' ? '简体中文' : (reportJob?.outputLanguage ?? (english ? 'UNKNOWN' : '未知'))}。{english ? 'This is evidence-grounded model inference, not VERIFIED evidence.' : '该内容是受证据约束的模型推断，不等于已验证。'}</p>
      </>}
      {!reportLoading && !reportSummary && reportJob && <p className="empty-state">
        {english ? `Report job ${reportJob.aiJobId} is ${reportJob.status}${reportJob.errorCode ? ` · ${reportJob.errorCode}` : ''}; no final inference summary is available.` : `报告任务 ${reportJob.aiJobId} 当前为 ${jobStatusLabel(reportJob.status)}${reportJob.errorCode ? ` · ${reportJob.errorCode}` : ''}，尚无最终推断摘要。`}
      </p>}
      {!reportLoading && !reportSummary && !reportJob && !reportError && <p className="empty-state">{english ? 'No report has been generated for this scan.' : '当前扫描尚未生成报告。'}</p>}
    </article>
    <div className="result-grid">
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">{english ? 'SECONDARY FINDINGS' : '次级发现'}</p><h2>{english ? 'Findings (secondary)' : '发现（次级）'}</h2></div><span>{filteredFindings.length}</span></div>
        <div className="finding-toolbar"><label className="field"><span>{english ? 'Filter findings' : '筛选发现'}</span><input value={findingQuery} onChange={(event) => setFindingQuery(event.target.value)} placeholder={english ? 'Title, entry, sink...' : '标题、入口或 sink…'} /></label><label className="field"><span>{english ? 'Evidence status' : '证据状态'}</span><select value={findingStatus} onChange={(event) => setFindingStatus(event.target.value as typeof findingStatus)}><option value="ALL">{english ? 'All statuses' : '全部状态'}</option><option value="STATIC_INFERRED">STATIC_INFERRED</option><option value="DYNAMIC_SUSPECTED">DYNAMIC_SUSPECTED</option><option value="DYNAMIC_CONFIRMED">DYNAMIC_CONFIRMED</option><option value="VERIFIED">VERIFIED</option><option value="UNREACHED">UNREACHED</option></select></label><label className="field checkbox-field"><span>{english ? 'Show AUTH_GAP' : '显示 AUTH_GAP'}</span><input type="checkbox" checked={showAuthGap} onChange={(event) => setShowAuthGap(event.target.checked)} /></label></div>
        <div className="card-list">{filteredFindings.map((finding) => <button type="button" className={`finding-card finding-card-button ${finding.id === selectedFinding?.id ? 'selected' : ''}`} key={finding.id} onClick={() => { setSelectedFindingId(finding.id); setSelectedStepIndex(0) }}><div className={`severity severity-${finding.severity}`}>{finding.severity}</div><div><strong>{finding.title}</strong><small>{finding.entry} → {finding.sink}</small><small>{finding.evidence} {english ? 'evidence items' : '条证据'} · {finding.dependency === 'none' && !english ? '无外部依赖记录' : finding.dependency}</small></div><StatusPill status={finding.status} /></button>)}{filteredFindings.length === 0 && <p className="empty-state">{english ? 'No findings match the current filter.' : '没有符合当前筛选条件的发现。'}</p>}</div>
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
        {selectedFinding ? <div className="evidence-detail"><div className="button-row"><button type="button" className="secondary-button" onClick={() => void replaySelectedFinding()} disabled={replayLoading || selectedFinding.status === 'VERIFIED'}>{replayLoading ? (english ? 'Requesting…' : '正在请求…') : (english ? 'Request sandbox replay' : '请求沙箱重放')}</button><span className="form-help">{english ? 'The server owns the sandbox policy; this does not mark VERIFIED.' : '由服务端固定沙箱策略；重放不会直接标记为 VERIFIED。'}</span></div>{replayError && <Notice kind="error">{replayError}</Notice>}{replayResult && <Notice kind="info">{english ? `Replay task ${replayResult.taskId} is ${replayResult.lifecycle}.` : `重放任务 ${replayResult.taskId} 当前为 ${replayResult.lifecycle}。`}</Notice>}<dl><div><dt>{english ? 'Entry' : '入口'}</dt><dd>{selectedFinding.entry}</dd></div><div><dt>{english ? 'Sink' : 'Sink'}</dt><dd>{selectedFinding.sink}</dd></div><div><dt>{english ? 'Dependency' : '依赖'}</dt><dd>{selectedFinding.dependency}</dd></div><div><dt>{english ? 'Evidence refs' : '证据引用'}</dt><dd>{selectedFinding.evidenceRefs?.length ?? selectedFinding.evidence}</dd></div></dl>{selectedStep && <section><h3>{selectedStep.label}</h3><p>{selectedStep.detail}</p><small>{selectedStep.provenanceKind ?? 'INFERENCE'} · {selectedStep.eventType ?? 'STATIC_ANALYSIS'} · {selectedStep.verificationStatus ?? selectedPath?.verificationStatus}</small></section>}</div> : <p className="empty-state">{english ? 'Findings are evidence-bound and remain static until runtime proof exists.' : '发现必须绑定证据；没有运行时证明时仍保持静态推断。'}</p>}
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">{english ? 'EVIDENCE PATH' : '证据路径'}</p><h2>{english ? 'Evidence timeline' : '证据时间线'}</h2></div><span>{english ? `${snapshot?.path.length ?? 0} steps` : `${snapshot?.path.length ?? 0} 步`}</span></div>
      <ol className="evidence-timeline">{snapshot?.path.map((step, index) => <li key={`${step.label}-${index}`}><span>{index + 1}</span><div><strong>{step.label}</strong><small>{step.detail}</small></div>{step.verificationStatus && <StatusPill status={step.verificationStatus} />}</li>)}{!snapshot?.path.length && <p className="empty-state">{english ? 'No evidence path is available.' : '尚无证据路径。'}</p>}</ol>
    </article>
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

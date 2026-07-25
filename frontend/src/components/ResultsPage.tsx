import { useEffect, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, type AiJobDto, type DashboardSnapshot, type OutputLanguage } from '../api'
import { dependencyModeLabel, jobStatusLabel } from '../labels'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

export function ResultsPage({ projectId, snapshot, language }: { projectId: string; snapshot: DashboardSnapshot | null; language: OutputLanguage }) {
  const english = language === 'EN'
  const findings = snapshot?.findings ?? []
  const entries = snapshot?.entries ?? []
  const [reportJob, setReportJob] = useState<AiJobDto>()
  const [reportSummary, setReportSummary] = useState<string>()
  const [reportError, setReportError] = useState<string>()
  const [reportLoading, setReportLoading] = useState(false)

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

  const downloadReport = () => {
    if (!reportSummary || !snapshot?.scanId) return
    const safeScanId = snapshot.scanId.replace(/[^A-Za-z0-9._-]/g, '_')
    const url = URL.createObjectURL(new Blob([reportSummary], { type: 'text/markdown;charset=utf-8' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `veyrion-report-${safeScanId}.md`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  return <section>
    <PageHeader eyebrow={snapshot?.scanId ?? (english ? 'NO SCAN' : '尚无扫描')} title={english ? 'Audit results' : '审计结果'}>
      {english ? 'Every conclusion retains its evidence status. Static signals without runtime evidence must not be described as exploitable vulnerabilities.' : '每项结论保留独立证据状态；无动态证据时不得将静态命中描述为可利用漏洞。'}
    </PageHeader>
    <div className="metrics-grid">
      <article className="metric"><span>{english ? 'Entries' : '入口'}</span><strong>{entries.length}</strong><small>{entries.filter((item) => item.status === 'UNREACHED').length} {english ? 'uncovered' : '未覆盖'}</small></article>
      <article className="metric"><span>{english ? 'Static inference' : '静态推断'}</span><strong>{findings.filter((item) => item.status === 'STATIC_INFERRED').length}</strong><small>{english ? 'Runtime evidence required' : '需运行时证据'}</small></article>
      <article className="metric"><span>{english ? 'Dynamic suspected' : '动态疑似'}</span><strong>{findings.filter((item) => item.status === 'DYNAMIC_SUSPECTED').length}</strong><small>{english ? 'Replayable validation required' : '需可重放验证'}</small></article>
      <article className="metric"><span>{english ? 'Verified' : '已验证'}</span><strong>{findings.filter((item) => item.status === 'VERIFIED').length}</strong><small>{english ? 'Highest evidence boundary' : '证据边界最高等级'}</small></article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">{english ? 'FINAL REPORT' : '最终报告'}</p><h2>{english ? 'Final report' : '最终报告'}</h2></div><div className="button-row"><span className="inference-badge">{english ? 'MODEL INFERENCE' : '模型推断'}</span>{reportSummary && <button type="button" className="secondary-button" onClick={downloadReport}>{english ? 'Download .md' : '下载 .md'}</button>}</div></div>
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
        <div className="panel-head"><div><p className="eyebrow">{english ? 'FINDINGS' : '发现'}</p><h2>{english ? 'Findings' : '发现'}</h2></div><span>{findings.length}</span></div>
        <div className="card-list">{findings.map((finding) => <div className="finding-card" key={finding.id}><div className={`severity severity-${finding.severity}`}>{finding.severity}</div><div><strong>{finding.title}</strong><small>{finding.entry} → {finding.sink}</small><small>{finding.evidence} {english ? 'evidence items' : '条证据'} · {finding.dependency === 'none' && !english ? '无外部依赖记录' : finding.dependency}</small></div><StatusPill status={finding.status} /></div>)}{findings.length === 0 && <p className="empty-state">{english ? 'The backend has returned no findings.' : '后端尚未返回发现。'}</p>}</div>
      </article>
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">{english ? 'ENTRY COVERAGE' : '入口覆盖'}</p><h2>{english ? 'Entries and coverage' : '入口与覆盖'}</h2></div><span>{dependencyModeLabel(snapshot?.dependencyMode)}</span></div>
        <div className="card-list">{entries.map((entry) => <div className="list-card" key={entry.id}><div><strong>{entry.method} {entry.route}</strong><small>{entry.module} · {entry.precondition} · {english ? `coverage ${entry.coverage}%` : `覆盖 ${entry.coverage}%`}</small></div><StatusPill status={entry.status} /></div>)}{entries.length === 0 && <p className="empty-state">{english ? 'No entries are available; this does not imply an empty attack surface.' : '暂无入口；这不表示攻击面为空。'}</p>}</div>
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">{english ? 'EVIDENCE PATH' : '证据路径'}</p><h2>{english ? 'Evidence timeline' : '证据时间线'}</h2></div><span>{english ? `${snapshot?.path.length ?? 0} steps` : `${snapshot?.path.length ?? 0} 步`}</span></div>
      <ol className="evidence-timeline">{snapshot?.path.map((step, index) => <li key={`${step.label}-${index}`}><span>{index + 1}</span><div><strong>{step.label}</strong><small>{step.detail}</small></div>{step.verificationStatus && <StatusPill status={step.verificationStatus} />}</li>)}{!snapshot?.path.length && <p className="empty-state">{english ? 'No evidence path is available.' : '尚无证据路径。'}</p>}</ol>
    </article>
  </section>
}

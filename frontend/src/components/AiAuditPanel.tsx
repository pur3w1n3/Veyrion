import { useEffect, useRef, useState } from 'react'
import { api, type AiJobDto, type AiJobEventDto } from '../api'
import { confirmAiAuthorization } from '../aiAuthorization'
import { errorMessage, Notice } from './Common'

const roles = ['PRE_ANALYSIS', 'PATH_EXPLORATION', 'VULNERABILITY_TRIAGE', 'REPORT_GENERATION'] as const

export function AiAuditPanel({ projectId, scanId }: { projectId: string; scanId?: string }) {
  const [jobs, setJobs] = useState<AiJobDto[]>([])
  const [selectedJobId, setSelectedJobId] = useState<string>()
  const [events, setEvents] = useState<AiJobEventDto[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingEvents, setLoadingEvents] = useState(false)
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string>()
  const jobRequestRef = useRef(0)
  const eventRequestRef = useRef(0)

  const refresh = () => {
    const requestId = ++jobRequestRef.current
    setLoading(true)
    setError(undefined)
    if (!projectId) {
      setJobs([])
      setLoading(false)
      return
    }
    void api.listAiJobs(projectId)
      .then((items) => {
        if (jobRequestRef.current === requestId) {
          setJobs([...items].sort((left, right) => right.createdAt.localeCompare(left.createdAt)))
        }
      })
      .catch((cause) => {
        if (jobRequestRef.current === requestId) setError(errorMessage(cause))
      })
      .finally(() => {
        if (jobRequestRef.current === requestId) setLoading(false)
      })
  }

  useEffect(() => {
    setSelectedJobId(undefined)
    setEvents([])
    setLoadingEvents(false)
    refresh()
  }, [projectId])

  useEffect(() => {
    if (!jobs.some((job) => job.status === 'QUEUED' || job.status === 'RUNNING')) return
    const timer = window.setTimeout(refresh, 1500)
    return () => window.clearTimeout(timer)
  }, [jobs])

  const selectedStatus = jobs.find((job) => job.aiJobId === selectedJobId)?.status
  useEffect(() => {
    if (!selectedJobId || (selectedStatus !== 'QUEUED' && selectedStatus !== 'RUNNING')) return
    const timer = window.setInterval(() => {
      const requestId = ++eventRequestRef.current
      void api.listAiJobEvents(selectedJobId).then((items) => {
        if (eventRequestRef.current === requestId) setEvents(items)
      }).catch((cause) => {
        if (eventRequestRef.current === requestId) setError(errorMessage(cause))
      })
    }, 1000)
    return () => window.clearInterval(timer)
  }, [selectedJobId, selectedStatus])

  const inspect = (aiJobId: string) => {
    const requestId = ++eventRequestRef.current
    setSelectedJobId(aiJobId)
    setEvents([])
    setLoadingEvents(true)
    setError(undefined)
    void api.listAiJobEvents(aiJobId)
      .then((items) => {
        if (eventRequestRef.current === requestId) setEvents(items)
      })
      .catch((cause) => {
        if (eventRequestRef.current === requestId) setError(errorMessage(cause))
      })
      .finally(() => {
        if (eventRequestRef.current === requestId) setLoadingEvents(false)
      })
  }

  const recreateJobs = () => {
    if (!projectId || !scanId || !confirmAiAuthorization()) return
    setCreating(true)
    setError(undefined)
    void Promise.allSettled(roles.map((role) => api.createAiJob(projectId, { role, scanId, authorized: true })))
      .then((results) => {
        const failed = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
        if (failed) setError(`部分或全部任务创建失败：${errorMessage(failed.reason)}`)
        refresh()
      })
      .finally(() => setCreating(false))
  }

  const deleteUnsuccessful = () => {
    const removable = jobs.filter((job) => ['FAILED', 'BLOCKED', 'CANCELLED'].includes(job.status))
    if (removable.length === 0 || !window.confirm(`删除 ${removable.length} 条失败、阻断或取消的 AI Job 及其事件？`)) return
    setDeleting(true)
    setError(undefined)
    void Promise.allSettled(removable.map((job) => api.deleteAiJob(job.aiJobId)))
      .then((results) => {
        const failed = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
        if (failed) setError(`部分记录删除失败：${errorMessage(failed.reason)}`)
        if (selectedJobId && removable.some((job) => job.aiJobId === selectedJobId)) {
          setSelectedJobId(undefined)
          setEvents([])
        }
        refresh()
      })
      .finally(() => setDeleting(false))
  }

  return <article className="panel section-gap">
    <div className="panel-head">
      <div><p className="eyebrow">AI AUDIT PROCESS</p><h2>AI 执行与工具过程</h2></div>
      <div className="button-row">
        <button className="secondary-button" type="button" disabled={creating || !projectId || !scanId} onClick={recreateJobs}>{creating ? '创建中…' : '为当前扫描创建四角色任务'}</button>
        <button className="text-button" type="button" disabled={deleting || !jobs.some((job) => ['FAILED', 'BLOCKED', 'CANCELLED'].includes(job.status))} onClick={deleteUnsuccessful}>{deleting ? '删除中…' : '清理失败记录'}</button>
        <button className="text-button" type="button" disabled={loading || !projectId} onClick={refresh}>{loading ? '刷新中…' : '刷新'}</button>
      </div>
    </div>
    <p className="form-help">仅展示后端持久化的执行阶段、Provider 元数据、工具调用/结果与模型推断摘要；不会记录或还原模型隐藏思维链。</p>
    {!scanId && <Notice kind="info">请先创建静态扫描，AI Job 必须显式绑定一个不可变扫描快照。</Notice>}
    {error && <Notice kind="error">{error}</Notice>}
    {jobs.some((job) => job.status === 'FAILED' && job.errorCode === 'HTTP_400') && <Notice kind="info">列表中的 HTTP_400 是修复前已终止的历史任务，状态不会被后台改写或自动重试；请清理失败记录后，在“模型服务”或本页重新创建任务。</Notice>}
    <div className="card-list">
      {jobs.map((job) => <div className="list-card" key={job.aiJobId}>
        <div><strong>{job.role}</strong><small>{job.aiJobId} · {job.createdAt}{job.errorCode ? ` · ${job.errorCode}` : ''}</small></div>
        <div className="button-row"><span className="locked-tag">{job.status}</span><button className="text-button" type="button" onClick={() => inspect(job.aiJobId)}>查看审计过程</button></div>
      </div>)}
      {!loading && jobs.length === 0 && <p className="empty-state">暂无 AI Job；请先在全局设置完成角色分配并创建任务。</p>}
    </div>
    {selectedJobId && <div className="section-gap">
      <div className="panel-head"><div><p className="eyebrow">AI JOB AUDIT</p><h2>执行事件</h2></div><span>{selectedJobId}</span></div>
      {loadingEvents
        ? <p className="empty-state">加载审计事件…</p>
        : <ol className="workflow-timeline">{events.map((event) => {
            const details = [
              event.providerRequestSummary && `请求：${event.providerRequestSummary}`,
              event.providerResultSummary && `Provider：${event.providerResultSummary}`,
              event.toolCallName && `工具：${event.toolCallName}${event.toolArgumentsSummary ? ` · ${event.toolArgumentsSummary}` : ''}`,
              event.toolResultStatus && `工具结果：${event.toolResultStatus}`,
              event.modelInferenceSummary && `模型推断摘要：${event.modelInferenceSummary}`,
              event.failureDiagnostic && `失败详情：${event.failureDiagnostic}`
            ].filter(Boolean).join('；')
            return <li className={event.status === 'FAILED' ? 'timeline-unavailable' : event.status === 'COMPLETED' ? 'timeline-completed' : 'timeline-active'} key={event.sequence}>
              <span>{event.sequence}</span><div><strong>{event.stage}</strong><small>{details || event.createdAt}</small></div><b>{event.status}</b>
            </li>
          })}</ol>}
      {!loadingEvents && events.length === 0 && <p className="empty-state">该任务没有可展示的详细事件；历史任务只保留迁移时可用的状态与失败代码。</p>}
    </div>}
  </article>
}

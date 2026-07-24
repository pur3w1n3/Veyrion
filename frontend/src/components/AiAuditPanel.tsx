import { useEffect, useRef, useState } from 'react'
import { api, type AiJobDto, type AiJobEventDto } from '../api'
import { errorMessage, Notice } from './Common'

export function AiAuditPanel({ projectId }: { projectId: string }) {
  const [jobs, setJobs] = useState<AiJobDto[]>([])
  const [selectedJobId, setSelectedJobId] = useState<string>()
  const [events, setEvents] = useState<AiJobEventDto[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingEvents, setLoadingEvents] = useState(false)
  const [error, setError] = useState<string>()
  const requestRef = useRef(0)

  const refresh = () => {
    const requestId = ++requestRef.current
    setLoading(true)
    setError(undefined)
    if (!projectId) {
      setJobs([])
      setLoading(false)
      return
    }
    void api.listAiJobs(projectId)
      .then((items) => {
        if (requestRef.current === requestId) setJobs(items)
      })
      .catch((cause) => {
        if (requestRef.current === requestId) setError(errorMessage(cause))
      })
      .finally(() => {
        if (requestRef.current === requestId) setLoading(false)
      })
  }

  useEffect(() => {
    setSelectedJobId(undefined)
    setEvents([])
    setLoadingEvents(false)
    refresh()
  }, [projectId])

  const inspect = (aiJobId: string) => {
    const requestId = ++requestRef.current
    setSelectedJobId(aiJobId)
    setEvents([])
    setLoadingEvents(true)
    setError(undefined)
    void api.listAiJobEvents(aiJobId)
      .then((items) => {
        if (requestRef.current === requestId) setEvents(items)
      })
      .catch((cause) => {
        if (requestRef.current === requestId) setError(errorMessage(cause))
      })
      .finally(() => {
        if (requestRef.current === requestId) setLoadingEvents(false)
      })
  }

  return <article className="panel section-gap">
    <div className="panel-head">
      <div><p className="eyebrow">AI AUDIT PROCESS</p><h2>AI 执行与工具过程</h2></div>
      <button className="text-button" type="button" disabled={loading || !projectId} onClick={refresh}>
        {loading ? '刷新中…' : '刷新'}
      </button>
    </div>
    <p className="form-help">仅展示后端持久化的执行阶段、Provider 元数据、工具调用/结果与模型推断摘要；不会记录或还原模型隐藏思维链。</p>
    {error && <Notice kind="error">{error}</Notice>}
    {jobs.some((job) => job.status === 'FAILED' && job.errorCode === 'HTTP_400') && <Notice kind="info">列表中的 HTTP_400 是修复前已终止的历史任务，状态不会被后台改写或自动重试；请在全局设置重新创建对应角色任务。</Notice>}
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

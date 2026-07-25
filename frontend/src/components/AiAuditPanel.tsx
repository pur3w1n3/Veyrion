import { useEffect, useRef, useState } from 'react'
import { api, type AiJobDto, type AiJobEventDto, type OutputLanguage } from '../api'
import { errorMessage, Notice } from './Common'

const flowForStage = (stage: string, english: boolean): string => {
  const flows: Record<string, [string, string]> = {
    LIFECYCLE: ['Control Plane → 编排器', 'Control Plane → Orchestrator'],
    PROVIDER_REQUEST: ['证据事实 → Provider', 'Evidence facts → Provider'],
    PROVIDER_RESPONSE: ['Provider → 适配器', 'Provider → Adapter'],
    PROVIDER_RESULT: ['适配器 → 编排器', 'Adapter → Orchestrator'],
    TOOL_CALL: ['模型决策 → 服务端白名单工具 → 有界结果', 'Model decision → server allowlisted tool → bounded result'],
    MODEL_INFERENCE: ['证据摘要 → 最终推断', 'Evidence summaries → final inference'],
    FAILURE: ['执行组件 → 失败状态', 'Component → failure state']
  }
  return flows[stage]?.[english ? 1 : 0] ?? (english ? 'Persisted stage → next component' : '持久化阶段 → 下一组件')
}

const decisionSummary = (event: AiJobEventDto, english: boolean): string =>
  event.providerRequestSummary
  ?? (event.toolCallName
    ? `${event.toolCallName}${event.toolArgumentsSummary ? ` · ${event.toolArgumentsSummary}` : ''}`
    : undefined)
  ?? event.modelInferenceSummary
  ?? (english ? 'No auditable decision summary was persisted for this event.' : '该事件未持久化可审计决策摘要。')

const executionResult = (event: AiJobEventDto, english: boolean): string =>
  event.failureDiagnostic
  ?? event.providerResultSummary
  ?? (event.toolResultStatus ? `${event.toolResultStatus}` : undefined)
  ?? event.modelInferenceSummary
  ?? `${event.status}${english ? ' (no additional result was persisted)' : '（未持久化其他结果）'}`

const nextStep = (event: AiJobEventDto, english: boolean): string => {
  if (event.status === 'FAILED' || event.stage === 'FAILURE') {
    return english ? 'Review the persisted failure diagnostic; no automatic success is inferred.' : '复核已持久化的失败诊断；不会自动推断为成功。'
  }
  if (event.status === 'CANCELLED' || event.status === 'BLOCKED') {
    return english ? 'The job remains terminal until an operator starts a new authorized job.' : '任务保持终态，需操作员重新创建已授权 Job。'
  }
  const nextByStage: Record<string, [string, string]> = {
    LIFECYCLE: ['等待编排器记录下一阶段', 'Wait for the orchestrator to persist the next stage'],
    PROVIDER_REQUEST: ['等待 Provider 响应', 'Wait for the provider response'],
    PROVIDER_RESPONSE: ['由适配器校验并记录协议结果', 'Validate and persist the protocol result in the adapter'],
    PROVIDER_RESULT: ['由编排器决定有界工具调用或最终推断', 'Let the orchestrator proceed to a bounded tool call or final inference'],
    TOOL_CALL: ['将有界工具结果交回编排器', 'Return the bounded tool result to the orchestrator'],
    MODEL_INFERENCE: ['保留为 AI INFERENCE，不提升为 VERIFIED', 'Retain as AI INFERENCE; do not promote to VERIFIED']
  }
  return nextByStage[event.stage]?.[english ? 1 : 0] ?? (english ? 'Wait for the next persisted event.' : '等待下一条持久化事件。')
}

export function AiAuditPanel({ projectId, scanId, language }: { projectId: string; scanId?: string; language: OutputLanguage }) {
  const english = language === 'EN'
  const [jobs, setJobs] = useState<AiJobDto[]>([])
  const [selectedJobId, setSelectedJobId] = useState<string>()
  const [events, setEvents] = useState<AiJobEventDto[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingEvents, setLoadingEvents] = useState(false)
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
          setJobs(items
            .filter((job) => !scanId || job.scanId === scanId)
            .sort((left, right) => right.createdAt.localeCompare(left.createdAt)))
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
  }, [projectId, scanId])

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

  const deleteUnsuccessful = () => {
    const removable = jobs.filter((job) => ['FAILED', 'BLOCKED', 'CANCELLED'].includes(job.status))
    if (removable.length === 0 || !window.confirm(english
      ? `Delete ${removable.length} failed, blocked, or cancelled AI jobs and their events?`
      : `删除 ${removable.length} 条失败、阻断或取消的 AI Job 及其事件？`)) return
    setDeleting(true)
    setError(undefined)
    void Promise.allSettled(removable.map((job) => api.deleteAiJob(job.aiJobId)))
      .then((results) => {
        const failed = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
        if (failed) setError(english ? `Some records could not be deleted: ${errorMessage(failed.reason)}` : `部分记录删除失败：${errorMessage(failed.reason)}`)
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
      <div><p className="eyebrow">AI AUDIT PROCESS</p><h2>{english ? 'AI execution and tool flow' : 'AI 执行与工具过程'}</h2></div>
      <div className="button-row">
        <button className="text-button" type="button" disabled={deleting || !jobs.some((job) => ['FAILED', 'BLOCKED', 'CANCELLED'].includes(job.status))} onClick={deleteUnsuccessful}>{deleting ? (english ? 'Deleting…' : '删除中…') : (english ? 'Clear failed records' : '清理失败记录')}</button>
        <button className="text-button" type="button" disabled={loading || !projectId} onClick={refresh}>{loading ? (english ? 'Refreshing…' : '刷新中…') : (english ? 'Refresh' : '刷新')}</button>
      </div>
    </div>
    <p className="form-help">{english ? 'Only persisted stages, provider metadata, tool calls/results, and inference summaries are shown. Hidden chain-of-thought is neither stored nor reconstructed.' : '仅展示后端持久化的执行阶段、Provider 元数据、工具调用/结果与模型推断摘要；不会记录或还原模型隐藏思维链。'}</p>
    {!scanId && <Notice kind="info">{english ? 'Start an audit first; AI jobs are created by the staged audit workflow.' : '请先在“审计执行”启动审计；AI Job 会按审计阶段自动或经计划评审创建。'}</Notice>}
    {error && <Notice kind="error">{error}</Notice>}
    {jobs.some((job) => job.status === 'FAILED' && job.errorCode === 'HTTP_400') && <Notice kind="info">{english
      ? 'HTTP_400 entries are immutable historical jobs. They are not rewritten or retried automatically; clear them and create a new authorized job from the audit workflow.'
      : '列表中的 HTTP_400 是修复前已终止的历史任务，状态不会被后台改写或自动重试；请清理失败记录后，从审计流程重新创建已授权任务。'}</Notice>}
    <div className="card-list">
      {jobs.map((job) => <div className="list-card" key={job.aiJobId}>
        <div><strong>{job.role}</strong><small>{job.aiJobId} · {job.createdAt}{job.outputLanguage ? ` · ${job.outputLanguage}` : ''}{job.errorCode ? ` · ${job.errorCode}` : ''}</small></div>
        <div className="button-row"><span className="locked-tag">{job.status}</span><button className="text-button" type="button" onClick={() => inspect(job.aiJobId)}>{english ? 'Inspect audit flow' : '查看审计过程'}</button></div>
      </div>)}
      {!loading && jobs.length === 0 && <p className="empty-state">{english ? 'No AI jobs. Configure roles, then start an audit.' : '暂无 AI Job；请先配置角色，然后在“审计执行”开始审计。'}</p>}
    </div>
    {selectedJobId && <div className="section-gap">
      <div className="panel-head"><div><p className="eyebrow">AI JOB AUDIT</p><h2>{english ? 'Execution events' : '执行事件'}</h2></div><span>{selectedJobId}</span></div>
      {loadingEvents
        ? <p className="empty-state">{english ? 'Loading audit events…' : '加载审计事件…'}</p>
        : <div className="audit-flow-list">{events.map((event) =>
          <details className={`audit-flow-event ${event.status === 'FAILED' ? 'flow-failed' : ''}`} key={event.sequence}>
            <summary><span>{event.sequence}</span><strong>{event.stage}</strong><small>{event.createdAt}</small><b>{event.status}</b></summary>
            <div className="audit-flow-body">
              <section><h3>{english ? 'Data source / flow' : '数据来源 / 流向'}</h3><p>{flowForStage(event.stage, english)}</p></section>
              <section><h3>{english ? 'Auditable decision summary (not hidden chain-of-thought)' : '可审计决策摘要（明确不是隐藏思维链）'}</h3><p>{decisionSummary(event, english)}</p></section>
              <section><h3>{english ? 'Execution result' : '执行结果'}</h3><p>{executionResult(event, english)}</p></section>
              <section><h3>{english ? 'Next step' : '下一步'}</h3><p>{nextStep(event, english)}</p></section>
            </div>
          </details>
        )}</div>}
      {!loadingEvents && events.length === 0 && <p className="empty-state">{english ? 'No detailed events are available; migrated jobs may retain only status and failure codes.' : '该任务没有可展示的详细事件；历史任务只保留迁移时可用的状态与失败代码。'}</p>}
    </div>}
  </article>
}

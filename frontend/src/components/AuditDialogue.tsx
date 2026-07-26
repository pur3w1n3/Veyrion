import { useEffect, useMemo, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, type AiJobDto, type AiJobEventDto, type DynamicTaskDto } from '../api'
import { jobStatusLabel, roleLabel } from '../labels'
import { errorMessage, Notice } from './Common'

type ChatBubble = {
  id: string
  kind: 'system' | 'user' | 'thinking' | 'assistant' | 'tool' | 'status'
  roleTitle: string
  title: string
  body: string
  createdAt: string
}

const stageTitle = (stage: string) => {
  switch (stage) {
    case 'PROMPT_SYSTEM':
      return '系统提示词'
    case 'PROMPT_USER':
      return '任务说明'
    case 'MODEL_THINKING':
      return '模型思考'
    case 'MODEL_OUTPUT':
      return '中间输出'
    case 'MODEL_INFERENCE':
      return '最终输出'
    case 'TOOL_CALL':
      return '工具调用'
    case 'PROVIDER_REQUEST':
      return '已向模型服务发请求'
    case 'PROVIDER_RESPONSE':
      return '模型服务已响应'
    case 'PROVIDER_RESULT':
      return '模型服务结果摘要'
    case 'LIFECYCLE':
      return '任务生命周期'
    case 'FAILURE':
      return '失败'
    default:
      return stage
  }
}

const toBubbles = (job: AiJobDto, events: AiJobEventDto[]): ChatBubble[] => {
  const roleTitle = roleLabel(job.role)
  const bubbles: ChatBubble[] = []
  for (const event of events) {
    if (event.stage === 'PROMPT_SYSTEM' && event.modelInferenceSummary) {
      bubbles.push({
        id: `${job.aiJobId}-${event.sequence}`,
        kind: 'system',
        roleTitle,
        title: stageTitle(event.stage),
        body: event.modelInferenceSummary,
        createdAt: event.createdAt
      })
      continue
    }
    if (event.stage === 'PROMPT_USER' && event.modelInferenceSummary) {
      bubbles.push({
        id: `${job.aiJobId}-${event.sequence}`,
        kind: 'user',
        roleTitle,
        title: stageTitle(event.stage),
        body: event.modelInferenceSummary,
        createdAt: event.createdAt
      })
      continue
    }
    if (event.stage === 'MODEL_THINKING' && event.modelInferenceSummary) {
      bubbles.push({
        id: `${job.aiJobId}-${event.sequence}`,
        kind: 'thinking',
        roleTitle,
        title: stageTitle(event.stage),
        body: event.modelInferenceSummary,
        createdAt: event.createdAt
      })
      continue
    }
    if ((event.stage === 'MODEL_OUTPUT' || event.stage === 'MODEL_INFERENCE') && event.modelInferenceSummary) {
      bubbles.push({
        id: `${job.aiJobId}-${event.sequence}`,
        kind: 'assistant',
        roleTitle,
        title: stageTitle(event.stage),
        body: event.modelInferenceSummary,
        createdAt: event.createdAt
      })
      continue
    }
    if (event.stage === 'TOOL_CALL') {
      bubbles.push({
        id: `${job.aiJobId}-${event.sequence}`,
        kind: 'tool',
        roleTitle,
        title: `工具：${event.toolCallName ?? '未知'}`,
        body: [
          event.toolResultStatus ? `结果状态：${event.toolResultStatus}` : '',
          event.toolArgumentsSummary ? `参数摘要：${event.toolArgumentsSummary}` : ''
        ].filter(Boolean).join('\n'),
        createdAt: event.createdAt
      })
      continue
    }
    if (event.stage === 'FAILURE' && event.failureDiagnostic) {
      bubbles.push({
        id: `${job.aiJobId}-${event.sequence}`,
        kind: 'status',
        roleTitle,
        title: '失败诊断',
        body: event.failureDiagnostic,
        createdAt: event.createdAt
      })
    }
  }
  return bubbles
}

export function AuditDialogue({
  projectId,
  scanId,
  jobs,
  dynamicTask,
  activityLines
}: {
  projectId: string
  scanId?: string
  jobs: AiJobDto[]
  dynamicTask?: DynamicTaskDto
  activityLines: string[]
}) {
  const [eventsByJob, setEventsByJob] = useState<Record<string, AiJobEventDto[]>>({})
  const [error, setError] = useState<string>()
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const scanJobs = useMemo(
    () => jobs
      .filter((job) => job.scanId === scanId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt)),
    [jobs, scanId]
  )

  useEffect(() => {
    let active = true
    if (!projectId || !scanId || scanJobs.length === 0) {
      setEventsByJob({})
      return () => { active = false }
    }
    setLoading(true)
    void Promise.all(scanJobs.map(async (job) => {
      const events = await api.listAiJobEvents(job.aiJobId)
      return [job.aiJobId, events] as const
    })).then((entries) => {
      if (!active) return
      setEventsByJob(Object.fromEntries(entries))
      setError(undefined)
    }).catch((cause) => {
      if (active) setError(errorMessage(cause))
    }).finally(() => {
      if (active) setLoading(false)
    })
    return () => { active = false }
  }, [projectId, scanId, scanJobs.map((job) => `${job.aiJobId}:${job.status}:${job.updatedAt ?? ''}`).join('|')])

  const bubbles = useMemo(
    () => scanJobs.flatMap((job) => toBubbles(job, eventsByJob[job.aiJobId] ?? [])),
    [scanJobs, eventsByJob]
  )

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [bubbles.length, activityLines.length, dynamicTask?.status])

  return <article className="panel audit-dialogue-panel section-gap">
    <div className="panel-head">
      <div><p className="eyebrow">模型对话</p><h2>审计过程</h2></div>
      <span>{loading ? '同步中…' : `${bubbles.length} 条对话`}</span>
    </div>
    <p className="form-help">按角色展示系统实际下发的提示词、模型思考（若模型返回）、工具调用与最终输出。思考内容只供审阅，不能当作已验证证据。</p>
    {error && <Notice kind="error">{error}</Notice>}
    {!scanId && <Notice kind="info">开始审计后，这里会以对话形式展示全过程。</Notice>}
    <div className="audit-chat">
      {scanJobs.map((job) => <div className="audit-chat-role-banner" key={`banner-${job.aiJobId}`}>
        <strong>{roleLabel(job.role)}</strong>
        <small>{job.aiJobId} · {jobStatusLabel(job.status)}{job.model ? ` · ${job.model}` : ''}</small>
      </div>)}
      {bubbles.map((bubble) => <div className={`chat-bubble chat-${bubble.kind}`} key={bubble.id}>
        <header><span>{bubble.roleTitle}</span><strong>{bubble.title}</strong><small>{bubble.createdAt}</small></header>
        {bubble.kind === 'assistant' || bubble.kind === 'user'
          ? <div className="chat-markdown"><ReactMarkdown skipHtml remarkPlugins={[remarkGfm]}>{bubble.body}</ReactMarkdown></div>
          : <pre>{bubble.body}</pre>}
      </div>)}
      {scanId && bubbles.length === 0 && !loading && <p className="empty-state">流水线已启动，等待模型回合写入对话…</p>}
      <div ref={bottomRef} />
    </div>
    <div className="live-activity">
      <div className="panel-head"><div><p className="eyebrow">实时动向</p><h2>系统当前在做什么</h2></div></div>
      <ul>
        {activityLines.map((line, index) => <li key={`${line}-${index}`}>{line}</li>)}
        {dynamicTask && <li>断网容器任务 {dynamicTask.taskId}：{[jobStatusLabel(dynamicTask.status), dynamicTask.progressDetail, dynamicTask.stopReason, dynamicTask.failureCode].filter(Boolean).join(' · ')}</li>}
        {activityLines.length === 0 && !dynamicTask && <li>等待审计启动</li>}
      </ul>
    </div>
  </article>
}

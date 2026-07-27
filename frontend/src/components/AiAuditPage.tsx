import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, type AiJobDto, type DashboardSnapshot, type DynamicTaskDto, type OutputLanguage } from '../api'
import { AI_ROLES, jobStatusLabel, roleLabel } from '../labels'
import { AuditDialogue } from './AuditDialogue'
import { errorMessage, Notice, PageHeader } from './Common'

export function AiAuditPage({
  projectId,
  snapshot,
  language,
  onRefresh
}: {
  projectId: string
  snapshot: DashboardSnapshot | null
  language: OutputLanguage
  onRefresh: () => Promise<void>
}) {
  const [jobs, setJobs] = useState<AiJobDto[]>([])
  const [dynamicTask, setDynamicTask] = useState<DynamicTaskDto>()
  const [error, setError] = useState<string>()
  const scanId = snapshot?.scanId && snapshot.scanId !== 'unscanned' ? snapshot.scanId : undefined

  const refreshJobs = useCallback(async () => {
    if (!projectId) { setJobs([]); return }
    setJobs(await api.listAiJobs(projectId))
  }, [projectId])

  useEffect(() => {
    let active = true
    setJobs([])
    setDynamicTask(undefined)
    setError(undefined)
    if (!projectId) return () => { active = false }
    void refreshJobs().catch((cause) => {
      if (active) setError(errorMessage(cause))
    })
    return () => { active = false }
  }, [projectId, refreshJobs])

  useEffect(() => {
    if (!jobs.some((job) => job.scanId === scanId && (job.status === 'QUEUED' || job.status === 'RUNNING'))) return
    const timer = window.setTimeout(() => { void refreshJobs().then(() => onRefresh()) }, 1200)
    return () => window.clearTimeout(timer)
  }, [jobs, scanId, refreshJobs, onRefresh])

  useEffect(() => {
    let active = true
    let timer: number | undefined
    if (!scanId) return () => { active = false }
    const refreshTask = () => {
      void api.listDynamicTasks(scanId).then((tasks) => {
        if (!active) return
        const latest = [...tasks].sort((left, right) => {
          const byTime = left.updatedAt.localeCompare(right.updatedAt)
          return byTime !== 0 ? byTime : left.taskId.localeCompare(right.taskId)
        }).at(-1)
        setDynamicTask(latest)
        if (latest && (latest.status === 'QUEUED' || latest.status === 'RUNNING' || latest.status === 'LEASED')) {
          timer = window.setTimeout(refreshTask, 1500)
        } else if (latest?.status === 'COMPLETED' || latest?.status === 'FAILED') {
          void refreshJobs()
          void onRefresh()
        }
      }).catch((cause) => {
        if (active) setError(errorMessage(cause))
      })
    }
    refreshTask()
    return () => {
      active = false
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [scanId, dynamicTask?.taskId, dynamicTask?.status, onRefresh, refreshJobs])

  const scanJobs = jobs.filter((job) => job.scanId === scanId)
  const activityLines = useMemo(() => {
    const lines: string[] = []
    if (!scanId) return ['请先在「审计执行」启动一次审计']
    lines.push(`当前扫描 ${scanId}`)
    for (const role of AI_ROLES) {
      const job = [...scanJobs]
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
        .find((item) => item.role === role)
      if (!job) continue
      lines.push(`${roleLabel(role)}：${jobStatusLabel(job.status)}${job.errorCode ? `（${job.errorCode}）` : ''}`)
    }
    const active = scanJobs.find((job) => job.status === 'QUEUED' || job.status === 'RUNNING')
    if (active) lines.push(`正在执行：${roleLabel(active.role)}`)
    else if (scanJobs.some((job) => job.role === 'REPORT_GENERATION' && job.status === 'COMPLETED')) {
      lines.push('流水线已完成，可在审计结果查看报告')
    } else if (scanJobs.some((job) => job.status === 'FAILED' || job.status === 'BLOCKED')) {
      lines.push('流水线已停止：存在失败或阻断的模型任务')
    } else if (scanJobs.length > 0) {
      lines.push('流水线推进中')
    }
    return lines
  }, [scanId, scanJobs])

  return <section>
    <PageHeader eyebrow="审计过程" title="审计过程">
      {language === 'EN'
        ? 'Chat-style view of system prompts, model thinking, tool calls, and final outputs for the current scan.'
        : '以对话形式查看当前扫描中系统下发的提示词、模型思考、工具调用与最终输出。'}
    </PageHeader>
    {!projectId && <Notice kind="info">请先在「工作区」选择或创建一个授权工作区。</Notice>}
    {error && <Notice kind="error">{error}</Notice>}
    <AuditDialogue
      projectId={projectId}
      scanId={scanId}
      jobs={jobs}
      dynamicTask={dynamicTask}
      activityLines={activityLines}
    />
  </section>
}

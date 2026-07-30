import { useMemo, useState } from 'react'
import { type DashboardSnapshot, type OutputLanguage } from '../api'
import { useAuditLiveRefresh } from '../hooks/useAuditLiveRefresh'
import { AI_ROLES, jobStatusLabel, roleLabel } from '../labels'
import { AuditDialogue } from './AuditDialogue'
import { Notice, PageHeader } from './Common'

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
  const [error, setError] = useState<string>()
  const scanId = snapshot?.scanId && snapshot.scanId !== 'unscanned' ? snapshot.scanId : undefined
  const { jobs, dynamicTask } = useAuditLiveRefresh({
    projectId,
    scanId,
    onDashboardRefresh: onRefresh,
    onError: setError
  })

  const english = language === 'EN'
  const scanJobs = jobs.filter((job) => job.scanId === scanId)
  const activityLines = useMemo(() => {
    const lines: string[] = []
    if (!scanId) {
      return [english ? 'Start an audit from Audit run first.' : '请先在「审计执行」启动一次审计']
    }
    lines.push(english ? `Current scan ${scanId}` : `当前扫描 ${scanId}`)
    for (const role of AI_ROLES) {
      const job = [...scanJobs]
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
        .find((item) => item.role === role)
      if (!job) continue
      lines.push(`${roleLabel(role, english)}: ${jobStatusLabel(job.status, english)}${job.errorCode ? ` (${job.errorCode})` : ''}`)
    }
    const active = scanJobs.find((job) => job.status === 'QUEUED' || job.status === 'RUNNING')
    if (active) {
      lines.push(english ? `Running: ${roleLabel(active.role, english)}` : `正在执行：${roleLabel(active.role)}`)
    } else if (scanJobs.some((job) => job.role === 'REPORT_GENERATION' && job.status === 'COMPLETED')) {
      lines.push(english ? 'Pipeline complete — open Audit results for the report.' : '流水线已完成，可在审计结果查看报告')
    } else if (scanJobs.some((job) => job.status === 'FAILED' || job.status === 'BLOCKED')) {
      lines.push(english ? 'Pipeline stopped: a model job failed or was blocked.' : '流水线已停止：存在失败或阻断的模型任务')
    } else if (scanJobs.length > 0) {
      lines.push(english ? 'Pipeline in progress' : '流水线推进中')
    }
    return lines
  }, [scanId, scanJobs, english])

  return <section>
    <PageHeader eyebrow={english ? 'AUDIT DIALOGUE' : '审计过程'} title={english ? 'Audit dialogue' : '审计过程'}>
      {english
        ? 'Chat-style view of system prompts, model thinking, tool calls, and final outputs for the current scan.'
        : '以对话形式查看当前扫描中系统下发的提示词、模型思考、工具调用与最终输出。'}
    </PageHeader>
    {!projectId && <Notice kind="info">{english ? 'Select or create an authorized workspace first.' : '请先在「工作区」选择或创建一个授权工作区。'}</Notice>}
    {error && <Notice kind="error">{error}</Notice>}
    <AuditDialogue
      projectId={projectId}
      scanId={scanId}
      jobs={jobs}
      dynamicTask={dynamicTask}
      activityLines={activityLines}
      language={language}
    />
  </section>
}

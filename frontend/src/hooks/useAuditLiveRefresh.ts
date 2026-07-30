import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react'
import { api, type AiJobDto, type DynamicTaskDto, type ScanDto } from '../api'
import { errorMessage } from '../components/Common'

const TERMINAL_JOB = new Set(['COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED'])
const ACTIVE_JOB = new Set(['QUEUED', 'RUNNING'])
const ACTIVE_TASK = new Set(['QUEUED', 'RUNNING', 'LEASED', 'PAUSED'])
const POLL_MS = 2500
const POLL_HIDDEN_MS = 10000

const pickLatestTask = (tasks: DynamicTaskDto[]): DynamicTaskDto | undefined =>
  [...tasks].sort((left, right) => {
    const byTime = left.updatedAt.localeCompare(right.updatedAt)
    return byTime !== 0 ? byTime : left.taskId.localeCompare(right.taskId)
  }).at(-1)

/**
 * 是否继续 live 拉取。
 *
 * 重要：制品静态扫描结束后 scan.status 即为 COMPLETED，但 AI/动态流水线仍可能
 * 长时间运行。因此不能用 scan.status 终态单独停轮询，必须以 pipeline 投影与
 * job/task 活跃态为准。
 */
export const shouldKeepAuditLive = (
  scan: ScanDto | undefined,
  jobs: AiJobDto[],
  task: DynamicTaskDto | undefined,
  scanId: string
): boolean => {
  if (task && ACTIVE_TASK.has(task.status)) return true
  const scanJobs = jobs.filter((job) => job.scanId === scanId)
  if (scanJobs.some((job) => ACTIVE_JOB.has(job.status))) return true

  const pipelineStatus = scan?.pipelineStatus
  if (scan?.pipelineArmed || pipelineStatus === 'RUNNING' || pipelineStatus === 'PAUSED') {
    return true
  }
  if (pipelineStatus === 'COMPLETE' || pipelineStatus === 'STOPPED') {
    return false
  }
  if (scanJobs.some((job) => job.role === 'REPORT_GENERATION' && job.status === 'COMPLETED')) {
    return false
  }

  // 跨 stage 间隙：上一 job/task 已终态、下一资源尚未创建；pipeline 可能短暂 IDLE/缺省。
  if (scanJobs.length === 0) {
    return pipelineStatus === 'IDLE'
  }
  if (scanJobs.some((job) => !TERMINAL_JOB.has(job.status))) return true

  const hasHardStop = scanJobs.some((job) =>
    job.status === 'FAILED' || job.status === 'BLOCKED' || job.status === 'CANCELLED')
  if (hasHardStop) {
    // 硬失败且流水线未声明仍在推进时停止；IDLE 保留短暂对账窗口。
    return pipelineStatus === 'IDLE'
  }
  if (task && (task.status === 'FAILED' || task.status === 'CANCELLED')) {
    return pipelineStatus === 'IDLE'
  }

  // 全部成功终态：在 pipeline 明确 NONE 前继续拉（覆盖 stage 间隙与投影滞后）。
  return pipelineStatus !== 'NONE'
}

/**
 * 审计执行 / 过程视图的 live 同步。
 * 优先 Control Plane SSE 触发 GET 刷新；有界轮询覆盖 SSE 早关
 * （静态 ScanCompleted / 动态 TaskStopped 会结束事件流）与跨 stage 间隙。
 */
export function useAuditLiveRefresh({
  projectId,
  scanId,
  onDashboardRefresh,
  onError
}: {
  projectId: string
  scanId: string | undefined
  onDashboardRefresh?: () => Promise<void>
  onError?: (message: string) => void
}): {
  jobs: AiJobDto[]
  setJobs: Dispatch<SetStateAction<AiJobDto[]>>
  dynamicTask: DynamicTaskDto | undefined
  setDynamicTask: Dispatch<SetStateAction<DynamicTaskDto | undefined>>
  scan: ScanDto | undefined
  setScan: Dispatch<SetStateAction<ScanDto | undefined>>
  refreshNow: () => Promise<void>
} {
  const [jobs, setJobs] = useState<AiJobDto[]>([])
  const [dynamicTask, setDynamicTask] = useState<DynamicTaskDto>()
  const [scan, setScan] = useState<ScanDto>()
  const jobsRef = useRef(jobs)
  const taskRef = useRef(dynamicTask)
  const scanRef = useRef(scan)
  const onDashboardRefreshRef = useRef(onDashboardRefresh)
  const onErrorRef = useRef(onError)

  useEffect(() => { jobsRef.current = jobs }, [jobs])
  useEffect(() => { taskRef.current = dynamicTask }, [dynamicTask])
  useEffect(() => { scanRef.current = scan }, [scan])
  useEffect(() => { onDashboardRefreshRef.current = onDashboardRefresh }, [onDashboardRefresh])
  useEffect(() => { onErrorRef.current = onError }, [onError])

  const refreshNow = useCallback(async () => {
    if (!projectId) {
      setJobs([])
      setDynamicTask(undefined)
      setScan(undefined)
      return
    }
    const nextJobs = await api.listAiJobs(projectId)
    setJobs(nextJobs)
    jobsRef.current = nextJobs

    if (!scanId || scanId === 'unscanned') {
      setDynamicTask(undefined)
      taskRef.current = undefined
      setScan(undefined)
      scanRef.current = undefined
      return
    }

    const [nextScan, tasks] = await Promise.all([
      api.getScan(scanId),
      api.listDynamicTasks(scanId)
    ])
    setScan(nextScan)
    scanRef.current = nextScan
    const latest = pickLatestTask(tasks)
    setDynamicTask(latest)
    taskRef.current = latest
    await onDashboardRefreshRef.current?.()
  }, [projectId, scanId])

  useEffect(() => {
    let active = true
    setJobs([])
    setDynamicTask(undefined)
    setScan(undefined)
    jobsRef.current = []
    taskRef.current = undefined
    scanRef.current = undefined
    if (!projectId) return () => { active = false }
    void refreshNow().catch((cause) => {
      if (active) onErrorRef.current?.(errorMessage(cause))
    })
    return () => { active = false }
  }, [projectId, scanId, refreshNow])

  useEffect(() => {
    if (!projectId || !scanId || scanId === 'unscanned') return

    let closed = false
    let pollTimer: number | undefined
    let inFlight = false

    const reportError = (cause: unknown) => {
      if (!closed) onErrorRef.current?.(errorMessage(cause))
    }

    const pollDelayMs = () =>
      (typeof document !== 'undefined' && document.visibilityState === 'hidden')
        ? POLL_HIDDEN_MS
        : POLL_MS

    const schedulePoll = (delayMs = pollDelayMs()) => {
      if (closed || pollTimer !== undefined) return
      pollTimer = window.setTimeout(() => {
        pollTimer = undefined
        void runPoll()
      }, delayMs)
    }

    const stillLive = () =>
      shouldKeepAuditLive(scanRef.current, jobsRef.current, taskRef.current, scanId)

    const runPoll = async () => {
      if (closed) return
      if (inFlight) {
        schedulePoll()
        return
      }
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        if (stillLive()) schedulePoll(POLL_HIDDEN_MS)
        return
      }
      inFlight = true
      try {
        await refreshNow()
      } catch (cause) {
        reportError(cause)
      } finally {
        inFlight = false
      }
      if (closed) return
      if (stillLive()) schedulePoll()
    }

    const onVisibility = () => {
      if (closed || document.visibilityState === 'hidden') return
      // 回到前台：若仍应 live 且无定时器，立刻补一次。
      if (pollTimer === undefined && stillLive()) schedulePoll(0)
    }
    document.addEventListener('visibilitychange', onVisibility)

    // SSE 仅提示；静态 ScanCompleted / 动态 TaskStopped 后流会结束，不能作为唯一通道。
    const unsubscribe = api.subscribe(scanId, () => undefined, {
      onReconcile: (next) => {
        if (closed) return
        setScan(next)
        scanRef.current = next
        void refreshNow().catch(reportError).then(() => {
          if (!closed && stillLive()) schedulePoll()
        })
      },
      onError: () => {
        // EventSource 重试间隙由轮询兜底（含 SSE 因终态事件关闭之后）。
        if (!closed && stillLive()) schedulePoll()
      }
    })

    schedulePoll()

    return () => {
      closed = true
      if (pollTimer !== undefined) window.clearTimeout(pollTimer)
      document.removeEventListener('visibilitychange', onVisibility)
      unsubscribe()
    }
  }, [projectId, scanId, refreshNow])

  return {
    jobs,
    setJobs,
    dynamicTask,
    setDynamicTask,
    scan,
    setScan,
    refreshNow
  }
}

import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react'
import { api, type AiJobDto, type DynamicTaskDto, type ScanDto } from '../api'
import { errorMessage } from '../components/Common'

const TERMINAL_SCAN = new Set(['COMPLETED', 'FAILED', 'CANCELLED'])
const TERMINAL_JOB = new Set(['COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED'])
const ACTIVE_JOB = new Set(['QUEUED', 'RUNNING'])
const ACTIVE_TASK = new Set(['QUEUED', 'RUNNING', 'LEASED'])
const POLL_MS = 1500

const pickLatestTask = (tasks: DynamicTaskDto[]): DynamicTaskDto | undefined =>
  [...tasks].sort((left, right) => {
    const byTime = left.updatedAt.localeCompare(right.updatedAt)
    return byTime !== 0 ? byTime : left.taskId.localeCompare(right.taskId)
  }).at(-1)

const shouldKeepLive = (
  scan: ScanDto | undefined,
  jobs: AiJobDto[],
  task: DynamicTaskDto | undefined,
  scanId: string
): boolean => {
  if (task && ACTIVE_TASK.has(task.status)) return true
  const scanJobs = jobs.filter((job) => job.scanId === scanId)
  if (scanJobs.some((job) => ACTIVE_JOB.has(job.status))) return true
  // 操作员暂停保留游标；继续轮询以保持 resume/status 新鲜。
  if (scan?.pipelineStatus === 'PAUSED' || scan?.pipelineStatus === 'RUNNING' || scan?.pipelineArmed) {
    return true
  }
  if (scan && TERMINAL_SCAN.has(scan.status)) return false
  // 动态观测失败/取消且无后续 AI job：停止轮询。
  if (task && (task.status === 'FAILED' || task.status === 'CANCELLED')) return false
  // 跨 stage 间隙持续刷新（上一 stage 完成、下一 job 尚未
  // 创建）。终态失败/阻塞表示流水线无法推进时停止 —
  // 否则 UI 需切换标签页才能恢复。
  if (scanJobs.length === 0) return scan == null || !TERMINAL_SCAN.has(scan.status)
  const allTerminal = scanJobs.every((job) => TERMINAL_JOB.has(job.status))
  if (!allTerminal) return true
  if (scanJobs.some((job) => job.status === 'FAILED' || job.status === 'BLOCKED' || job.status === 'CANCELLED')) {
    return false
  }
  return scan == null || !TERMINAL_SCAN.has(scan.status)
}

/**
 * 审计执行 / 过程视图的 live 同步。
 * 优先 Control Plane SSE 触发 GET 刷新；scan 或任意 job/task 非终态时
 * 回退到有界轮询。
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
    let sseAlive = false

    const reportError = (cause: unknown) => {
      if (!closed) onErrorRef.current?.(errorMessage(cause))
    }

    const schedulePoll = () => {
      if (closed || pollTimer !== undefined) return
      pollTimer = window.setTimeout(() => {
        pollTimer = undefined
        void runPoll()
      }, POLL_MS)
    }

    const runPoll = async () => {
      if (closed) return
      try {
        await refreshNow()
      } catch (cause) {
        reportError(cause)
      }
      if (closed) return
      if (shouldKeepLive(scanRef.current, jobsRef.current, taskRef.current, scanId)) {
        schedulePoll()
      }
    }

    // SSE 仅提示；onReconcile 已 GET scan。refreshNow 重载 jobs/tasks。
    const unsubscribe = api.subscribe(scanId, () => undefined, {
      onReconcile: (next) => {
        if (closed) return
        sseAlive = true
        setScan(next)
        scanRef.current = next
        void refreshNow().catch(reportError).then(() => {
          if (!closed && shouldKeepLive(scanRef.current, jobsRef.current, taskRef.current, scanId)) {
            schedulePoll()
          }
        })
      },
      onError: () => {
        // EventSource 自行重试；SSE 不稳定时确保轮询覆盖间隙。
        if (!closed && !sseAlive) schedulePoll()
      }
    })

    // 始终启动有界轮询；SSE 可用时加速更新。
    schedulePoll()

    return () => {
      closed = true
      if (pollTimer !== undefined) window.clearTimeout(pollTimer)
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

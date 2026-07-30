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
  if (scan && TERMINAL_SCAN.has(scan.status)) return false
  // Dynamic observation failed/cancelled with no follow-up AI job: stop polling.
  if (task && (task.status === 'FAILED' || task.status === 'CANCELLED')) return false
  // Keep refreshing across inter-stage gaps (previous stage done, next job not
  // created yet). Stop when a terminal failure/block means the pipeline cannot
  // advance — otherwise the UI required a tab switch to resume.
  if (scanJobs.length === 0) return scan == null || !TERMINAL_SCAN.has(scan.status)
  const allTerminal = scanJobs.every((job) => TERMINAL_JOB.has(job.status))
  if (!allTerminal) return true
  if (scanJobs.some((job) => job.status === 'FAILED' || job.status === 'BLOCKED' || job.status === 'CANCELLED')) {
    return false
  }
  return scan == null || !TERMINAL_SCAN.has(scan.status)
}

/**
 * Live sync for audit execution / process views.
 * Prefer Control Plane SSE to trigger GET refreshes; fall back to bounded
 * polling while the scan or any job/task is non-terminal.
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

    // SSE only hints; onReconcile already GETs the scan. refreshNow reloads jobs/tasks.
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
        // EventSource retries on its own; ensure polling covers gaps when SSE is flaky.
        if (!closed && !sseAlive) schedulePoll()
      }
    })

    // Always start bounded polling; SSE accelerates updates when available.
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

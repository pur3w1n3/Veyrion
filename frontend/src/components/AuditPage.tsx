import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, type AiJobDto, type AiRole, type ArtifactDto, type DashboardSnapshot, type DynamicTaskDto, type OutputLanguage, type RoleAssignmentDto, type ScanDto } from '../api'
import { confirmAiAuthorization } from '../aiAuthorization'
import { ArtifactImportPanel } from './ArtifactImportPanel'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

export function AuditPage({ projectId, snapshot, onRefresh, language }: { projectId: string; snapshot: DashboardSnapshot | null; onRefresh: () => Promise<void>; language: OutputLanguage }) {
  const [artifacts, setArtifacts] = useState<ArtifactDto[]>([])
  const [assignments, setAssignments] = useState<RoleAssignmentDto[]>([])
  const [jobs, setJobs] = useState<AiJobDto[]>([])
  const [scan, setScan] = useState<ScanDto>()
  const [error, setError] = useState<string>()
  const [message, setMessage] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [dynamicBusy, setDynamicBusy] = useState(false)
  const [dynamicTask, setDynamicTask] = useState<DynamicTaskDto>()
  const [loadingArtifacts, setLoadingArtifacts] = useState(false)

  const refreshArtifacts = useCallback(async () => {
    if (!projectId) { setArtifacts([]); return }
    setArtifacts(await api.listArtifacts(projectId))
  }, [projectId])

  const refreshJobs = useCallback(async () => {
    if (!projectId) { setJobs([]); return }
    setJobs(await api.listAiJobs(projectId))
  }, [projectId])

  useEffect(() => {
    let active = true
    setArtifacts([])
    setAssignments([])
    setJobs([])
    setScan(undefined)
    setDynamicTask(undefined)
    setError(undefined)
    setMessage(undefined)
    if (!projectId) return () => { active = false }
    setLoadingArtifacts(true)
    void Promise.all([api.listArtifacts(projectId), api.listRoleAssignments(projectId), api.listAiJobs(projectId)]).then(([items, roleAssignments, aiJobs]) => {
      if (!active) return
      setArtifacts(items)
      setAssignments(roleAssignments)
      setJobs(aiJobs)
    }).catch((cause) => {
      if (active) setError(errorMessage(cause))
    }).finally(() => {
      if (active) setLoadingArtifacts(false)
    })
    return () => { active = false }
  }, [projectId])

  const activeScanId = scan?.scanId ?? snapshot?.scanId
  const scanJobs = jobs.filter((job) => job.scanId === activeScanId)
  const roleJob = (role: AiRole) => [...scanJobs]
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
    .find((job) => job.role === role)
  const preAnalysisJob = roleJob('PRE_ANALYSIS')
  const pathJob = roleJob('PATH_EXPLORATION')
  const triageJob = roleJob('VULNERABILITY_TRIAGE')
  const reportJob = roleJob('REPORT_GENERATION')

  useEffect(() => {
    if (!jobs.some((job) => job.scanId === activeScanId && (job.status === 'QUEUED' || job.status === 'RUNNING'))) return
    const timer = window.setTimeout(() => { void refreshJobs() }, 1200)
    return () => window.clearTimeout(timer)
  }, [activeScanId, jobs, refreshJobs])

  useEffect(() => {
    let active = true
    let timer: number | undefined
    if (!activeScanId) return () => { active = false }
    const refreshTask = () => {
      void api.listDynamicTasks(activeScanId).then((tasks) => {
        if (!active) return
        const latest = tasks.at(-1)
        setDynamicTask(latest)
        if (latest && (latest.status === 'QUEUED' || latest.status === 'RUNNING')) {
          timer = window.setTimeout(refreshTask, 1500)
        } else if (latest?.status === 'COMPLETED') {
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
  }, [activeScanId, dynamicTask?.taskId])

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    if (data.get('authorized') !== 'on') { setError('必须明确确认已获授权'); return }
    if (!assignments.some((assignment) => assignment.role === 'PRE_ANALYSIS')) {
      setError('PRE_ANALYSIS 尚未绑定模型。请先在“模型服务”完成前置 AI 配置。')
      return
    }
    if (!confirmAiAuthorization()) return
    setBusy(true); setError(undefined); setMessage(undefined)
    void api.startAudit(projectId, {
      artifactId: String(data.get('artifactId')),
      authorized: true,
      aiAuthorized: true,
      dependencyMode: String(data.get('dependencyMode')),
      networkMode: 'DENY',
      dangerousActionMode: 'DRY_RUN',
      outputLanguage: language,
      maxWallClockSeconds: Number(data.get('timeout')),
      maxMemoryBytes: Number(data.get('memory')) * 1024 * 1024
    }).then(async (created) => {
      setScan(created.scan)
      setJobs((current) => [
        created.preAnalysisJob,
        ...current.filter((job) => job.aiJobId !== created.preAnalysisJob.aiJobId)
      ])
      setMessage('静态事实与入口已建立，PRE_ANALYSIS 前置 AI 已进入执行队列')
      await onRefresh()
    }).catch((cause) => setError(`审计启动未完整完成：${errorMessage(cause)}`)).finally(() => setBusy(false))
  }

  const startRole = (role: AiRole) => {
    if (!activeScanId || !assignments.some((assignment) => assignment.role === role)) {
      setError(`${role} 尚未绑定模型，请先在“模型服务”完成配置。`)
      return
    }
    if (!confirmAiAuthorization()) return
    setBusy(true); setError(undefined); setMessage(undefined)
    void api.createAiJob(projectId, { role, scanId: activeScanId, authorized: true, outputLanguage: language })
      .then(async (job) => {
        setJobs((current) => [job, ...current])
        setMessage(`${role} 已进入执行队列`)
        await refreshJobs()
      })
      .catch((cause) => setError(errorMessage(cause)))
      .finally(() => setBusy(false))
  }

  const runArtifactInDocker = () => {
    const scanId = activeScanId
    if (!scanId) { setError('请先创建静态扫描'); return }
    if (!window.confirm('将当前扫描对应的内部 JAR 在断网 Docker 容器中运行。该模式阻止网络出站，但不构成恶意代码强化隔离。确认排队？')) return
    setDynamicBusy(true); setError(undefined)
    void api.createDynamicTask(scanId).then(async (created) => {
      setDynamicTask(created)
      await onRefresh()
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setDynamicBusy(false))
  }

  const dynamicStatus = dynamicTask?.status
  const dynamicObserved = dynamicStatus === 'COMPLETED' || snapshot?.verificationStatus === 'DYNAMIC_SUSPECTED'
  const dynamicState = dynamicObserved ? 'completed'
    : dynamicStatus === 'FAILED' || dynamicStatus === 'CANCELLED' ? 'unavailable'
      : dynamicStatus === 'QUEUED' || dynamicStatus === 'RUNNING' ? 'active' : 'waiting'
  const dynamicDetail = dynamicTask
    ? `${dynamicTask.taskId} · ${dynamicStatus}${dynamicTask.failureCode ? ` · ${dynamicTask.failureCode}` : ''}${dynamicTask.stopReason ? ` · ${dynamicTask.stopReason}` : ''}${dynamicTask.failureDiagnostic ? ` · ${dynamicTask.failureDiagnostic}` : ''}`
    : activeScanId ? '尚未创建动态任务；点击下方按钮后由后端 Worker 校验运行能力' : '请先创建静态扫描'
  const jobState = (job?: AiJobDto) => job?.status === 'COMPLETED' ? 'completed'
    : job?.status === 'FAILED' || job?.status === 'BLOCKED' || job?.status === 'CANCELLED' ? 'unavailable'
      : job?.status === 'QUEUED' || job?.status === 'RUNNING' ? 'active' : 'waiting'
  const jobDetail = (job: AiJobDto | undefined, waiting: string) => job
    ? `${job.aiJobId} · ${job.status}${job.errorCode ? ` · ${job.errorCode}` : ''}`
    : waiting
  const steps = [
    ['目标摘要复核', snapshot?.artifactDigest ? 'completed' : 'waiting', snapshot?.artifactDigest ?? '等待后端摘要'],
    ['静态事实与入口发现', snapshot?.entries.length ? 'completed' : 'waiting', `${snapshot?.entries.length ?? 0} 个入口；事实层不由模型改写`],
    ['PRE_ANALYSIS 前置 AI 建模', jobState(preAnalysisJob), jobDetail(preAnalysisJob, '由“开始审计”在静态分析后自动创建')],
    ['计划评审与路径探索 AI', jobState(pathJob), jobDetail(pathJob, '前置建模完成后，由分析师批准进入路径规划')],
    ['断网 Docker 动态观察', dynamicState, dynamicDetail],
    ['漏洞研判 AI', jobState(triageJob), jobDetail(triageJob, '动态观察后关联事实与证据')],
    ['报告生成 AI', jobState(reportJob), jobDetail(reportJob, '研判完成后汇总证据、限制与未覆盖区域')]
  ]

  return <section>
    <PageHeader eyebrow="AUDIT / ORCHESTRATION" title="审计执行">导入制品后，一次启动静态事实与入口发现，并自动接续 PRE_ANALYSIS 前置 AI；后续阶段按计划评审顺序推进。</PageHeader>
    {error && <Notice kind="error">{error}。请求未回退到 demo 或伪造任务。</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    {!projectId && <Notice kind="info">请点击左上角“当前工作区”创建或选择授权工作区。</Notice>}
    <div className="audit-grid">
      <ArtifactImportPanel projectId={projectId} artifacts={artifacts} onArtifactsChanged={async () => {
        setLoadingArtifacts(true)
        try { await refreshArtifacts() } finally { setLoadingArtifacts(false) }
      }} />
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">AUDIT START</p><h2>审计范围与策略</h2></div><span>{loadingArtifacts ? '加载目标…' : `${artifacts.length} 个目标`}</span></div>
        <form className="stack-form" onSubmit={submit}>
          <label className="field"><span>目标制品</span><select required name="artifactId" disabled={!projectId || loadingArtifacts}><option value="">{loadingArtifacts ? '正在加载目标' : artifacts.length ? '选择制品' : '当前工作区暂无制品'}</option>{artifacts.map((item) => <option key={item.artifactId} value={item.artifactId}>{item.type} · {item.artifactId}</option>)}</select></label>
          <div className="form-grid">
            <label className="field"><span>依赖模式</span><select name="dependencyMode"><option value="MOCK">MOCK</option><option value="REPLAY">REPLAY</option></select></label>
            <label className="field"><span>网络策略</span><input value="DENY（固定）" readOnly /></label>
            <label className="field"><span>超时（秒）</span><input name="timeout" type="number" min="10" max="3600" defaultValue="300" /></label>
            <label className="field"><span>内存（MiB）</span><input name="memory" type="number" min="128" max="8192" defaultValue="512" /></label>
          </div>
          <div className="selected-ai"><small>前置 AI · {language === 'ZH_CN' ? '简体中文输出' : 'English output'}</small><strong>{assignments.find((assignment) => assignment.role === 'PRE_ANALYSIS')?.model ?? '未配置 PRE_ANALYSIS'}</strong><span>{language === 'ZH_CN' ? '静态解析器先产出事实与入口，模型只做带证据的业务解释。' : 'Static parsers produce facts and entries first; the model only provides evidence-grounded interpretation.'}</span></div>
          <label className="check-field"><input type="checkbox" name="authorized" />我确认该制品与范围已获授权，且接受无外网、DRY_RUN 策略。</label>
          <button className="primary-button" disabled={!projectId || busy || artifacts.length === 0}>{busy ? '启动中…' : '开始审计：静态分析 + 前置 AI'}</button>
        </form>
      </article>
      <article className="panel audit-timeline-panel">
        <div className="panel-head"><div><p className="eyebrow">EXECUTION TIMELINE</p><h2>执行过程</h2></div>{(scan?.verificationStatus ?? snapshot?.verificationStatus) && <StatusPill status={(scan?.verificationStatus ?? snapshot?.verificationStatus)!} />}</div>
        <ol className="workflow-timeline">{steps.map(([title, state, detail], index) => <li className={`timeline-${state}`} key={title}><span>{index + 1}</span><div><strong>{title}</strong><small>{detail}</small></div><b>{state === 'unavailable' ? 'UNAVAILABLE' : state.toUpperCase()}</b></li>)}</ol>
        <div className="button-row section-gap">
          {preAnalysisJob?.status === 'COMPLETED' && !pathJob && <button className="secondary-button" disabled={busy} onClick={() => startRole('PATH_EXPLORATION')}>批准计划并生成路径探索</button>}
          {pathJob?.status === 'COMPLETED' && dynamicStatus !== 'COMPLETED' && <button className="secondary-button" disabled={dynamicBusy} onClick={runArtifactInDocker}>{dynamicBusy ? '排队中…' : '在断网 Docker 中执行探索'}</button>}
          {dynamicObserved && !triageJob && <button className="secondary-button" disabled={busy} onClick={() => startRole('VULNERABILITY_TRIAGE')}>开始漏洞研判</button>}
          {triageJob?.status === 'COMPLETED' && !reportJob && <button className="secondary-button" disabled={busy} onClick={() => startRole('REPORT_GENERATION')}>生成审计报告</button>}
        </div>
        <p className="form-help">仅接受当前 scan 绑定的后端受控制品副本；固定使用 --network none、只读挂载和 JVM Agent，不接受前端命令、路径、环境变量或网络放宽。</p>
        <p className="form-help">SSE 仅作增量通知；最终状态始终以 GET scan/dashboard 为准。</p>
      </article>
    </div>
  </section>
}

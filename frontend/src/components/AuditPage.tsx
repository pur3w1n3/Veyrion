import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, type AiJobDto, type ArtifactDto, type DashboardSnapshot, type DynamicTaskDto, type OutputLanguage, type RoleAssignmentDto, type ScanDto } from '../api'
import { confirmAiAuthorization } from '../aiAuthorization'
import { dependencyModeLabel, jobStatusLabel, roleLabel, timelineStateLabel } from '../labels'
import { AI_ROLES } from '../labels'
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
  const roleJob = (role: (typeof AI_ROLES)[number]) => [...scanJobs]
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
    .find((job) => job.role === role)
  const preAnalysisJob = roleJob('PRE_ANALYSIS')
  const pathJob = roleJob('PATH_EXPLORATION')
  const dynamicVerifyJob = roleJob('DYNAMIC_VERIFICATION')
  const triageJob = roleJob('VULNERABILITY_TRIAGE')
  const reportJob = roleJob('REPORT_GENERATION')

  useEffect(() => {
    if (!jobs.some((job) => job.scanId === activeScanId && (job.status === 'QUEUED' || job.status === 'RUNNING'))) return
    const timer = window.setTimeout(() => { void refreshJobs().then(() => onRefresh()) }, 1200)
    return () => window.clearTimeout(timer)
  }, [activeScanId, jobs, refreshJobs, onRefresh])

  useEffect(() => {
    let active = true
    let timer: number | undefined
    if (!activeScanId || activeScanId === 'unscanned') return () => { active = false }
    const refreshTask = () => {
      void api.listDynamicTasks(activeScanId).then((tasks) => {
        if (!active) return
        const latest = tasks.at(-1)
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
  }, [activeScanId, dynamicTask?.taskId, dynamicTask?.status, onRefresh, refreshJobs])

  const missingRoles = AI_ROLES.filter((role) => !assignments.some((item) => item.role === role))

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    if (data.get('authorized') !== 'on') { setError('必须明确确认已获授权'); return }
    if (missingRoles.length > 0) {
      setError(`请先在“模型服务”绑定全部五个角色：${missingRoles.map(roleLabel).join('、')}`)
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
      setMessage('审计流水线已启动：静态分析完成后，系统将自动推进前置建模、路径探索、断网容器观察、动态验证、漏洞研判与报告生成。')
      await onRefresh()
      await refreshJobs()
    }).catch((cause) => setError(`审计启动未完整完成：${errorMessage(cause)}`)).finally(() => setBusy(false))
  }

  const jobState = (job?: AiJobDto) => job?.status === 'COMPLETED' ? 'completed'
    : job?.status === 'FAILED' || job?.status === 'BLOCKED' || job?.status === 'CANCELLED' ? 'unavailable'
      : job?.status === 'QUEUED' || job?.status === 'RUNNING' ? 'active' : 'waiting'
  const dynamicStatus = dynamicTask?.status
  const dynamicState = dynamicStatus === 'COMPLETED' ? 'completed'
    : dynamicStatus === 'FAILED' || dynamicStatus === 'CANCELLED' ? 'unavailable'
      : dynamicStatus === 'QUEUED' || dynamicStatus === 'RUNNING' || dynamicStatus === 'LEASED' ? 'active' : 'waiting'
  const jobDetail = (job: AiJobDto | undefined, waiting: string) => job
    ? `${job.aiJobId} · ${jobStatusLabel(job.status)}${job.errorCode ? ` · ${job.errorCode}` : ''}`
    : waiting
  const steps = [
    ['目标摘要复核', snapshot?.artifactDigest ? 'completed' : 'waiting', snapshot?.artifactDigest ?? '等待后端摘要'],
    ['静态事实与入口发现', snapshot?.entries.length ? 'completed' : 'waiting', `${snapshot?.entries.length ?? 0} 个入口；事实层不由模型改写`],
    ['前置建模', jobState(preAnalysisJob), jobDetail(preAnalysisJob, '流水线自动创建')],
    ['路径探索', jobState(pathJob), jobDetail(pathJob, '前置建模完成后自动进入')],
    ['断网容器动态观察', dynamicState, dynamicTask ? `${dynamicTask.taskId} · ${jobStatusLabel(dynamicStatus)}` : '路径探索完成后自动排队'],
    ['动态验证', jobState(dynamicVerifyJob), jobDetail(dynamicVerifyJob, '容器观察后自动对照路径假设验证')],
    ['漏洞研判', jobState(triageJob), jobDetail(triageJob, '动态验证后自动进入')],
    ['报告生成', jobState(reportJob), jobDetail(reportJob, '研判完成后自动汇总')]
  ] as const

  return <section>
    <PageHeader eyebrow="审计编排" title="审计执行">
      导入制品并开始审计后，系统按流水线自动推进全部阶段。提示词、思考与输出请到左侧「审计过程」查看。
    </PageHeader>
    {error && <Notice kind="error">{error}。请求未回退到演示数据或伪造任务。</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    {!projectId && <Notice kind="info">请先在「工作区」首页选择或创建授权工作区。</Notice>}
    <div className="audit-grid">
      <ArtifactImportPanel projectId={projectId} artifacts={artifacts} onArtifactsChanged={async () => {
        setLoadingArtifacts(true)
        try { await refreshArtifacts() } finally { setLoadingArtifacts(false) }
      }} />
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">启动审计</p><h2>审计范围与策略</h2></div><span>{loadingArtifacts ? '加载目标…' : `${artifacts.length} 个目标`}</span></div>
        <form className="stack-form" onSubmit={submit}>
          <label className="field"><span>目标制品</span><select required name="artifactId" disabled={!projectId || loadingArtifacts}><option value="">{loadingArtifacts ? '正在加载目标' : artifacts.length ? '选择制品' : '当前工作区暂无制品'}</option>{artifacts.map((item) => <option key={item.artifactId} value={item.artifactId}>{item.type} · {item.artifactId}</option>)}</select></label>
          <div className="form-grid">
            <label className="field"><span>执行模式（外部依赖）</span><select name="dependencyMode"><option value="MOCK">{dependencyModeLabel('MOCK')}：外部依赖用模拟代替</option><option value="REPLAY">{dependencyModeLabel('REPLAY')}：按已有记录重放</option></select></label>
            <label className="field"><span>网络策略</span><input value="禁止外网（固定）" readOnly /></label>
            <label className="field"><span>超时（秒）</span><input name="timeout" type="number" min="10" max="3600" defaultValue="300" /></label>
            <label className="field"><span>内存（MiB）</span><input name="memory" type="number" min="128" max="8192" defaultValue="512" /></label>
          </div>
          <div className="selected-ai"><small>自动流水线 · {language === 'ZH_CN' ? '简体中文输出' : 'English output'}</small><strong>{assignments.length}/5 个角色已绑定</strong><span>一次授权后，系统自动完成五个模型角色与断网容器观察；动态验证会独立对照路径探索假设。</span></div>
          <label className="check-field"><input type="checkbox" name="authorized" />我确认该制品与范围已获授权，并接受无外网、危险动作空跑演练，以及整条审计流水线自动推进。</label>
          <button className="primary-button" disabled={!projectId || busy || artifacts.length === 0}>{busy ? '启动中…' : '开始审计（自动流水线）'}</button>
        </form>
      </article>
      <article className="panel audit-timeline-panel">
        <div className="panel-head"><div><p className="eyebrow">执行过程</p><h2>阶段进度</h2></div>{(scan?.verificationStatus ?? snapshot?.verificationStatus) && <StatusPill status={(scan?.verificationStatus ?? snapshot?.verificationStatus)!} />}</div>
        <ol className="workflow-timeline">{steps.map(([title, state, detail], index) => <li className={`timeline-${state}`} key={title}><span>{index + 1}</span><div><strong>{title}</strong><small>{detail}</small></div><b>{timelineStateLabel(state)}</b></li>)}</ol>
        <p className="form-help">无需逐步点击批准。任一步失败会停止后续自动推进；模型对话细节请在「审计过程」页查看。</p>
      </article>
    </div>
  </section>
}

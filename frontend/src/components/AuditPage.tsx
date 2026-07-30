import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, artifactLabel, type ArtifactDto, type AuditRetryStage, type DashboardSnapshot, type OutputLanguage, type RoleAssignmentDto } from '../api'
import { confirmAiAuthorization } from '../aiAuthorization'
import { useAuditLiveRefresh } from '../hooks/useAuditLiveRefresh'
import { AI_ROLES, dependencyModeLabel, pipelineStatusLabel, roleLabel, stopReasonLabel, timelineStateLabel } from '../labels'
import { ArtifactImportPanel } from './ArtifactImportPanel'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

export function AuditPage({ projectId, snapshot, onRefresh, language }: { projectId: string; snapshot: DashboardSnapshot | null; onRefresh: () => Promise<void>; language: OutputLanguage }) {
  const english = language === 'EN'
  const [artifacts, setArtifacts] = useState<ArtifactDto[]>([])
  const [assignments, setAssignments] = useState<RoleAssignmentDto[]>([])
  const [error, setError] = useState<string>()
  const [message, setMessage] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [loadingArtifacts, setLoadingArtifacts] = useState(false)
  const [localScanId, setLocalScanId] = useState<string>()

  const activeScanId = localScanId ?? (snapshot?.scanId && snapshot.scanId !== 'unscanned' ? snapshot.scanId : undefined)
  const {
    jobs,
    setJobs,
    dynamicTask,
    setDynamicTask,
    scan,
    setScan,
    refreshNow
  } = useAuditLiveRefresh({
    projectId,
    scanId: activeScanId,
    onDashboardRefresh: onRefresh,
    onError: setError
  })

  const refreshArtifacts = useCallback(async () => {
    if (!projectId) { setArtifacts([]); return }
    setArtifacts(await api.listArtifacts(projectId))
  }, [projectId])

  useEffect(() => {
    let active = true
    setArtifacts([])
    setAssignments([])
    setLocalScanId(undefined)
    setError(undefined)
    setMessage(undefined)
    if (!projectId) return () => { active = false }
    setLoadingArtifacts(true)
    void Promise.all([api.listArtifacts(projectId), api.listRoleAssignments(projectId)]).then(([items, roleAssignments]) => {
      if (!active) return
      setArtifacts(items)
      setAssignments(roleAssignments)
    }).catch((cause) => {
      if (active) setError(errorMessage(cause))
    }).finally(() => {
      if (active) setLoadingArtifacts(false)
    })
    return () => { active = false }
  }, [projectId])

  const scanJobs = jobs.filter((job) => job.scanId === activeScanId)
  const roleJob = (role: (typeof AI_ROLES)[number]) => [...scanJobs]
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
    .find((job) => job.role === role)
  const preAnalysisJob = roleJob('PRE_ANALYSIS')
  const authJobs = [...scanJobs]
    .filter((job) => job.role === 'AUTH_ANALYSIS')
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt))
  const authAnalysisJob = authJobs[0]
  const authBypassJob = authJobs[1]
  const pathJob = roleJob('PATH_EXPLORATION')
  const dynamicVerifyJob = roleJob('DYNAMIC_VERIFICATION')
  const triageJob = roleJob('VULNERABILITY_TRIAGE')
  const reportJob = roleJob('REPORT_GENERATION')

  const missingRoles = AI_ROLES.filter((role) => !assignments.some((item) => item.role === role))

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    if (data.get('authorized') !== 'on') {
      setError(english ? 'You must explicitly confirm authorization.' : '必须明确确认已获授权')
      return
    }
    if (missingRoles.length > 0) {
      setError(english
        ? `Bind all six roles under Model providers first: ${missingRoles.map((role) => roleLabel(role, true)).join(', ')}`
        : `请先在“模型服务”绑定全部六个角色：${missingRoles.map((role) => roleLabel(role)).join('、')}`)
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
      setLocalScanId(created.scan.scanId)
      setJobs((current) => [
        created.preAnalysisJob,
        ...current.filter((job) => job.aiJobId !== created.preAnalysisJob.aiJobId)
      ])
      setMessage(english
        ? 'Audit pipeline started: pre-analysis → auth → track observation → bypass confirm → dynamic verification → path exploration → triage → report.'
        : '审计流水线已启动：系统将按前置建模、鉴权分析、按轨动态观察、绕过确认、动态验证、路径探索、漏洞研判与报告生成推进。')
      await onRefresh()
      await refreshNow()
    }).catch((cause) => setError(english
      ? `Audit start incomplete: ${errorMessage(cause, true)}`
      : `审计启动未完整完成：${errorMessage(cause)}`)).finally(() => setBusy(false))
  }

  const jobState = (job?: typeof preAnalysisJob) => job?.status === 'COMPLETED' ? 'completed'
    : job?.status === 'FAILED' || job?.status === 'BLOCKED' || job?.status === 'CANCELLED' ? 'unavailable'
      : job?.status === 'QUEUED' || job?.status === 'RUNNING' ? 'active' : 'waiting'
  const dynamicStatus = dynamicTask?.status
  const dynamicState = dynamicStatus === 'COMPLETED' ? 'completed'
    : dynamicStatus === 'FAILED' || dynamicStatus === 'CANCELLED' ? 'unavailable'
      : dynamicStatus === 'QUEUED' || dynamicStatus === 'RUNNING' || dynamicStatus === 'LEASED' ? 'active' : 'waiting'
  const jobDetail = (job: typeof preAnalysisJob, waiting: string) => job
    ? `${job.aiJobId} · ${pipelineStatusLabel(job.status, job.errorCode, english)}${job.errorCode ? ` · ${job.errorCode}` : ''}`
    : waiting
  const dynamicDetail = dynamicTask
    ? [
        dynamicTask.taskId,
        pipelineStatusLabel(dynamicStatus, dynamicTask.failureCode, english),
        dynamicTask.progressDetail,
        stopReasonLabel(dynamicTask.stopReason, english),
        dynamicTask.failureCode,
        dynamicTask.failureDiagnostic
      ].filter(Boolean).join(' · ')
    : (english ? 'Queued after pre-analysis' : '前置建模完成后自动排队')
  const retryStage = (stage: AuditRetryStage) => {
    if (!projectId || !activeScanId || activeScanId === 'unscanned') {
      setError(english ? 'No scan available to retry' : '没有可重试的扫描')
      return
    }
    if (!confirmAiAuthorization()) return
    setBusy(true); setError(undefined); setMessage(undefined)
    void api.retryAuditStage(projectId, {
      scanId: activeScanId,
      stage,
      authorized: true,
      aiAuthorized: stage === 'DYNAMIC_OBSERVATION' ? undefined : true,
      outputLanguage: language
    }).then(async (result) => {
      if (result.aiJob) {
        setJobs((current) => [result.aiJob!, ...current.filter((job) => job.aiJobId !== result.aiJob!.aiJobId)])
      }
      if (result.dynamicTask) setDynamicTask(result.dynamicTask)
      const stageLabel = stage === 'DYNAMIC_OBSERVATION'
        ? (english ? 'Offline container track observation' : '断网容器按轨动态观察')
        : stage === 'AUTH_BYPASS_CONFIRM'
          ? (english ? 'Auth bypass confirm' : '鉴权绕过确认')
          : roleLabel(stage, english)
      setMessage(english
        ? `Re-queued: ${stageLabel}. The pipeline will continue from this stage.`
        : `已重新排队：${stageLabel}。流水线将从该阶段继续自动推进。`)
      await refreshNow()
      await onRefresh()
    }).catch((cause) => setError(english
      ? `Stage retry failed: ${errorMessage(cause, true)}`
      : `阶段重试失败：${errorMessage(cause)}`)).finally(() => setBusy(false))
  }
  const steps: Array<{
    title: string
    state: string
    detail: string
    retryStage?: AuditRetryStage
  }> = [
    { title: english ? 'Artifact summary review' : '目标摘要复核', state: snapshot?.artifactDigest ? 'completed' : 'waiting', detail: snapshot?.artifactDigest ?? (english ? 'Waiting for backend summary' : '等待后端摘要') },
    { title: english ? 'Static facts & entry discovery' : '静态事实与入口发现', state: snapshot?.entries.length ? 'completed' : 'waiting', detail: english ? `${snapshot?.entries.length ?? 0} entries; facts are not model-writable` : `${snapshot?.entries.length ?? 0} 个入口；事实层不由模型改写` },
    { title: english ? 'Pre-analysis' : '前置建模', state: jobState(preAnalysisJob), detail: jobDetail(preAnalysisJob, english ? 'Created by pipeline' : '流水线自动创建'), retryStage: jobState(preAnalysisJob) === 'unavailable' ? 'PRE_ANALYSIS' : undefined },
    { title: english ? 'Auth analysis' : '鉴权分析', state: jobState(authAnalysisJob), detail: jobDetail(authAnalysisJob, english ? 'Static auth model, synthetic identity, experiment plans' : '静态鉴权模型、合成身份与实验计划'), retryStage: jobState(authAnalysisJob) === 'unavailable' ? 'AUTH_ANALYSIS' : undefined },
    { title: english ? 'Offline container track observation' : '断网容器按轨动态观察', state: dynamicState, detail: dynamicDetail, retryStage: dynamicState === 'unavailable' ? 'DYNAMIC_OBSERVATION' : undefined },
    { title: english ? 'Auth bypass confirm' : '鉴权绕过确认', state: jobState(authBypassJob), detail: jobDetail(authBypassJob, english ? 'Confirm bypass from 401 / pass-gate PathRuns' : '消费 401/过闸 PathRun 后确认绕过'), retryStage: jobState(authBypassJob) === 'unavailable' ? 'AUTH_BYPASS_CONFIRM' : undefined },
    { title: english ? 'Dynamic verification & local probes' : '动态验证与本地发包', state: jobState(dynamicVerifyJob), detail: jobDetail(dynamicVerifyJob, english ? 'Authorized loopback probes by entry and params' : '沙箱反馈后按入口和参数进行授权 loopback 探索'), retryStage: jobState(dynamicVerifyJob) === 'unavailable' ? 'DYNAMIC_VERIFICATION' : undefined },
    { title: english ? 'Path exploration' : '路径探索', state: jobState(pathJob), detail: jobDetail(pathJob, english ? 'Path model after PathRuns persist' : 'PathRun 保存后建立路径模型'), retryStage: jobState(pathJob) === 'unavailable' ? 'PATH_EXPLORATION' : undefined },
    { title: english ? 'Vulnerability triage' : '漏洞研判', state: jobState(triageJob), detail: jobDetail(triageJob, english ? 'After PathRun + dynamic debug close' : 'PathRun 与动态调试闭环后进入'), retryStage: jobState(triageJob) === 'unavailable' ? 'VULNERABILITY_TRIAGE' : undefined },
    { title: english ? 'Report generation' : '报告生成', state: jobState(reportJob), detail: jobDetail(reportJob, english ? 'Auto-summarize after triage' : '研判完成后自动汇总'), retryStage: jobState(reportJob) === 'unavailable' ? 'REPORT_GENERATION' : undefined }
  ]

  return <section>
    <PageHeader eyebrow={english ? 'AUDIT ORCHESTRATION' : '审计编排'} title={english ? 'Audit run' : '审计执行'}>
      {english
        ? 'Import an artifact and start the audit; the pipeline advances all stages automatically. Prompts, thinking, and outputs are on Audit dialogue.'
        : '导入制品并开始审计后，系统按流水线自动推进全部阶段。提示词、思考与输出请到左侧「审计过程」查看。'}
    </PageHeader>
    {error && <Notice kind="error">{error}{english ? '. Requests do not fall back to demo data or forged jobs.' : '。请求未回退到演示数据或伪造任务。'}</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    {!projectId && <Notice kind="info">{english ? 'Select or create an authorized workspace on the Workspaces page first.' : '请先在「工作区」首页选择或创建授权工作区。'}</Notice>}
    <div className="audit-grid">
      <ArtifactImportPanel projectId={projectId} artifacts={artifacts} onArtifactsChanged={async () => {
        setLoadingArtifacts(true)
        try { await refreshArtifacts() } finally { setLoadingArtifacts(false) }
      }} />
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">{english ? 'START AUDIT' : '启动审计'}</p><h2>{english ? 'Scope and policy' : '审计范围与策略'}</h2></div><span>{loadingArtifacts ? (english ? 'Loading targets…' : '加载目标…') : (english ? `${artifacts.length} targets` : `${artifacts.length} 个目标`)}</span></div>
        <form className="stack-form" onSubmit={submit}>
          <label className="field"><span>{english ? 'Target artifact' : '目标制品'}</span><select required name="artifactId" disabled={!projectId || loadingArtifacts}><option value="">{loadingArtifacts ? (english ? 'Loading targets' : '正在加载目标') : artifacts.length ? (english ? 'Select artifact' : '选择制品') : (english ? 'No artifacts in workspace' : '当前工作区暂无制品')}</option>{artifacts.map((item) => <option key={item.artifactId} value={item.artifactId}>{artifactLabel(item)}</option>)}</select></label>
          <div className="form-grid">
            <label className="field"><span>{english ? 'Execution mode (external deps)' : '执行模式（外部依赖）'}</span><select name="dependencyMode"><option value="MOCK">{dependencyModeLabel('MOCK', english)}{english ? ': rule/protocol mocks for external deps (only mode available)' : '：外部依赖用规则/协议模拟代替（当前唯一可用）'}</option></select></label>
            <label className="field"><span>{english ? 'Network policy' : '网络策略'}</span><input value={english ? 'No external network (fixed)' : '禁止外网（固定）'} readOnly /></label>
            <label className="field"><span>{english ? 'Timeout (seconds)' : '超时（秒）'}</span><input name="timeout" type="number" min="10" max="3600" defaultValue="300" /></label>
            <label className="field"><span>{english ? 'Memory (MiB)' : '内存（MiB）'}</span><input name="memory" type="number" min="128" max="4096" defaultValue="2048" /></label>
          </div>
          <div className="selected-ai"><small>{english ? 'Automatic pipeline' : '自动流水线'} · {language === 'ZH_CN' ? (english ? 'Simplified Chinese output' : '简体中文输出') : 'English output'}</small><strong>{english ? `${assignments.length}/6 roles bound` : `${assignments.length}/6 个角色已绑定`}</strong><span>{english ? 'After one authorization, the system advances pre-analysis → auth → track observation → bypass confirm → dynamic verification → path exploration → triage → report. Models cannot change sandbox policy or alone upgrade status.' : '一次授权后，系统按前置建模、鉴权分析、按轨观察、绕过确认、动态验证、路径探索、漏洞研判、报告生成推进；模型不能改沙箱策略或单独升级状态。'}</span></div>
          <label className="check-field"><input type="checkbox" name="authorized" />{english ? 'I confirm this artifact and scope are authorized, and accept no external network, dry-run dangerous actions, and automatic pipeline advancement.' : '我确认该制品与范围已获授权，并接受无外网、危险动作空跑演练，以及整条审计流水线自动推进。'}</label>
          <button className="primary-button" disabled={!projectId || busy || artifacts.length === 0}>{busy ? (english ? 'Starting…' : '启动中…') : (english ? 'Start audit (automatic pipeline)' : '开始审计（自动流水线）')}</button>
        </form>
      </article>
      <article className="panel audit-timeline-panel">
        <div className="panel-head"><div><p className="eyebrow">{english ? 'EXECUTION' : '执行过程'}</p><h2>{english ? 'Stage progress' : '阶段进度'}</h2></div>{(scan?.verificationStatus ?? snapshot?.verificationStatus) && <StatusPill status={(scan?.verificationStatus ?? snapshot?.verificationStatus)!} english={english} />}</div>
        <ol className="workflow-timeline">{steps.map((step, index) => <li className={`timeline-${step.state}`} key={step.title}>
          <span>{index + 1}</span>
          <div>
            <strong>{step.title}</strong>
            <small>{step.detail}</small>
            {step.retryStage && <button type="button" className="secondary-button timeline-retry" disabled={busy || !activeScanId} onClick={() => retryStage(step.retryStage!)}>{english ? 'Retry stage' : '重试该阶段'}</button>}
          </div>
          <b>{timelineStateLabel(step.state, english)}</b>
        </li>)}</ol>
        <p className="form-help">{english ? 'No step-by-step approval. A failure stops later auto-advancement; retry a failed stage (new authorized job, re-arm pipeline). Model dialogue details are on Audit dialogue.' : '无需逐步点击批准。任一步失败会停止后续自动推进；可对失败阶段单独重试（新建授权任务并重新武装流水线）。模型对话细节请在「审计过程」页查看。'}</p>
      </article>
    </div>
  </section>
}

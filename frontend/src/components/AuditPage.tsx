import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, artifactLabel, type ArtifactDto, type AuditRetryStage, type DashboardSnapshot, type OutputLanguage, type RoleAssignmentDto } from '../api'
import { confirmAiAuthorization } from '../aiAuthorization'
import { useAuditLiveRefresh } from '../hooks/useAuditLiveRefresh'
import { AI_ROLES, dependencyModeLabel, pipelineStatusLabel, roleLabel, stopReasonLabel, timelineStateLabel } from '../labels'
import { ArtifactImportPanel } from './ArtifactImportPanel'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

/**
 * Stage 进度与 as-built AuditPipelineCoordinator.PipelineStage 1:1 映射，外加两行
 * 流水线前 intake（非 coordinator 游标）：
 *  1 TARGET_READY          — artifact/workspace 绑定（流水线前）
 *  2 STATIC_FACTS          — createOrReplayScan / static IR（流水线前）
 *  3 PRE_ANALYSIS
 *  4 AUTH_ANALYSIS
 *  5 DYNAMIC_OBSERVATION   — 沙箱 track 观测（非「联网探测」）
 *  6 AUTH_BYPASS_CONFIRM   — 无动态 auth 证据时可跳过
 *  7 DYNAMIC_VERIFICATION
 *  8 PATH_EXPLORATION
 *  9 VULNERABILITY_TRIAGE
 * 10 REPORT_GENERATION
 * 重启使用 POST …/audit-stage-retries（自 stage N 重新武装；游标推进后后续 stage 重跑）。
 */
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
  const pipelineStatus = scan?.pipelineStatus
  const pipelinePaused = pipelineStatus === 'PAUSED'
  const pipelineRunning = pipelineStatus === 'RUNNING' || scan?.pipelineArmed === true
  const pipelineControllable = Boolean(activeScanId && activeScanId !== 'unscanned' && (pipelineRunning || pipelinePaused))

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
        ? 'Audit pipeline started: pre-analysis → auth → sandbox observation → bypass confirm → dynamic verification → path exploration → triage → report.'
        : '审计流水线已启动：前置建模 → 鉴权分析 → 沙箱动态观察 → 绕过确认 → 动态验证 → 路径探求 → 漏洞研判 → 报告生成。')
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
      : dynamicStatus === 'QUEUED' || dynamicStatus === 'RUNNING' || dynamicStatus === 'LEASED' || dynamicStatus === 'PAUSED' ? 'active' : 'waiting'
  const laterThanBypassStarted = Boolean(dynamicVerifyJob || pathJob || triageJob || reportJob)
  const authBypassState = authBypassJob
    ? jobState(authBypassJob)
    : (dynamicState === 'completed' && laterThanBypassStarted ? 'skipped' : 'waiting')
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
    : (english ? 'Queued after auth analysis' : '鉴权分析完成后自动排队')

  const stageReached = (state: string) => state === 'completed' || state === 'active' || state === 'unavailable' || state === 'skipped'
  const canRestart = (stage: AuditRetryStage, state: string) => {
    if (!activeScanId || activeScanId === 'unscanned') return false
    if (pipelinePaused) return false
    if (!stageReached(state) && state !== 'waiting') return false
    // 前提可满足时允许重启（stage 已到达，或 PRE）。
    if (stage === 'PRE_ANALYSIS') return Boolean(activeScanId)
    if (stage === 'AUTH_ANALYSIS') return stageReached(jobState(preAnalysisJob)) || jobState(preAnalysisJob) === 'completed'
    if (stage === 'DYNAMIC_OBSERVATION') return jobState(authAnalysisJob) === 'completed'
    if (stage === 'AUTH_BYPASS_CONFIRM') return dynamicState === 'completed'
    if (stage === 'DYNAMIC_VERIFICATION') return dynamicState === 'completed' && jobState(authAnalysisJob) === 'completed'
    if (stage === 'PATH_EXPLORATION') return jobState(dynamicVerifyJob) === 'completed'
    if (stage === 'VULNERABILITY_TRIAGE') return jobState(pathJob) === 'completed'
    if (stage === 'REPORT_GENERATION') return jobState(triageJob) === 'completed'
    return false
  }

  const restartStage = (stage: AuditRetryStage) => {
    if (!projectId || !activeScanId || activeScanId === 'unscanned') {
      setError(english ? 'No scan available to restart' : '没有可重新开始的扫描')
      return
    }
    const confirmText = english
      ? 'Restart this stage and all stages after it on the same scan? In-flight work for the current pipeline attempt will be cancelled.'
      : '将重置本阶段及之后阶段（同一扫描增量重跑）。当前流水线进行中的任务会被取消。是否继续？'
    if (!window.confirm(confirmText)) return
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
        ? (english ? 'Sandbox dynamic observation' : '沙箱动态观察')
        : stage === 'AUTH_BYPASS_CONFIRM'
          ? (english ? 'Auth bypass confirm' : '鉴权绕过确认')
          : roleLabel(stage, english)
      setMessage(english
        ? `Restarted from ${stageLabel}. The pipeline continues from this stage.`
        : `已从「${stageLabel}」重新开始；流水线将从该阶段继续自动推进。`)
      await refreshNow()
      await onRefresh()
    }).catch((cause) => setError(english
      ? `Stage restart failed: ${errorMessage(cause, true)}`
      : `阶段重新开始失败：${errorMessage(cause)}`)).finally(() => setBusy(false))
  }

  const controlPipeline = (action: 'pause' | 'resume' | 'cancel') => {
    if (!activeScanId || activeScanId === 'unscanned') {
      setError(english ? 'No active scan to control' : '没有可控制的扫描')
      return
    }
    if (action === 'cancel') {
      const ok = window.confirm(english
        ? 'Stop this audit pipeline? In-flight AI jobs and dynamic tasks will be cancelled.'
        : '停止本次审计流水线？进行中的模型任务与动态任务将被取消。')
      if (!ok) return
    }
    if (action === 'resume' && !confirmAiAuthorization()) return
    setBusy(true); setError(undefined); setMessage(undefined)
    void api.updateScan(activeScanId, {
      action,
      authorized: true,
      aiAuthorized: action === 'resume' ? true : undefined,
      outputLanguage: action === 'resume' ? language : undefined
    }).then(async (next) => {
      setScan(next)
      setMessage(action === 'pause'
        ? (english ? 'Pipeline paused. Resume to continue from the current stage.' : '流水线已暂停。可点击「继续」从当前阶段恢复。')
        : action === 'resume'
          ? (english ? 'Pipeline resumed from the paused stage.' : '流水线已从暂停阶段继续。')
          : (english ? 'Pipeline stopped.' : '流水线已停止。'))
      await refreshNow()
      await onRefresh()
    }).catch((cause) => setError(english
      ? `Pipeline control failed: ${errorMessage(cause, true)}`
      : `流水线控制失败：${errorMessage(cause)}`)).finally(() => setBusy(false))
  }

  const targetState = snapshot?.artifactDigest || artifacts.length ? 'completed' : 'waiting'
  const staticState = snapshot?.entries?.length || scan?.entries?.length
    ? 'completed'
    : (preAnalysisJob || activeScanId ? 'completed' : 'waiting')

  const steps: Array<{
    id: string
    title: string
    state: string
    detail: string
    restartStage?: AuditRetryStage
  }> = [
    {
      id: 'TARGET_READY',
      title: english ? 'Target & artifact ready' : '目标与制品就绪',
      state: targetState,
      detail: snapshot?.artifactDigest
        ? snapshot.artifactDigest
        : (english ? 'Bind an authorized artifact in the workspace' : '在工作区绑定已授权制品')
    },
    {
      id: 'STATIC_FACTS',
      title: english ? 'Static facts & entry discovery' : '静态事实与入口发现',
      state: staticState,
      detail: english
        ? `${snapshot?.entries.length ?? scan?.entries?.length ?? 0} entries; facts are not model-writable`
        : `${snapshot?.entries.length ?? scan?.entries?.length ?? 0} 个入口；事实层不由模型改写`
    },
    {
      id: 'PRE_ANALYSIS',
      title: english ? 'Pre-analysis (PRE_ANALYSIS)' : '前置建模 PRE_ANALYSIS',
      state: jobState(preAnalysisJob),
      detail: jobDetail(preAnalysisJob, english ? 'Created by pipeline' : '流水线自动创建'),
      restartStage: 'PRE_ANALYSIS'
    },
    {
      id: 'AUTH_ANALYSIS',
      title: english ? 'Auth analysis (AUTH_ANALYSIS)' : '鉴权分析 AUTH_ANALYSIS',
      state: jobState(authAnalysisJob),
      detail: jobDetail(authAnalysisJob, english ? 'Static auth model, synthetic identity, experiment plans' : '静态鉴权模型、合成身份与实验计划'),
      restartStage: 'AUTH_ANALYSIS'
    },
    {
      id: 'DYNAMIC_OBSERVATION',
      title: english ? 'Sandbox dynamic observation' : '沙箱动态观察 DYNAMIC_OBSERVATION',
      state: dynamicState,
      detail: dynamicDetail,
      restartStage: 'DYNAMIC_OBSERVATION'
    },
    {
      id: 'AUTH_BYPASS_CONFIRM',
      title: english ? 'Auth bypass confirm' : '鉴权绕过确认 AUTH_BYPASS_CONFIRM',
      state: authBypassState,
      detail: authBypassState === 'skipped'
        ? (english ? 'Skipped: no dynamic auth evidence' : '已跳过：无动态鉴权证据')
        : jobDetail(authBypassJob, english ? 'Confirm bypass from AUTH_CHALLENGE / pass-gate PathRuns' : '有 AUTH_CHALLENGE / 过闸 PathRun 时确认绕过'),
      restartStage: 'AUTH_BYPASS_CONFIRM'
    },
    {
      id: 'DYNAMIC_VERIFICATION',
      title: english ? 'Dynamic verification' : '动态验证 DYNAMIC_VERIFICATION',
      state: jobState(dynamicVerifyJob),
      detail: jobDetail(dynamicVerifyJob, english ? 'Authorized loopback probes by entry and params' : '沙箱反馈后按入口和参数进行授权 loopback 探索'),
      restartStage: 'DYNAMIC_VERIFICATION'
    },
    {
      id: 'PATH_EXPLORATION',
      title: english ? 'Path exploration' : '路径探求 PATH_EXPLORATION',
      state: jobState(pathJob),
      detail: jobDetail(pathJob, english ? 'Path model after PathRuns; may loop OBS' : 'PathRun 后建立路径模型；可有界回环 OBS'),
      restartStage: 'PATH_EXPLORATION'
    },
    {
      id: 'VULNERABILITY_TRIAGE',
      title: english ? 'Vulnerability triage' : '漏洞研判 VULNERABILITY_TRIAGE',
      state: jobState(triageJob),
      detail: jobDetail(triageJob, english ? 'After PathRun + dynamic debug close; may loop OBS' : 'PathRun 与动态调试闭环后进入；可有界回环 OBS'),
      restartStage: 'VULNERABILITY_TRIAGE'
    },
    {
      id: 'REPORT_GENERATION',
      title: english ? 'Report generation' : '报告生成 REPORT_GENERATION',
      state: jobState(reportJob),
      detail: jobDetail(reportJob, english ? 'Bindings / ledger / gates after triage' : '研判完成后汇总 bindings / ledger / 门禁'),
      restartStage: 'REPORT_GENERATION'
    }
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
          <div className="selected-ai"><small>{english ? 'Automatic pipeline' : '自动流水线'} · {language === 'ZH_CN' ? (english ? 'Simplified Chinese output' : '简体中文输出') : 'English output'}</small><strong>{english ? `${assignments.length}/6 roles bound` : `${assignments.length}/6 个角色已绑定`}</strong><span>{english ? 'After one authorization, the system advances pre-analysis → auth → sandbox observation → bypass confirm → dynamic verification → path exploration → triage → report. Models cannot change sandbox policy or alone upgrade status.' : '一次授权后，系统按前置建模、鉴权分析、沙箱动态观察、绕过确认、动态验证、路径探求、漏洞研判、报告生成推进；模型不能改沙箱策略或单独升级状态。'}</span></div>
          <label className="check-field"><input type="checkbox" name="authorized" />{english ? 'I confirm this artifact and scope are authorized, and accept no external network, dry-run dangerous actions, and automatic pipeline advancement.' : '我确认该制品与范围已获授权，并接受无外网、危险动作空跑演练，以及整条审计流水线自动推进。'}</label>
          <button className="primary-button" disabled={!projectId || busy || artifacts.length === 0}>{busy ? (english ? 'Starting…' : '启动中…') : (english ? 'Start audit (automatic pipeline)' : '开始审计（自动流水线）')}</button>
        </form>
      </article>
      <article className="panel audit-timeline-panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{english ? 'EXECUTION' : '执行过程'}</p>
            <h2>{english ? 'Stage progress' : '阶段进度'}</h2>
          </div>
          <div className="timeline-toolbar">
            {(scan?.verificationStatus ?? snapshot?.verificationStatus) && <StatusPill status={(scan?.verificationStatus ?? snapshot?.verificationStatus)!} english={english} />}
            {pipelinePaused && <span className="timeline-pipeline-flag">{english ? 'Paused' : '已暂停'}</span>}
            {pipelineRunning && !pipelinePaused && <span className="timeline-pipeline-flag">{english ? 'Running' : '运行中'}</span>}
          </div>
        </div>
        <div className="button-row timeline-controls">
          {pipelinePaused
            ? <button type="button" className="secondary-button" disabled={busy || !pipelineControllable} onClick={() => controlPipeline('resume')}>{english ? 'Resume' : '继续'}</button>
            : <button type="button" className="secondary-button" disabled={busy || !pipelineRunning} onClick={() => controlPipeline('pause')}>{english ? 'Pause' : '暂停'}</button>}
          <button type="button" className="danger-button" disabled={busy || !pipelineControllable} onClick={() => controlPipeline('cancel')}>{english ? 'Stop scan' : '停止扫描'}</button>
        </div>
        <ol className="workflow-timeline">{steps.map((step, index) => {
          const restartable = step.restartStage ? canRestart(step.restartStage, step.state) : false
          return <li className={`timeline-${step.state}`} key={step.id}>
            <span>{index + 1}</span>
            <div>
              <strong>{step.title}</strong>
              <small>{step.detail}</small>
            </div>
            <div className="timeline-row-actions">
              {step.restartStage && (
                <button
                  type="button"
                  className="secondary-button timeline-restart"
                  disabled={busy || !restartable}
                  title={!restartable
                    ? (pipelinePaused
                      ? (english ? 'Resume or stop before restarting a stage' : '请先继续或停止流水线，再重新开始阶段')
                      : (english ? 'Stage not reachable yet (prerequisite missing)' : '阶段尚未可达（前置条件未满足）'))
                    : undefined}
                  onClick={() => restartStage(step.restartStage!)}
                >{english ? 'Restart' : '重新开始'}</button>
              )}
              <b>{timelineStateLabel(step.state, english)}</b>
            </div>
          </li>
        })}</ol>
        <p className="form-help">{english
          ? 'Pause keeps the cursor for resume; stop cancels in-flight work. Restart from a row re-queues that coordinator stage and continues automatically. Model dialogue details are on Audit dialogue.'
          : '暂停保留游标以便继续；停止会取消进行中的任务。「重新开始」会从该协调器阶段重新排队并自动向后推进。模型对话细节请在「审计过程」页查看。'}</p>
      </article>
    </div>
  </section>
}

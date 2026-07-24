import { useEffect, useState, type FormEvent } from 'react'
import { api, type ArtifactDto, type DashboardSnapshot, type DynamicTaskDto, type ScanDto } from '../api'
import { AiAuditPanel } from './AiAuditPanel'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

export function AuditPage({ projectId, snapshot, onRefresh }: { projectId: string; snapshot: DashboardSnapshot | null; onRefresh: () => Promise<void> }) {
  const [artifacts, setArtifacts] = useState<ArtifactDto[]>([])
  const [scan, setScan] = useState<ScanDto>()
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [dynamicBusy, setDynamicBusy] = useState(false)
  const [dynamicTask, setDynamicTask] = useState<DynamicTaskDto>()
  const [loadingArtifacts, setLoadingArtifacts] = useState(false)

  useEffect(() => {
    let active = true
    setArtifacts([])
    setScan(undefined)
    setDynamicTask(undefined)
    setError(undefined)
    if (!projectId) return () => { active = false }
    setLoadingArtifacts(true)
    void api.listArtifacts(projectId).then((items) => {
      if (active) setArtifacts(items)
    }).catch((cause) => {
      if (active) setError(errorMessage(cause))
    }).finally(() => {
      if (active) setLoadingArtifacts(false)
    })
    return () => { active = false }
  }, [projectId])

  const activeScanId = scan?.scanId ?? snapshot?.scanId
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
    setBusy(true); setError(undefined)
    void api.createScan({
      artifactId: String(data.get('artifactId')),
      authorized: true,
      dependencyMode: String(data.get('dependencyMode')),
      networkMode: 'DENY',
      dangerousActionMode: 'DRY_RUN',
      maxWallClockSeconds: Number(data.get('timeout')),
      maxMemoryBytes: Number(data.get('memory')) * 1024 * 1024
    }, projectId).then(async (created) => {
      setScan(created)
      await onRefresh()
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setBusy(false))
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
  const steps = [
    ['目标摘要复核', snapshot?.artifactDigest ? 'completed' : 'waiting', snapshot?.artifactDigest ?? '等待后端摘要'],
    ['静态入口建模', snapshot?.entries.length ? 'completed' : 'waiting', `${snapshot?.entries.length ?? 0} 个入口`],
    ['断网 Docker 动态观察', dynamicState, dynamicDetail],
    ['证据复核', snapshot?.findings.some((item) => item.status === 'VERIFIED') ? 'completed' : 'waiting', '不由 AI 单独升级为 VERIFIED']
  ]

  return <section>
    <PageHeader eyebrow="AUDIT / POLICY" title="发起审计">策略只提交固定允许字段；默认断网、无破坏性动作，并要求显式授权。</PageHeader>
    {error && <Notice kind="error">{error}。请求未回退到 demo 或伪造任务。</Notice>}
    <div className="audit-grid">
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">SCAN POLICY</p><h2>扫描策略</h2></div><span>{loadingArtifacts ? '加载目标…' : `${artifacts.length} 个目标`}</span></div>
        <form className="stack-form" onSubmit={submit}>
          <label className="field"><span>目标制品</span><select required name="artifactId" disabled={!projectId || loadingArtifacts}><option value="">{loadingArtifacts ? '正在加载目标' : artifacts.length ? '选择制品' : '当前工作区暂无制品'}</option>{artifacts.map((item) => <option key={item.artifactId} value={item.artifactId}>{item.type} · {item.artifactId}</option>)}</select></label>
          <div className="form-grid">
            <label className="field"><span>依赖模式</span><select name="dependencyMode"><option value="MOCK">MOCK</option><option value="REPLAY">REPLAY</option></select></label>
            <label className="field"><span>网络策略</span><input value="DENY（固定）" readOnly /></label>
            <label className="field"><span>超时（秒）</span><input name="timeout" type="number" min="10" max="3600" defaultValue="300" /></label>
            <label className="field"><span>内存（MiB）</span><input name="memory" type="number" min="128" max="8192" defaultValue="512" /></label>
          </div>
          <label className="check-field"><input type="checkbox" name="authorized" />我确认该制品与范围已获授权，且接受无外网、DRY_RUN 策略。</label>
          <button className="primary-button" disabled={!projectId || busy}>{busy ? '提交中…' : '创建扫描'}</button>
        </form>
      </article>
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">EXECUTION TIMELINE</p><h2>执行过程</h2></div>{(scan?.verificationStatus ?? snapshot?.verificationStatus) && <StatusPill status={(scan?.verificationStatus ?? snapshot?.verificationStatus)!} />}</div>
        <ol className="workflow-timeline">{steps.map(([title, state, detail], index) => <li className={`timeline-${state}`} key={title}><span>{index + 1}</span><div><strong>{title}</strong><small>{detail}</small></div><b>{state === 'unavailable' ? 'UNAVAILABLE' : state.toUpperCase()}</b></li>)}</ol>
        <button className="secondary-button" disabled={!(scan?.scanId ?? snapshot?.scanId) || dynamicBusy} onClick={runArtifactInDocker}>{dynamicBusy ? '排队中…' : '在断网 Docker 中运行当前 JAR'}</button>
        <p className="form-help">仅接受当前 scan 绑定的后端受控制品副本；固定使用 --network none、只读挂载和 JVM Agent，不接受前端命令、路径、环境变量或网络放宽。</p>
        <p className="form-help">SSE 仅作增量通知；最终状态始终以 GET scan/dashboard 为准。</p>
      </article>
    </div>
    <AiAuditPanel projectId={projectId} scanId={activeScanId} />
  </section>
}

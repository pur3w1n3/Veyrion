import { useState, type FormEvent } from 'react'
import { api, type ArtifactDto, type DashboardSnapshot, type ScanDto } from '../api'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

export function AuditPage({ projectId, snapshot, onRefresh }: { projectId: string; snapshot: DashboardSnapshot | null; onRefresh: () => Promise<void> }) {
  const [artifacts, setArtifacts] = useState<ArtifactDto[]>([])
  const [scan, setScan] = useState<ScanDto>()
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)

  const loadArtifacts = () => {
    if (!projectId) return
    void api.listArtifacts(projectId).then(setArtifacts).catch((cause) => setError(errorMessage(cause)))
  }

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

  const steps = [
    ['目标摘要复核', snapshot?.artifactDigest ? 'completed' : 'waiting', snapshot?.artifactDigest ?? '等待后端摘要'],
    ['静态入口建模', snapshot?.entries.length ? 'completed' : 'waiting', `${snapshot?.entries.length ?? 0} 个入口`],
    ['受控动态观察', snapshot?.verificationStatus === 'DYNAMIC_SUSPECTED' ? 'active' : 'unavailable', '仅受控 Fixture / 强化沙箱'],
    ['证据复核', snapshot?.findings.some((item) => item.status === 'VERIFIED') ? 'completed' : 'waiting', '不由 AI 单独升级为 VERIFIED']
  ]

  return <section>
    <PageHeader eyebrow="AUDIT / POLICY" title="发起审计">策略只提交固定允许字段；默认断网、无破坏性动作，并要求显式授权。</PageHeader>
    {error && <Notice kind="error">{error}。请求未回退到 demo 或伪造任务。</Notice>}
    <div className="audit-grid">
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">SCAN POLICY</p><h2>扫描策略</h2></div><button className="text-button" onClick={loadArtifacts} disabled={!projectId}>刷新目标</button></div>
        <form className="stack-form" onSubmit={submit}>
          <label className="field"><span>目标制品</span><select required name="artifactId" disabled={!projectId}><option value="">选择制品</option>{artifacts.map((item) => <option key={item.artifactId} value={item.artifactId}>{item.type} · {item.artifactId}</option>)}</select></label>
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
        <p className="form-help">SSE 仅作增量通知；最终状态始终以 GET scan/dashboard 为准。</p>
      </article>
    </div>
  </section>
}

import { useEffect, useState, type FormEvent } from 'react'
import { api, type ArtifactDto, type ProjectDto } from '../api'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

type Props = {
  projects: ProjectDto[]
  projectId: string
  onSelect: (projectId: string) => void
  onProjectsChanged: () => Promise<void>
}

export function WorkspacePage({ projects, projectId, onSelect, onProjectsChanged }: Props) {
  const [artifacts, setArtifacts] = useState<ArtifactDto[]>([])
  const [message, setMessage] = useState<string>()
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!projectId) { setArtifacts([]); return }
    void api.listArtifacts(projectId).then(setArtifacts).catch((cause) => {
      setArtifacts([])
      setError(errorMessage(cause))
    })
  }, [projectId])

  const perform = async (operation: () => Promise<void>, success: string) => {
    setBusy(true); setError(undefined); setMessage(undefined)
    try { await operation(); setMessage(success) } catch (cause) { setError(errorMessage(cause)) } finally { setBusy(false) }
  }

  const createProject = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    const name = String(data.get('name') ?? '').trim()
    if (!name) return
    void perform(async () => {
      const created = await api.createProject({ name })
      form.reset()
      await onProjectsChanged()
      onSelect(created.projectId)
    }, '项目已创建')
  }

  const registerArtifact = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    const path = String(data.get('path') ?? '').trim()
    const type = String(data.get('type') ?? 'JAR')
    void perform(async () => {
      const artifact = await api.registerArtifact({ path, type, staticOnly: true }, projectId)
      setArtifacts((current) => [...current, artifact])
      form.reset()
    }, '审计目标已登记；浏览器未读取本地文件')
  }

  const removeProject = () => {
    if (!projectId || !window.confirm('删除当前项目？后端必须再次执行权限校验，此操作不可由前端撤销。')) return
    void perform(async () => {
      await api.deleteProject(projectId)
      onSelect('')
      await onProjectsChanged()
    }, '项目已删除')
  }

  return <section>
    <PageHeader eyebrow="WORKSPACE / PROJECTS" title="工作区" action={<button className="danger-button" disabled={!projectId || busy} onClick={removeProject}>删除当前项目</button>}>
      选择或创建授权项目；项目切换不会改变工具权限、沙箱能力或授权范围。
    </PageHeader>
    {error && <Notice kind="error">{error}。该能力当前 unavailable，未创建任何本地替代数据。</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    <div className="two-column">
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">PROJECT SELECTOR</p><h2>项目</h2></div><span>{projects.length}</span></div>
        <label className="field"><span>当前项目</span><select value={projectId} onChange={(event) => onSelect(event.target.value)}><option value="">请选择</option>{projects.map((project) => <option key={project.projectId} value={project.projectId}>{project.name} · {project.projectId}</option>)}</select></label>
        <form className="stack-form" onSubmit={createProject}>
          <label className="field"><span>新项目名称</span><input name="name" maxLength={100} required placeholder="例如：结算服务授权审计" /></label>
          <button className="primary-button" disabled={busy}>创建项目</button>
        </form>
      </article>
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">AUTHORIZED TARGET</p><h2>登记审计目标</h2></div><span>JVM</span></div>
        <form className="stack-form" onSubmit={registerArtifact}>
          <label className="field"><span>Control Plane 可访问的本地路径</span><input name="path" required disabled={!projectId} placeholder="E:\authorized\samples\app.jar" /></label>
          <label className="field"><span>制品类型</span><select name="type" disabled={!projectId}><option>JAR</option><option>WAR</option><option>CLASS</option></select></label>
          <p className="form-help">首版固定静态登记。路径发送给本地 Control Plane，浏览器不会上传或打开文件。</p>
          <button className="primary-button" disabled={!projectId || busy}>登记目标</button>
        </form>
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">ARTIFACT INVENTORY</p><h2>已登记目标</h2></div><span>{artifacts.length} items</span></div>
      <div className="card-list">{artifacts.map((artifact) => <div className="list-card" key={artifact.artifactId}><div><strong>{artifact.type} · {artifact.artifactId}</strong><small>{artifact.artifactDigest} · {(artifact.sizeBytes / 1024).toFixed(1)} KiB</small></div><StatusPill status={artifact.verificationStatus} /></div>)}{artifacts.length === 0 && <p className="empty-state">暂无已登记制品。</p>}</div>
    </article>
  </section>
}

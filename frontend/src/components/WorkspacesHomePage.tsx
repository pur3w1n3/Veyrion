import { useState, type FormEvent } from 'react'
import { api, type ProjectDto } from '../api'
import { errorMessage, Notice, PageHeader } from './Common'

type Props = {
  projects: ProjectDto[]
  projectId: string
  onSelect: (projectId: string) => void
  onOpenAudit: () => void
  onProjectsChanged: () => Promise<void>
}

export function WorkspacesHomePage({
  projects,
  projectId,
  onSelect,
  onOpenAudit,
  onProjectsChanged
}: Props) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [message, setMessage] = useState<string>()
  const [creating, setCreating] = useState(false)
  const [nameDraft, setNameDraft] = useState('')

  const createProject = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const name = nameDraft.trim()
    if (!name) return
    setBusy(true)
    setError(undefined)
    setMessage(undefined)
    void api.createProject({ name }).then(async (created) => {
      setNameDraft('')
      setCreating(false)
      await onProjectsChanged()
      onSelect(created.projectId)
      setMessage(`已创建工作区「${created.name}」并切换为当前工作区`)
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setBusy(false))
  }

  const removeProject = (project: ProjectDto) => {
    if (!window.confirm(`删除工作区「${project.name}」？此操作由后端再次校验权限，相关扫描与任务不会在界面伪造删除成功。`)) return
    setBusy(true)
    setError(undefined)
    setMessage(undefined)
    void api.deleteProject(project.projectId).then(async () => {
      if (project.projectId === projectId) onSelect('')
      await onProjectsChanged()
      setMessage(`已删除工作区「${project.name}」`)
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setBusy(false))
  }

  const openWorkspace = (nextId: string) => {
    onSelect(nextId)
    onOpenAudit()
  }

  return <section className="workspaces-home">
    <PageHeader
      eyebrow="工作区"
      title="工作区"
      action={<button className="primary-button" type="button" disabled={busy} onClick={() => {
        setCreating(true)
        setError(undefined)
        setMessage(undefined)
      }}>新建工作区</button>}
    >
      以格子浏览已有授权工作区。点击格子即可切换并进入审计执行；也可在此新建或删除。
    </PageHeader>
    {error && <Notice kind="error">{error}</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    {creating && <article className="panel section-gap create-workspace-panel">
      <div className="panel-head"><div><p className="eyebrow">新建</p><h2>添加工作区</h2></div><button className="text-button" type="button" disabled={busy} onClick={() => setCreating(false)}>取消</button></div>
      <form className="stack-form" onSubmit={createProject}>
        <label className="field"><span>工作区名称</span><input value={nameDraft} maxLength={100} required placeholder="例如：结算服务授权审计" onChange={(event) => setNameDraft(event.target.value)} /></label>
        <div className="button-row">
          <button className="primary-button" disabled={busy || !nameDraft.trim()}>{busy ? '创建中…' : '创建并设为当前'}</button>
        </div>
      </form>
    </article>}
    <div className="workspace-tile-grid">
      {projects.map((project) => {
        const active = project.projectId === projectId
        return <article className={`workspace-tile ${active ? 'active' : ''}`} key={project.projectId}>
          <button className="workspace-tile-main" type="button" disabled={busy} onClick={() => openWorkspace(project.projectId)}>
            <span className="workspace-tile-mark">{project.name.slice(0, 1).toUpperCase()}</span>
            <strong>{project.name}</strong>
            <small>{project.projectId}</small>
            {active ? <b>当前工作区</b> : <b>点击切换</b>}
          </button>
          <div className="workspace-tile-actions">
            <button className="secondary-button" type="button" disabled={busy} onClick={() => openWorkspace(project.projectId)}>进入审计</button>
            <button className="danger-button" type="button" disabled={busy} onClick={() => removeProject(project)}>删除</button>
          </div>
        </article>
      })}
      <button className="workspace-tile workspace-tile-add" type="button" disabled={busy} onClick={() => setCreating(true)}>
        <span aria-hidden="true">＋</span>
        <strong>添加工作区</strong>
        <small>创建新的授权审计上下文</small>
      </button>
    </div>
    {projects.length === 0 && !creating && <p className="empty-state">还没有工作区。点击「新建工作区」或下方添加格子开始。</p>}
  </section>
}

import { useState, type FormEvent } from 'react'
import { api, type ProjectDto } from '../api'
import { errorMessage, Notice } from './Common'

type Props = {
  projects: ProjectDto[]
  projectId: string
  onSelect: (projectId: string) => void
  onProjectsChanged: () => Promise<void>
}

export function WorkspaceSwitcher({ projects, projectId, onSelect, onProjectsChanged }: Props) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const current = projects.find((project) => project.projectId === projectId)

  const createProject = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const name = String(new FormData(form).get('name') ?? '').trim()
    if (!name) return
    setBusy(true)
    setError(undefined)
    void api.createProject({ name }).then(async (created) => {
      form.reset()
      await onProjectsChanged()
      onSelect(created.projectId)
      setOpen(false)
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setBusy(false))
  }

  const removeCurrent = () => {
    if (!projectId || !window.confirm(`删除工作区“${current?.name ?? projectId}”？此操作由后端再次校验权限。`)) return
    setBusy(true)
    setError(undefined)
    void api.deleteProject(projectId).then(async () => {
      onSelect('')
      await onProjectsChanged()
      setOpen(false)
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setBusy(false))
  }

  return <div className="workspace-switcher">
    <button className="workspace-chip" type="button" aria-expanded={open} onClick={() => {
      setError(undefined)
      setOpen((value) => !value)
    }}>
      <span />
      <div><small>当前工作区 · 点击切换</small><strong>{current?.name ?? '未选择工作区'}</strong></div>
      <b aria-hidden="true">{open ? '▴' : '▾'}</b>
    </button>
    {open && <div className="workspace-menu" role="dialog" aria-label="切换工作区">
      <label className="field"><span>已授权工作区</span><select value={projectId} disabled={busy} onChange={(event) => {
        onSelect(event.target.value)
        setOpen(false)
      }}><option value="">请选择工作区</option>{projects.map((project) => <option key={project.projectId} value={project.projectId}>{project.name}</option>)}</select></label>
      <form className="stack-form" onSubmit={createProject}>
        <label className="field"><span>新建工作区</span><input name="name" maxLength={100} required placeholder="例如：结算服务授权审计" /></label>
        <button className="primary-button" disabled={busy}>{busy ? '处理中…' : '创建并切换'}</button>
      </form>
      {projectId && <button className="danger-button" type="button" disabled={busy} onClick={removeCurrent}>删除当前工作区</button>}
      {error && <Notice kind="error">{error}</Notice>}
    </div>}
  </div>
}

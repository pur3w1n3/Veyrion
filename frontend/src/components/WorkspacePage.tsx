import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react'
import { api, MAX_BROWSER_HASH_BYTES, type ArtifactDto, type ProjectDto, type UploadTask } from '../api'
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
  const [selectedFile, setSelectedFile] = useState<File>()
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadFailed, setUploadFailed] = useState(false)
  const uploadRef = useRef<UploadTask | undefined>(undefined)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!projectId) { setArtifacts([]); return }
    void api.listArtifacts(projectId).then(setArtifacts).catch((cause) => {
      setArtifacts([])
      setError(errorMessage(cause))
    })
  }, [projectId])

  useEffect(() => () => uploadRef.current?.cancel(), [projectId])

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

  const chooseFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    setSelectedFile(file)
    setUploadProgress(0)
    setUploadFailed(false)
    setError(undefined)
    setMessage(undefined)
  }

  const startUpload = () => {
    if (!selectedFile || !projectId || uploading) return
    setUploading(true)
    setUploadProgress(0)
    setUploadFailed(false)
    setError(undefined)
    setMessage(undefined)
    const task = api.uploadArtifact(selectedFile, projectId, setUploadProgress)
    uploadRef.current = task
    void task.then(async () => {
      setArtifacts(await api.listArtifacts(projectId))
      setMessage('制品上传并登记成功')
      setSelectedFile(undefined)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }).catch((cause) => {
      setUploadFailed(true)
      setError(errorMessage(cause))
    }).finally(() => {
      if (uploadRef.current === task) uploadRef.current = undefined
      setUploading(false)
    })
  }

  const cancelUpload = () => {
    uploadRef.current?.cancel()
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
    {error && <Notice kind="error">{error}</Notice>}
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
        <div className="panel-head"><div><p className="eyebrow">AUTHORIZED TARGET</p><h2>上传审计目标</h2></div><span>JAR / WAR / CLASS</span></div>
        <div className="stack-form">
          <label className="field"><span>选择本地制品</span><input ref={fileInputRef} type="file" accept=".jar,.war,.class" disabled={!projectId || uploading} onChange={chooseFile} /></label>
          {selectedFile && <div className="upload-summary">
            <div><strong>{selectedFile.name}</strong><small>{formatBytes(selectedFile.size)}</small></div>
            <span>{uploading ? uploadProgress === 0 ? '正在计算 SHA-256' : `上传 ${uploadProgress}%` : uploadFailed ? '上传失败' : '等待上传'}</span>
          </div>}
          {(uploading || uploadProgress > 0) && <progress className="upload-progress" max="100" value={uploadProgress} aria-label="制品上传进度">{uploadProgress}%</progress>}
          <p className="form-help">浏览器先计算完整文件 SHA-256，再以 1 MiB 分块上传并校验每块摘要。因 Web Crypto 需要将完整文件载入内存，文件上限为 {MAX_BROWSER_HASH_BYTES / 1024 / 1024} MiB；文件内容、路径和密钥不会写入浏览器存储或日志。</p>
          <div className="button-row">
            <button type="button" className="primary-button" disabled={!projectId || !selectedFile || uploading} onClick={startUpload}>计算摘要并上传</button>
            {uploading && <button type="button" className="danger-button" onClick={cancelUpload}>取消上传</button>}
          </div>
          <details className="compatibility-panel">
            <summary>高级/兼容方式：登记 Control Plane 本地路径</summary>
            <form className="stack-form" onSubmit={registerArtifact}>
              <label className="field"><span>Control Plane 可访问的本地路径</span><input name="path" required disabled={!projectId || uploading} placeholder="E:\authorized\samples\app.jar" /></label>
              <label className="field"><span>制品类型</span><select name="type" disabled={!projectId || uploading}><option>JAR</option><option>WAR</option><option>CLASS</option></select></label>
              <p className="form-help">仅用于本地部署兼容场景。浏览器不会读取该路径，后端仍会执行授权根目录与文件边界校验。</p>
              <button className="secondary-button" disabled={!projectId || busy || uploading}>登记路径</button>
            </form>
          </details>
        </div>
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">ARTIFACT INVENTORY</p><h2>已登记目标</h2></div><span>{artifacts.length} items</span></div>
      <div className="card-list">{artifacts.map((artifact) => <div className="list-card" key={artifact.artifactId}><div><strong>{artifact.type} · {artifact.artifactId}</strong><small>{artifact.artifactDigest} · {(artifact.sizeBytes / 1024).toFixed(1)} KiB</small></div><StatusPill status={artifact.verificationStatus} /></div>)}{artifacts.length === 0 && <p className="empty-state">暂无已登记制品。</p>}</div>
    </article>
  </section>
}

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
}

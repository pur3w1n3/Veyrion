import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react'
import { api, MAX_BROWSER_HASH_BYTES, type ArtifactDto, type UploadTask } from '../api'
import { errorMessage, Notice, StatusPill } from './Common'

type Props = {
  projectId: string
  artifacts: ArtifactDto[]
  onArtifactsChanged: () => Promise<void>
}

export function ArtifactImportPanel({ projectId, artifacts, onArtifactsChanged }: Props) {
  const [selectedFile, setSelectedFile] = useState<File>()
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [message, setMessage] = useState<string>()
  const uploadRef = useRef<UploadTask | undefined>(undefined)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => () => uploadRef.current?.cancel(), [projectId])

  const chooseFile = (event: ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(event.target.files?.[0])
    setUploadProgress(0)
    setError(undefined)
    setMessage(undefined)
  }

  const upload = () => {
    if (!selectedFile || !projectId || uploading) return
    setUploading(true)
    setUploadProgress(0)
    setError(undefined)
    setMessage(undefined)
    const task = api.uploadArtifact(selectedFile, projectId, setUploadProgress)
    uploadRef.current = task
    void task.then(async () => {
      await onArtifactsChanged()
      setMessage('制品已校验并保存到后端内容寻址目录')
      setSelectedFile(undefined)
      if (inputRef.current) inputRef.current.value = ''
    }).catch((cause) => setError(errorMessage(cause))).finally(() => {
      if (uploadRef.current === task) uploadRef.current = undefined
      setUploading(false)
    })
  }

  const registerPath = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    setBusy(true)
    setError(undefined)
    setMessage(undefined)
    void api.registerArtifact({
      path: String(data.get('path') ?? '').trim(),
      type: String(data.get('type') ?? 'JAR'),
      staticOnly: true
    }, projectId).then(async () => {
      form.reset()
      await onArtifactsChanged()
      setMessage('Control Plane 本地制品已登记')
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setBusy(false))
  }

  return <article className="panel">
    <div className="panel-head"><div><p className="eyebrow">AUTHORIZED ARTIFACT</p><h2>导入审计目标</h2></div><span>{artifacts.length} 个版本</span></div>
    {error && <Notice kind="error">{error}</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    <div className="stack-form">
      <label className="field"><span>选择 JAR / WAR / CLASS</span><input ref={inputRef} type="file" accept=".jar,.war,.class" disabled={!projectId || uploading} onChange={chooseFile} /></label>
      {selectedFile && <div className="upload-summary"><div><strong>{selectedFile.name}</strong><small>{formatBytes(selectedFile.size)}</small></div><span>{uploading ? uploadProgress === 0 ? '计算 SHA-256' : `上传 ${uploadProgress}%` : '等待上传'}</span></div>}
      {(uploading || uploadProgress > 0) && <progress className="upload-progress" max="100" value={uploadProgress}>{uploadProgress}%</progress>}
      <p className="form-help">浏览器计算完整 SHA-256 后分块上传；后端复核大小、扩展名、ZIP 结构和摘要。浏览器哈希上限为 {MAX_BROWSER_HASH_BYTES / 1024 / 1024} MiB。</p>
      <div className="button-row">
        <button className="primary-button" type="button" disabled={!projectId || !selectedFile || uploading} onClick={upload}>校验并导入</button>
        {uploading && <button className="danger-button" type="button" onClick={() => uploadRef.current?.cancel()}>取消</button>}
      </div>
      <details className="compatibility-panel">
        <summary>高级：登记 Control Plane 本地路径</summary>
        <form className="stack-form" onSubmit={registerPath}>
          <label className="field"><span>授权目录内路径</span><input name="path" required disabled={!projectId || busy} placeholder="E:\authorized\samples\app.jar" /></label>
          <label className="field"><span>类型</span><select name="type" disabled={!projectId || busy}><option>JAR</option><option>WAR</option><option>CLASS</option></select></label>
          <button className="secondary-button" disabled={!projectId || busy}>{busy ? '登记中…' : '登记路径'}</button>
        </form>
      </details>
    </div>
    <div className="card-list section-gap">{artifacts.map((artifact) => <div className="list-card" key={artifact.artifactId}><div><strong>{artifact.type} · {artifact.artifactId}</strong><small>{artifact.artifactDigest} · {formatBytes(artifact.sizeBytes)}</small></div><StatusPill status={artifact.verificationStatus} /></div>)}{artifacts.length === 0 && <p className="empty-state">当前工作区尚未导入审计目标。</p>}</div>
  </article>
}

const formatBytes = (bytes: number) => bytes < 1024
  ? `${bytes} B`
  : bytes < 1024 * 1024
    ? `${(bytes / 1024).toFixed(1)} KiB`
    : `${(bytes / 1024 / 1024).toFixed(1)} MiB`

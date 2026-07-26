import { useEffect, useState } from 'react'
import { api, type ScanDto } from '../api'
import { dependencyModeLabel } from '../labels'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

export function AuditHistoryPage({
  projectId,
  activeScanId,
  onOpenScan,
  onOpenAudit
}: {
  projectId: string
  activeScanId?: string
  onOpenScan: (scanId: string) => void
  onOpenAudit: () => void
}) {
  const [scans, setScans] = useState<ScanDto[]>([])
  const [error, setError] = useState<string>()
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let active = true
    setScans([])
    setError(undefined)
    if (!projectId) return () => { active = false }
    setLoading(true)
    void api.listScans(projectId).then((items) => {
      if (!active) return
      setScans(items)
    }).catch((cause) => {
      if (active) setError(errorMessage(cause))
    }).finally(() => {
      if (active) setLoading(false)
    })
    return () => { active = false }
  }, [projectId])

  return <section>
    <PageHeader eyebrow="历史记录" title="审计历史">
      查看当前工作区全部扫描记录。点击一条可打开其结果快照；失败阶段请到「审计执行」重试对应链路。
    </PageHeader>
    {error && <Notice kind="error">{error}</Notice>}
    {!projectId && <Notice kind="info">请先在「工作区」选择授权工作区。</Notice>}
    <article className="panel">
      <div className="panel-head">
        <div><p className="eyebrow">工作区扫描</p><h2>{loading ? '加载中…' : `${scans.length} 条记录`}</h2></div>
        <button type="button" className="secondary-button" disabled={!projectId} onClick={onOpenAudit}>去审计执行</button>
      </div>
      {scans.length === 0 && !loading && projectId && <p className="form-help">尚无扫描记录。开始一次审计后会出现在这里。</p>}
      <ul className="history-list">
        {scans.map((scan) => {
          const selected = scan.scanId === activeScanId
          return <li key={scan.scanId} className={selected ? 'history-item selected' : 'history-item'}>
            <div>
              <strong>{scan.scanId}</strong>
              <small>{scan.createdAt}{scan.completedAt ? ` → ${scan.completedAt}` : ''}</small>
              <small>制品 {scan.artifactDigest.slice(0, 16)}… · {dependencyModeLabel(scan.dependencyMode)} · {scan.status}</small>
            </div>
            <div className="history-actions">
              <StatusPill status={scan.verificationStatus} />
              <button type="button" className="secondary-button" onClick={() => onOpenScan(scan.scanId)}>
                {selected ? '当前查看中' : '查看结果'}
              </button>
            </div>
          </li>
        })}
      </ul>
    </article>
  </section>
}

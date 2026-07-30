import { useEffect, useState } from 'react'
import { api, type OutputLanguage, type ScanDto } from '../api'
import { formatDisplayDateTime } from '../datetime'
import { dependencyModeLabel } from '../labels'
import { errorMessage, Notice, PageHeader, StatusPill } from './Common'

export function AuditHistoryPage({
  projectId,
  language = 'ZH_CN',
  activeScanId,
  onOpenScan,
  onOpenAudit,
  onScanDeleted
}: {
  projectId: string
  language?: OutputLanguage
  activeScanId?: string
  onOpenScan: (scanId: string) => void
  onOpenAudit: () => void
  onScanDeleted?: (scanId: string) => void
}) {
  const english = language === 'EN'
  const [scans, setScans] = useState<ScanDto[]>([])
  const [error, setError] = useState<string>()
  const [loading, setLoading] = useState(false)
  const [deletingId, setDeletingId] = useState<string>()

  const refresh = () => {
    if (!projectId) {
      setScans([])
      return
    }
    setLoading(true)
    setError(undefined)
    void api.listScans(projectId).then((items) => {
      setScans(items)
    }).catch((cause) => {
      setError(errorMessage(cause, english))
    }).finally(() => {
      setLoading(false)
    })
  }

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
      if (active) setError(errorMessage(cause, english))
    }).finally(() => {
      if (active) setLoading(false)
    })
    return () => { active = false }
  }, [projectId, english])

  const removeScan = (scan: ScanDto) => {
    if (!projectId || deletingId) return
    if (!window.confirm(
      english
        ? `Delete scan record “${scan.scanId}”? In-flight tasks for this scan will be cancelled, then the record is permanently removed. The UI updates only after the server confirms success.`
        : `删除扫描记录「${scan.scanId}」？将取消该扫描进行中的任务后永久删除；界面仅在服务端确认成功后更新。`
    )) return
    setDeletingId(scan.scanId)
    setError(undefined)
    void api.deleteScan(projectId, scan.scanId)
      .then(() => {
        setScans((current) => current.filter((item) => item.scanId !== scan.scanId))
        onScanDeleted?.(scan.scanId)
        refresh()
      })
      .catch((cause) => {
        setError(errorMessage(cause, english))
        refresh()
      })
      .finally(() => setDeletingId(undefined))
  }

  return <section>
    <PageHeader eyebrow={english ? 'HISTORY' : '历史记录'} title={english ? 'Audit history' : '审计历史'}>
      {english
        ? 'All scans in the current workspace. Open a row for its results snapshot; retry failed stages from Audit run.'
        : '查看当前工作区全部扫描记录。点击一条可打开其结果快照；失败阶段请到「审计执行」重试对应链路。'}
    </PageHeader>
    {error && <Notice kind="error">{error}</Notice>}
    {!projectId && <Notice kind="info">{english ? 'Select an authorized workspace first.' : '请先在「工作区」选择授权工作区。'}</Notice>}
    <article className="panel">
      <div className="panel-head">
        <div><p className="eyebrow">{english ? 'WORKSPACE SCANS' : '工作区扫描'}</p><h2>{loading ? (english ? 'Loading…' : '加载中…') : (english ? `${scans.length} records` : `${scans.length} 条记录`)}</h2></div>
        <button type="button" className="secondary-button" disabled={!projectId} onClick={onOpenAudit}>
          {english ? 'Go to Audit run' : '去审计执行'}
        </button>
      </div>
      {scans.length === 0 && !loading && projectId && (
        <p className="form-help">{english ? 'No scan records yet. Start an audit to populate this list.' : '尚无扫描记录。开始一次审计后会出现在这里。'}</p>
      )}
      <ul className="history-list">
        {scans.map((scan) => {
          const selected = scan.scanId === activeScanId
          const busy = deletingId === scan.scanId
          return <li key={scan.scanId} className={selected ? 'history-item selected' : 'history-item'}>
            <div>
              <strong>{scan.scanId}</strong>
              <small>{formatDisplayDateTime(scan.createdAt, { english })}{scan.completedAt ? ` → ${formatDisplayDateTime(scan.completedAt, { english })}` : ''}</small>
              <small>{english ? 'Artifact' : '制品'} {scan.artifactDigest.slice(0, 16)}… · {dependencyModeLabel(scan.dependencyMode, english)} · {scan.status}</small>
            </div>
            <div className="history-actions">
              <StatusPill status={scan.verificationStatus} english={english} />
              <div className="history-action-buttons">
                <button type="button" className="secondary-button" disabled={busy} onClick={() => onOpenScan(scan.scanId)}>
                  {selected ? (english ? 'Viewing' : '当前查看中') : (english ? 'View results' : '查看结果')}
                </button>
                <button type="button" className="danger-button" disabled={busy || !projectId} onClick={() => removeScan(scan)}>
                  {busy ? (english ? 'Deleting…' : '删除中…') : (english ? 'Delete' : '删除')}
                </button>
              </div>
            </div>
          </li>
        })}
      </ul>
    </article>
  </section>
}

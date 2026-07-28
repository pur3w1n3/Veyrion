import type { DashboardSnapshot } from '../../api'
import { dependencyModeLabel, jobStatusLabel } from '../../labels'
import { StatusPill } from '../Common'

export function ScanContextBand({
  snapshot,
  english,
  reportJobStatus,
  reportErrorCode
}: {
  snapshot: DashboardSnapshot | null
  english: boolean
  reportJobStatus?: string
  reportErrorCode?: string
}) {
  const scanId = snapshot?.scanId ?? (english ? 'unscanned' : '未扫描')
  const verificationStatus = snapshot?.verificationStatus

  return (
    <header className="scan-context-band" aria-label={english ? 'Scan context' : '扫描上下文'}>
      <div className="scan-context-band__scope">
        <span className="scan-context-band__label">{english ? 'Scan' : '扫描'}</span>
        <code className="veyrion-long-text">{scanId}</code>
        {snapshot?.projectId && <>
          <span className="scan-context-band__sep">·</span>
          <span className="scan-context-band__label">{english ? 'Project' : '项目'}</span>
          <code className="veyrion-long-text">{snapshot.projectId}</code>
        </>}
        {snapshot?.artifactDigest && <>
          <span className="scan-context-band__sep">·</span>
          <span className="scan-context-band__label">{english ? 'Artifact' : '制品'}</span>
          <code className="veyrion-long-text">{snapshot.artifactDigest.slice(0, 12)}…</code>
        </>}
      </div>
      <div className="scan-context-band__status">
        {verificationStatus && <StatusPill status={verificationStatus} />}
        {snapshot?.dependencyMode && (
          <span className="scan-context-band__meta">{dependencyModeLabel(snapshot.dependencyMode)}</span>
        )}
        {reportJobStatus && (
          <span className="scan-context-band__meta">
            {english ? 'Report' : '报告'} · {jobStatusLabel(reportJobStatus)}
            {reportErrorCode ? ` · ${reportErrorCode}` : ''}
          </span>
        )}
      </div>
    </header>
  )
}

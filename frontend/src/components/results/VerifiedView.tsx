import type { DashboardSnapshot, VerifiedFindingDto } from '../../api'
import { StatusPill } from '../Common'
import { formatCoverageDelta } from './resultsUtils'

export function VerifiedView({
  english,
  verifiedFindings
}: {
  english: boolean
  verifiedFindings: VerifiedFindingDto[]
}) {
  return (
    <div className="results-view results-view--verified">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'VERIFIED' : '已验证'}</p>
          <h2>{english ? 'VerifiedStatusGate (gated)' : 'VerifiedStatusGate（门禁）'}</h2>
        </div>
        <span>{verifiedFindings.length}</span>
      </div>
      <p className="form-help">
        {english
          ? 'Empty means no VERIFIED promotion yet — not a claim of zero risk.'
          : '空列表表示尚未升格 VERIFIED，不等于无风险。'}
      </p>
      <div className="results-table-list">
        {verifiedFindings.map((item) => (
          <div className={`results-row status-tone-${item.verificationStatus.toLowerCase()}`} key={item.findingId}>
            <span className={`severity severity-${item.severity ?? 'info'}`}>{item.severity ?? 'info'}</span>
            <div className="results-row__body">
              <strong>{item.title || item.findingId}</strong>
              <small>{[item.entry, item.sink].filter(Boolean).join(' → ') || item.findingId}</small>
            </div>
            <StatusPill status={item.verificationStatus} />
          </div>
        ))}
        {verifiedFindings.length === 0 && (
          <p className="empty-state">{english ? 'No verified_findings rows.' : '尚无 verified_findings 行。'}</p>
        )}
      </div>
    </div>
  )
}

export function ContrastView({
  english,
  snapshot
}: {
  english: boolean
  snapshot: DashboardSnapshot | null
}) {
  const rankedSinks = snapshot?.rankedSinks ?? []
  const ledgerDiff = snapshot?.ledgerDiff
  const topRankedSinks = rankedSinks.slice(0, 12)

  return (
    <div className="results-view results-view--contrast">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'RANKED SINKS' : 'Sink 排序'}</p>
          <h2>{english ? 'Candidate sink ranking' : '候选 Sink 排序'}</h2>
        </div>
        <span>{rankedSinks.length}</span>
      </div>
      <div className="results-table-list">
        {topRankedSinks.map((sink) => (
          <div className="results-row" key={sink.sinkId}>
            <span className="severity severity-medium">#{sink.rank}</span>
            <div className="results-row__body">
              <strong>{sink.symbol || sink.sinkId}</strong>
              <small>{sink.category || '—'} · {sink.score.toFixed(2)}</small>
            </div>
          </div>
        ))}
        {rankedSinks.length === 0 && (
          <p className="empty-state">{english ? 'No ranked sinks.' : '尚无 Sink 排序。'}</p>
        )}
      </div>

      <div className="section-gap">
        <p className="eyebrow">{english ? 'LEDGER DIFF' : '对照账本差分'}</p>
        <dl className="ledger-diff-stats">
          <div><dt>{english ? 'Newly matched' : '新命中'}</dt><dd>{ledgerDiff?.newlyMatched.length ?? 0}</dd></div>
          <div><dt>{english ? 'Regressions' : '回退'}</dt><dd>{ledgerDiff?.regressions.length ?? 0}</dd></div>
          <div><dt>{english ? 'Unchanged' : '未变'}</dt><dd>{ledgerDiff?.unchangedCount ?? 0}</dd></div>
          <div><dt>{english ? 'Coverage Δ' : '覆盖率变化'}</dt><dd>{formatCoverageDelta(ledgerDiff?.coverageDelta ?? 0)}</dd></div>
        </dl>
        {snapshot?.contrastSnapshotId && (
          <p className="form-help">snapshot · {snapshot.contrastSnapshotId}</p>
        )}
      </div>
    </div>
  )
}

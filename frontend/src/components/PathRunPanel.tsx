import { useMemo, useState } from 'react'
import type { PathRunDto } from '../api'
import { outcomeClassLabel } from '../labels'
import { StatusPill } from './Common'

export function PathRunPanel({
  pathRuns,
  english
}: {
  pathRuns: PathRunDto[]
  english: boolean
}) {
  const [track, setTrack] = useState<'ALL' | string>('ALL')
  const [outcome, setOutcome] = useState<'ALL' | string>('ALL')
  const [selectedId, setSelectedId] = useState<string>()

  const tracks = useMemo(
    () => Array.from(new Set(pathRuns.map((run) => run.track))).sort(),
    [pathRuns]
  )
  const outcomes = useMemo(
    () => Array.from(new Set(pathRuns.map((run) => run.outcomeClass))).sort(),
    [pathRuns]
  )
  const filtered = useMemo(() => pathRuns.filter((run) => {
    if (track !== 'ALL' && run.track !== track) return false
    if (outcome !== 'ALL' && run.outcomeClass !== outcome) return false
    return true
  }), [pathRuns, track, outcome])
  const selected = filtered.find((run) => run.pathRunId === selectedId) ?? filtered[0]

  return <article className="panel section-gap">
    <div className="panel-head">
      <div>
        <p className="eyebrow">{english ? 'PATH RUNS' : '路径会话'}</p>
        <h2>{english ? 'PathRun sessions' : 'PathRun 会话（入口 × 身份轨）'}</h2>
      </div>
      <span>{filtered.length}/{pathRuns.length}</span>
    </div>
    <p className="form-help">
      {english
        ? 'Primary result view. AUTH_GAP findings are secondary static signals.'
        : '结果主视图。AUTH_GAP 等发现仅为次级静态信号。'}
    </p>
    <div className="finding-toolbar">
      <label className="field">
        <span>{english ? 'Track' : '身份轨'}</span>
        <select value={track} onChange={(event) => setTrack(event.target.value)}>
          <option value="ALL">{english ? 'All tracks' : '全部轨'}</option>
          {tracks.map((value) => <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <label className="field">
        <span>{english ? 'Outcome' : '超时/结果码'}</span>
        <select value={outcome} onChange={(event) => setOutcome(event.target.value)}>
          <option value="ALL">{english ? 'All outcomes' : '全部结果'}</option>
          {outcomes.map((value) => <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
    </div>
    <div className="result-grid">
      <div className="card-list">
        {filtered.map((run) => <button
          type="button"
          key={run.pathRunId}
          className={`finding-card finding-card-button ${run.pathRunId === selected?.pathRunId ? 'selected' : ''}`}
          onClick={() => setSelectedId(run.pathRunId)}
        >
          <div className="severity severity-medium">{run.track}</div>
          <div>
            <strong>{run.method} {run.entrypointRef}</strong>
            <small>{outcomeClassLabel(run.outcomeClass)} · HTTP {run.httpStatus < 0 ? '—' : run.httpStatus}</small>
            <small>{run.sqlEvents.length} SQL · {run.identityProvenance ?? 'MOCK'}</small>
          </div>
          <StatusPill status={run.verificationStatus} />
        </button>)}
        {filtered.length === 0 && <p className="empty-state">
          {english ? 'No PathRun sessions yet for this scan.' : '当前扫描尚无 PathRun 会话。'}
        </p>}
      </div>
      <div className="evidence-detail">
        {selected ? <>
          <h3>{selected.requestSummary || selected.entrypointRef}</h3>
          <dl>
            <div><dt>{english ? 'Track' : '身份轨'}</dt><dd>{selected.track}</dd></div>
            <div><dt>{english ? 'Outcome' : '结果码'}</dt><dd>{selected.outcomeClass} · {outcomeClassLabel(selected.outcomeClass)}</dd></div>
            <div><dt>{english ? 'Identity' : '身份前置'}</dt><dd>{selected.identityPrecondition || selected.identityProvenance || 'MOCK'}</dd></div>
            <div><dt>SQL</dt><dd>{selected.sqlEvents.length === 0 ? (english ? 'none' : '无') : selected.sqlEvents.map((sql) => sql.sqlText).join(' | ')}</dd></div>
            <div><dt>{english ? 'Stop reason' : '停止原因'}</dt><dd>{selected.stopReason}</dd></div>
          </dl>
          <StatusPill status={selected.verificationStatus} />
        </> : <p className="empty-state">{english ? 'Select a PathRun to inspect.' : '选择 PathRun 查看详情。'}</p>}
      </div>
    </div>
  </article>
}

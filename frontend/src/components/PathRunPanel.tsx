import { useMemo, useState } from 'react'
import type { EntryDto, FocusEntryProbeDto, PathRunDto } from '../api'
import { outcomeClassLabel } from '../labels'
import { Notice, StatusPill } from './Common'

function resolveEntryId(run: PathRunDto, entries: EntryDto[]): string | undefined {
  const ref = run.entrypointRef
  if (ref.startsWith('entry:')) {
    const rest = ref.slice('entry:'.length)
    const byId = entries.find((entry) => entry.id === rest)
    if (byId) return byId.id
    const methodRoute = rest.match(/^([A-Z]+):(\/.+)$/)
    if (methodRoute) {
      const matched = entries.find((entry) =>
        entry.method.toUpperCase() === methodRoute[1]
        && entry.route === methodRoute[2])
      if (matched) return matched.id
    }
  }
  const byExactId = entries.find((entry) => entry.id === ref)
  if (byExactId) return byExactId.id
  return entries.find((entry) =>
    entry.method.toUpperCase() === run.method.toUpperCase()
    && (ref.includes(entry.route) || `${entry.method} ${entry.route}` === ref))?.id
}

function entryLabel(run: PathRunDto, entries: EntryDto[]): string {
  const entryId = resolveEntryId(run, entries)
  const entry = entryId ? entries.find((item) => item.id === entryId) : undefined
  if (entry) return `${entry.method} ${entry.route}`
  return `${run.method} ${run.entrypointRef}`
}

function triState(value: boolean | null | undefined, english: boolean): string {
  if (value === true) return english ? 'yes' : '是'
  if (value === false) return english ? 'no' : '否'
  return 'unknown'
}

export function PathRunPanel({
  pathRuns,
  entries = [],
  scanId,
  english,
  onFocusEntry,
  onSelectRun
}: {
  pathRuns: PathRunDto[]
  entries?: EntryDto[]
  scanId?: string
  english: boolean
  onFocusEntry?: (entryId: string) => Promise<FocusEntryProbeDto | void>
  onSelectRun?: (run: PathRunDto) => void
}) {
  const [track, setTrack] = useState<'ALL' | string>('ALL')
  const [outcome, setOutcome] = useState<'ALL' | string>('ALL')
  const [entryFilter, setEntryFilter] = useState<'ALL' | string>('ALL')
  const [selectedId, setSelectedId] = useState<string>()
  const [focusLoading, setFocusLoading] = useState(false)
  const [focusError, setFocusError] = useState<string>()
  const [focusResult, setFocusResult] = useState<FocusEntryProbeDto>()

  const entryOptions = useMemo(() => {
    const labels = new Map<string, string>()
    for (const entry of entries) {
      labels.set(entry.id, `${entry.method} ${entry.route}`)
    }
    for (const run of pathRuns) {
      const id = resolveEntryId(run, entries) ?? run.entrypointRef
      if (!labels.has(id)) labels.set(id, entryLabel(run, entries))
    }
    return Array.from(labels.entries()).sort((left, right) => left[1].localeCompare(right[1]))
  }, [entries, pathRuns])

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
    if (entryFilter !== 'ALL') {
      const id = resolveEntryId(run, entries) ?? run.entrypointRef
      if (id !== entryFilter) return false
    }
    return true
  }), [pathRuns, track, outcome, entryFilter, entries])

  const grouped = useMemo(() => {
    const groups = new Map<string, PathRunDto[]>()
    for (const run of filtered) {
      const key = `${resolveEntryId(run, entries) ?? run.entrypointRef}\u0000${run.track}`
      const bucket = groups.get(key) ?? []
      bucket.push(run)
      groups.set(key, bucket)
    }
    return Array.from(groups.entries()).map(([key, runs]) => {
      const [entryKey, trackKey] = key.split('\u0000')
      return { entryKey, trackKey, runs }
    })
  }, [filtered, entries])

  const selected = filtered.find((run) => run.pathRunId === selectedId) ?? filtered[0]
  const selectedEntryId = selected ? resolveEntryId(selected, entries) : undefined

  const runFocus = async () => {
    if (!selectedEntryId || !onFocusEntry || focusLoading) return
    setFocusLoading(true)
    setFocusError(undefined)
    setFocusResult(undefined)
    try {
      const result = await onFocusEntry(selectedEntryId)
      if (result) setFocusResult(result)
    } catch (cause) {
      setFocusError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setFocusLoading(false)
    }
  }

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
        ? 'Primary result view grouped by entry × track. AUTH_GAP findings are secondary static signals.'
        : '结果主视图按入口 × 轨分组。AUTH_GAP 等发现仅为次级静态信号。'}
    </p>
    <div className="finding-toolbar">
      <label className="field">
        <span>{english ? 'Entry' : '入口'}</span>
        <select value={entryFilter} onChange={(event) => setEntryFilter(event.target.value)}>
          <option value="ALL">{english ? 'All entries' : '全部入口'}</option>
          {entryOptions.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
        </select>
      </label>
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
        {grouped.map((group) => <div key={`${group.entryKey}-${group.trackKey}`} className="pathrun-group">
          <p className="form-help">
            <strong>{group.runs[0] ? entryLabel(group.runs[0], entries) : group.entryKey}</strong>
            {' · '}{group.trackKey}
          </p>
          {group.runs.map((run) => <button
            type="button"
            key={run.pathRunId}
            className={`finding-card finding-card-button ${run.pathRunId === selected?.pathRunId ? 'selected' : ''}`}
            onClick={() => {
              setSelectedId(run.pathRunId)
              onSelectRun?.(run)
            }}
          >
            <div className="severity severity-medium">{run.track}</div>
            <div>
              <strong>{run.method} {run.entrypointRef}</strong>
              <small>{outcomeClassLabel(run.outcomeClass)} · HTTP {run.httpStatus < 0 ? '—' : run.httpStatus}</small>
              <small>{run.sqlEvents.length} SQL · {run.identityProvenance ?? 'MOCK'}</small>
            </div>
            <StatusPill status={run.verificationStatus} />
          </button>)}
        </div>)}
        {filtered.length === 0 && <p className="empty-state">
          {english ? 'No PathRun sessions yet for this scan.' : '当前扫描尚无 PathRun 会话。'}
        </p>}
      </div>
      <div className="evidence-detail">
        {selected ? <>
          <h3>{selected.requestSummary || selected.entrypointRef}</h3>
          <p className="eyebrow">{english ? 'EXPERIMENT SHAPE' : '一次实验形态'}</p>
          <dl>
            <div><dt>{english ? 'HTTP line' : 'HTTP 线'}</dt><dd>{selected.requestSummary || `${selected.method} ${selected.entrypointRef}`}</dd></div>
            <div><dt>{english ? 'Entry' : '入口'}</dt><dd>{entryLabel(selected, entries)}</dd></div>
            <div><dt>{english ? 'Track' : '身份轨'}</dt><dd>{selected.track}</dd></div>
            <div><dt>{english ? 'Outcome' : '结果码'}</dt><dd>{selected.outcomeClass} · {outcomeClassLabel(selected.outcomeClass)} · HTTP {selected.httpStatus < 0 ? '—' : selected.httpStatus}</dd></div>
            <div><dt>entryHit</dt><dd>{triState(selected.entryHit, english)}</dd></div>
            <div><dt>parameterBound</dt><dd>{triState(selected.parameterBound, english)}</dd></div>
            <div><dt>{english ? 'Identity' : '身份前置'}</dt><dd>{selected.identityPrecondition || selected.identityProvenance || 'MOCK'}</dd></div>
            <div><dt>SQL</dt><dd>{selected.sqlEvents.length === 0 ? (english ? 'none (not a success claim)' : '无（不等于注入成功）') : selected.sqlEvents.map((sql) => sql.sqlText).join(' | ')}</dd></div>
            <div><dt>{english ? 'Stop reason' : '停止原因'}</dt><dd>{selected.stopReason || '—'}</dd></div>
            {(selected.legacyIncomplete || selected.postureKind || selected.exitReason) && <>
              <div><dt>{english ? 'Path debug' : '路径调试'}</dt>
                <dd>{selected.legacyIncomplete
                  ? (english ? 'Legacy incomplete (no PathTrace)' : '旧版动态不完整（无 PathTrace）')
                  : `${selected.postureKind ?? '—'} · ${selected.exitReason ?? '—'}`}</dd></div>
              {selected.lastBusinessHop && <div><dt>{english ? 'Last hop' : '最后业务 hop'}</dt><dd>{selected.lastBusinessHop}</dd></div>}
              {selected.authRequirement && <div><dt>{english ? 'Auth req.' : '鉴权要求'}</dt><dd>{selected.authRequirement}</dd></div>}
              {selected.effectRefs && selected.effectRefs.length > 0 && <div><dt>{english ? 'Effects' : 'Effect'}</dt><dd>{selected.effectRefs.join(', ')}</dd></div>}
            </>}
            <div><dt>{english ? 'Dependency' : '依赖模式'}</dt><dd><span className="inference-badge">MOCK</span></dd></div>
            <div>
              <dt>branchHitMap</dt>
              <dd>
                {selected.branchHitMap && Object.keys(selected.branchHitMap).length > 0
                  ? <div className="branch-hit-map">
                    {Object.entries(selected.branchHitMap).map(([method, hits]) => (
                      <div className="branch-hit-row" key={method}>
                        <code>{method}</code>
                        <span>{hits.length === 0 ? '—' : hits.join(', ')}</span>
                      </div>
                    ))}
                  </div>
                  : (english ? 'none (no BRANCH_COVERAGE yet)' : '无（尚无 BRANCH_COVERAGE）')}
              </dd>
            </div>
          </dl>
          <StatusPill status={selected.verificationStatus} />
          <div className="button-row section-gap">
            <button
              type="button"
              className="secondary-button"
              onClick={() => void runFocus()}
              disabled={!selectedEntryId || !onFocusEntry || !scanId || focusLoading}
            >
              {focusLoading
                ? (english ? 'Requesting…' : '正在请求…')
                : (english ? 'Run this entry only' : '只跑此入口')}
            </button>
            <span className="form-help">
              {english
                ? 'Enqueues a focused DYNAMIC_SUSPECTED probe; server owns sandbox policy.'
                : '排队焦点探针，最高 DYNAMIC_SUSPECTED；沙箱策略由服务端固定。'}
            </span>
          </div>
          {focusError && <Notice kind="error">{focusError}</Notice>}
          {focusResult && <Notice kind="info">
            {english
              ? `Focus task ${focusResult.taskId} is ${focusResult.lifecycle}`
                + `${focusResult.attemptKind ? ` [${focusResult.attemptKind}]` : ''}`
                + `${focusResult.experimentPlanId ? ` plan=${focusResult.experimentPlanId}` : ''}`
                + `${focusResult.replayed ? ' (idempotent replay)' : ''}.`
              : `焦点任务 ${focusResult.taskId} 当前为 ${focusResult.lifecycle}`
                + `${focusResult.attemptKind ? ` [${focusResult.attemptKind}]` : ''}`
                + `${focusResult.experimentPlanId ? ` 计划=${focusResult.experimentPlanId}` : ''}`
                + `${focusResult.replayed ? '（幂等重放）' : ''}。`}
          </Notice>}
        </> : <p className="empty-state">{english ? 'Select a PathRun to inspect.' : '选择 PathRun 查看详情。'}</p>}
      </div>
    </div>
  </article>
}

import type {
  CoverageMatrixDto,
  EvidenceGraphDto,
  EvidenceGraphNodeDto,
  OutputLanguage,
  SecurityHypothesisDto
} from '../api'
import { HYPOTHESIS_FAMILIES, normalizeHypothesisFamily } from '../api'
import { Notice } from './Common'

/** Renders namespaced extensions without language-specific branching. */
export function UnknownExtensionView({
  extensions,
  language,
  english
}: {
  extensions?: Record<string, unknown>
  language?: string
  english: boolean
}) {
  const entries = Object.entries(extensions ?? {})
  if (entries.length === 0) {
    return <small>{english ? 'No namespaced extensions.' : '无 namespaced extension。'}</small>
  }
  const knownLanguage = language && language !== 'UNKNOWN' && language !== 'JVM'
  return (
    <div className="unknown-extension-block">
      <small>
        {english
          ? `Extensions (${entries.length})${knownLanguage ? ` · language=${language}` : language ? ` · unknown/other language=${language}` : ''}`
          : `扩展（${entries.length}）${knownLanguage ? ` · language=${language}` : language ? ` · 未知/其他语言=${language}` : ''}`}
      </small>
      <ul>
        {entries.map(([namespace, payload]) => (
          <li key={namespace}>
            <strong>{namespace}</strong>
            <code>{safeJson(payload)}</code>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function EvidenceGraphNodeCard({
  node,
  english
}: {
  node: EvidenceGraphNodeDto
  english: boolean
}) {
  const kindDegraded = node.kind === 'UNKNOWN' || (node.kindRaw != null && node.kindRaw !== node.kind)
  const languageLabel = node.language && node.language !== 'JVM' && node.language !== 'UNKNOWN'
    ? node.language
    : (node.language ?? (english ? 'unspecified' : '未指定'))
  return (
    <div className="list-card">
      <div>
        <strong>{node.symbol || node.id}</strong>
        <small>
          {node.kind}
          {kindDegraded && node.kindRaw ? ` · raw=${node.kindRaw}` : ''}
          {' · '}
          {languageLabel}
          {node.location ? ` · ${node.location}` : ''}
          {' · '}
          {node.provenanceKind}
        </small>
        <small>{node.id}</small>
        {(node.extensions || node.extras) && (
          <UnknownExtensionView
            extensions={{ ...(node.extensions ?? {}), ...(node.extras ?? {}) }}
            language={node.language}
            english={english}
          />
        )}
      </div>
      <span>{node.evidenceRefs.length}</span>
    </div>
  )
}

export function CoverageMatrixPanel({
  coverage,
  loading,
  error,
  english
}: {
  coverage?: CoverageMatrixDto
  loading: boolean
  error?: string
  english: boolean
}) {
  return (
    <article className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">COVERAGE</p>
          <h2>{english ? 'Coverage Matrix' : '覆盖矩阵'}</h2>
        </div>
        <span>{coverage?.scanId ?? '—'}</span>
      </div>
      {error && <Notice kind="error">{error}</Notice>}
      {loading && <p className="empty-state">{english ? 'Loading coverage…' : '正在加载覆盖矩阵…'}</p>}
      {!loading && coverage && (
        <>
          <p className="form-help">
            {english
              ? 'SUCCESS / COMPLETED never means safe. Gaps are not counted as covered.'
              : '扫描 SUCCESS/COMPLETED 不等于安全；缺口不计为已覆盖。'}
          </p>
          <dl className="coverage-gap-dl">
            <div><dt>unknown</dt><dd>{coverage.gaps?.unknown ?? 0}</dd></div>
            <div><dt>unresolved</dt><dd>{coverage.gaps?.unresolved ?? 0}</dd></div>
            <div><dt>truncated</dt><dd>{coverage.gaps?.truncated ?? 0}</dd></div>
            <div><dt>unreached</dt><dd>{coverage.gaps?.unreached ?? 0}</dd></div>
          </dl>
          <p className="form-help">
            {english
              ? `Universe: ${coverage.artifactUniverseSummary.classCount} classes / ${coverage.artifactUniverseSummary.methodCount} methods / ${coverage.artifactUniverseSummary.fieldCount} fields / ${coverage.artifactUniverseSummary.dependencyCount} dependencies${coverage.artifactUniverseSummary.incomplete ? `; incomplete (${coverage.artifactUniverseSummary.note})` : ''}.`
              : `Universe incomplete=${coverage.artifactUniverseSummary.incomplete}; note=${coverage.artifactUniverseSummary.note}.`}
          </p>
          <dl className="coverage-gap-dl">
            <div><dt>direct calls</dt><dd>{coverage.callResolution.DIRECT}</dd></div>
            <div><dt>CHA calls</dt><dd>{coverage.callResolution.CHA}</dd></div>
            <div><dt>unresolved calls</dt><dd>{coverage.callResolution.UNRESOLVED}</dd></div>
            <div><dt>effective attempts</dt><dd>{coverage.dynamicExperiments.effectiveAttemptCount}</dd></div>
            <div><dt>unreached attempts</dt><dd>{coverage.dynamicExperiments.unreachedCount}</dd></div>
          </dl>
          {coverage.stopReasons.length > 0 && (
            <div className="card-list section-gap">
              {coverage.stopReasons.map((reason) => (
                <div className="list-card" key={reason.name}>
                  <div><strong>{reason.name}</strong><small>stop reason</small></div>
                  <span>{reason.count}</span>
                </div>
              ))}
            </div>
          )}
          {coverage.entryFamilies && coverage.entryFamilies.length > 0 && (            <div className="card-list section-gap">
              {coverage.entryFamilies.map((row) => (
                <div className="list-card" key={row.name}>
                  <div><strong>{row.name}</strong><small>{english ? 'entry family' : '入口族'}</small></div>
                  <span>{row.count}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
      {!loading && !coverage && !error && (
        <p className="empty-state">{english ? 'No coverage matrix for this scan.' : '当前扫描无覆盖矩阵。'}</p>
      )}
    </article>
  )
}

export function HypothesisFamilyPanel({
  hypotheses,
  english
}: {
  hypotheses: SecurityHypothesisDto[]
  english: boolean
}) {
  const byFamily = new Map<string, SecurityHypothesisDto[]>()
  for (const family of HYPOTHESIS_FAMILIES) byFamily.set(family, [])
  for (const item of hypotheses) {
    const family = normalizeHypothesisFamily(item.family)
    const list = byFamily.get(family) ?? []
    list.push(item)
    byFamily.set(family, list)
  }
  return (
    <article className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">HYPOTHESIS</p>
          <h2>{english ? 'Security hypotheses by family' : '按族安全假设'}</h2>
        </div>
        <span>{hypotheses.length}</span>
      </div>
      <p className="form-help">
        {english
          ? 'Unknown wire family values degrade to UNKNOWN; empty families are not a safety claim.'
          : '未知 wire family 降级为 UNKNOWN；空族不等于安全。'}
      </p>
      <div className="card-list">
        {HYPOTHESIS_FAMILIES.map((family) => {
          const items = byFamily.get(family) ?? []
          return (
            <div className="list-card" key={family}>
              <div>
                <strong>{family}</strong>
                {items.length === 0
                  ? <small>{english ? 'Empty family' : '该族为空'}</small>
                  : items.map((item) => (
                    <small key={item.hypothesisId}>
                      {item.hypothesisId} · {item.securityProperty} · {item.lifecycle}
                      {item.familyRaw && normalizeHypothesisFamily(item.familyRaw) === 'UNKNOWN' && item.familyRaw !== 'UNKNOWN'
                        ? ` · raw=${item.familyRaw}`
                        : ''}
                    </small>
                  ))}
              </div>
              <span>{items.length}</span>
            </div>
          )
        })}
      </div>
    </article>
  )
}

export function EvidenceGraphPanel({
  graph,
  loading,
  error,
  english,
  language,
  onSelectNode
}: {
  graph?: EvidenceGraphDto
  loading: boolean
  error?: string
  english: boolean
  language: OutputLanguage
  onSelectNode?: (node: EvidenceGraphNodeDto) => void
}) {
  void language
  const nodes = graph?.nodes ?? []
  return (
    <article className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">EVIDENCE GRAPH</p>
          <h2>{english ? 'Evidence Graph (local)' : '证据图（局部）'}</h2>
        </div>
        <span>{nodes.length}</span>
      </div>
      {error && <Notice kind="error">{error}</Notice>}
      {loading && <p className="empty-state">{english ? 'Loading evidence graph…' : '正在加载证据图…'}</p>}
      {!loading && graph && (
        <>
          <p className="form-help">
            {english
              ? `schema v${graph.schemaVersion} · edges ${graph.edges.length}${graph.truncated ? ' · truncated' : ''}. Unknown language/kind/extension nodes stay readable via general fields.`
              : `schema v${graph.schemaVersion} · 边 ${graph.edges.length}${graph.truncated ? ' · 已截断' : ''}。未知语言/kind/extension 节点仍按通用字段可读。`}
          </p>
          <p className="form-help">
            {`Compatibility gap: ${graph.compatibilityGap.entryDtoCount - graph.compatibilityGap.entryNodeCount} entries filtered${graph.compatibilityGap.notes.length > 0 ? ` (${graph.compatibilityGap.notes.join('; ')})` : ''}.${graph.stopReason ? ` Stop: ${graph.stopReason}.` : ''}`}
          </p>
          <div className="card-list">
            {nodes.slice(0, 80).map((node) => (
              onSelectNode ? (
                <button
                  type="button"
                  className="results-row"
                  key={node.id}
                  onClick={() => onSelectNode(node)}
                >
                  <EvidenceGraphNodeCard node={node} english={english} />
                </button>
              ) : (
                <EvidenceGraphNodeCard key={node.id} node={node} english={english} />
              )
            ))}
            {nodes.length === 0 && (
              <p className="empty-state">
                {english ? 'No IR nodes in this projection.' : '当前投影无 IR 节点。'}
              </p>
            )}
            {nodes.length > 80 && (
              <p className="form-help">
                {english ? `Showing 80 of ${nodes.length} nodes.` : `仅显示 ${nodes.length} 个节点中的前 80 个。`}
              </p>
            )}
          </div>
        </>
      )}
    </article>
  )
}

function safeJson(value: unknown): string {
  try {
    const text = JSON.stringify(value)
    return text.length > 240 ? `${text.slice(0, 240)}…` : text
  } catch {
    return String(value)
  }
}

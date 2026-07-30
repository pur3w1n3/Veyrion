import { useMemo } from 'react'
import {
  HYPOTHESIS_FAMILIES,
  normalizeHypothesisFamily,
  type HypothesisFamily,
  type SecurityHypothesisDto
} from '../../api'
import { hypothesisFamilyBlurb, hypothesisFamilyLabel } from '../../labels'

export function HypothesesView({
  hypotheses,
  english,
  selectedHypothesisId,
  selectedFamily,
  onSelectHypothesis,
  onSelectFamily
}: {
  hypotheses: SecurityHypothesisDto[]
  english: boolean
  selectedHypothesisId?: string
  selectedFamily?: HypothesisFamily
  onSelectHypothesis?: (hypothesis: SecurityHypothesisDto) => void
  onSelectFamily?: (family: HypothesisFamily, items: SecurityHypothesisDto[]) => void
}) {
  const byFamily = useMemo(() => {
    const buckets = new Map<HypothesisFamily, SecurityHypothesisDto[]>()
    for (const family of HYPOTHESIS_FAMILIES) buckets.set(family, [])
    for (const item of hypotheses) {
      buckets.get(normalizeHypothesisFamily(item.family))?.push(item)
    }
    return buckets
  }, [hypotheses])

  return (
    <div className="results-view results-view--hypotheses">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'HYPOTHESIS' : '安全假设'}</p>
          <h2>{english ? 'Hypotheses by family' : '按族假设'}</h2>
        </div>
        <span>{hypotheses.length}</span>
      </div>

      <table className="results-data-table hyp-family-table">
        <thead>
          <tr>
            <th>{english ? 'No.' : '编号'}</th>
            <th>{english ? 'Family' : '类型（族）'}</th>
            <th>{english ? 'Count' : '数量'}</th>
            <th>{english ? 'Summary' : '说明'}</th>
          </tr>
        </thead>
        <tbody>
          {HYPOTHESIS_FAMILIES.map((family, index) => {
            const items = byFamily.get(family) ?? []
            const selected = selectedFamily === family && !selectedHypothesisId
            return (
              <tr
                key={family}
                className={selected ? 'selected' : undefined}
                onClick={() => onSelectFamily?.(family, items)}
              >
                <td className="hyp-family-table__num">{index + 1}</td>
                <td>
                  <strong>{hypothesisFamilyLabel(family, english)}</strong>
                  <span className="term-chip">{family}</span>
                </td>
                <td className="hyp-family-table__count">{items.length}</td>
                <td className="veyrion-long-text">
                  {items.length === 0
                    ? (english ? 'Empty' : '空')
                    : hypothesisFamilyBlurb(family, english)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {hypotheses.length > 0 && (
        <div className="section-gap">
          <p className="eyebrow">{english ? 'HYPOTHESES' : '假设条目'}</p>
          <div className="results-table-list">
            <div className="results-compact-head" aria-hidden="true">
              <span>{english ? 'No.' : '编号'}</span>
              <span>{english ? 'Family' : '类型'}</span>
              <span>{english ? 'Evidence' : '证据'}</span>
              <span>{english ? 'Property' : '说明'}</span>
            </div>
            {hypotheses.map((item, index) => (
              <button
                type="button"
                className={`results-row results-row--hyp ${item.hypothesisId === selectedHypothesisId ? 'selected' : ''}`}
                key={item.hypothesisId}
                onClick={() => onSelectHypothesis?.(item)}
              >
                <span className="results-row__num">H{index + 1}</span>
                <span className="results-row__kind">
                  {hypothesisFamilyLabel(item.family, english)}
                  <span className="term-chip">{item.family}</span>
                </span>
                <span className="results-row__score">{item.supportingEvidenceRefs.length}</span>
                <span className="results-row__blurb veyrion-long-text">{item.securityProperty}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {hypotheses.length === 0 && (
        <p className="empty-state section-gap">
          {english ? 'No hypotheses in this scan.' : '当前扫描无假设。'}
        </p>
      )}
    </div>
  )
}

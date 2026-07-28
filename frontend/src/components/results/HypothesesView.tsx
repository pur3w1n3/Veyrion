import type { SecurityHypothesisDto } from '../../api'
import { HypothesisFamilyPanel } from '../CapabilityEvidencePanels'

export function HypothesesView({
  hypotheses,
  english,
  onSelectHypothesis
}: {
  hypotheses: SecurityHypothesisDto[]
  english: boolean
  onSelectHypothesis?: (hypothesis: SecurityHypothesisDto) => void
}) {
  return (
    <div className="results-view results-view--hypotheses">
      <HypothesisFamilyPanel hypotheses={hypotheses} english={english} />
      {onSelectHypothesis && hypotheses.length > 0 && (
        <div className="results-table-list section-gap">
          {hypotheses.slice(0, 20).map((item) => (
            <button type="button" className="results-row" key={item.hypothesisId} onClick={() => onSelectHypothesis(item)}>
              <strong>{item.hypothesisId}</strong>
              <small>{item.family} · {item.securityProperty}</small>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

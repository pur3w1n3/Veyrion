import type { CoverageMatrixDto, EvidenceGraphDto, OutputLanguage } from '../../api'
import { CoverageMatrixPanel, EvidenceGraphPanel } from '../CapabilityEvidencePanels'

export function EvidenceGraphView({
  graph,
  loading,
  error,
  english,
  language
}: {
  graph?: EvidenceGraphDto
  loading: boolean
  error?: string
  english: boolean
  language: OutputLanguage
}) {
  return (
    <div className="results-view results-view--graph">
      <EvidenceGraphPanel graph={graph} loading={loading} error={error} english={english} language={language} />
    </div>
  )
}

export function CoverageGapsView({
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
    <div className="results-view results-view--coverage">
      <CoverageMatrixPanel coverage={coverage} loading={loading} error={error} english={english} />
    </div>
  )
}

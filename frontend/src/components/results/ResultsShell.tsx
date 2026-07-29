import type { ReactNode } from 'react'
import type { DashboardSnapshot, SecurityHypothesisDto } from '../../api'
import type { ResultsViewId } from '../../guiSemantics'
import { EvidenceInspector } from './EvidenceInspector'
import { EvidenceSummaryStrip } from './EvidenceSummaryStrip'
import { ResultsSubnav, type ViewMeta } from './ResultsSubnav'
import { ScanContextBand } from './ScanContextBand'
import type { EvidenceSelection, SummaryCounts } from './resultsUtils'

export function ResultsShell({
  snapshot,
  english,
  reportJobStatus,
  reportErrorCode,
  summaryCounts,
  activeView,
  onViewChange,
  viewMeta,
  selection,
  hypothesisById,
  children
}: {
  snapshot: DashboardSnapshot | null
  english: boolean
  reportJobStatus?: string
  reportErrorCode?: string
  summaryCounts: SummaryCounts
  activeView: ResultsViewId
  onViewChange: (view: ResultsViewId) => void
  viewMeta: (view: ResultsViewId) => ViewMeta
  selection: EvidenceSelection
  hypothesisById: Map<string, SecurityHypothesisDto>
  children: ReactNode
}) {
  return (
    <section className="results-shell">
      <ScanContextBand
        snapshot={snapshot}
        english={english}
        reportJobStatus={reportJobStatus}
        reportErrorCode={reportErrorCode}
      />
      <EvidenceSummaryStrip counts={summaryCounts} english={english} />
      <ResultsSubnav
        activeView={activeView}
        onViewChange={onViewChange}
        viewMeta={viewMeta}
        english={english}
      />
      <div className={`results-shell__body${activeView === 'report' ? ' results-shell__body--report' : ''}`}>
        <main className="results-shell__main">{children}</main>
        {activeView !== 'report' && (
          <EvidenceInspector
            selection={selection}
            english={english}
            hypothesisById={hypothesisById}
          />
        )}
      </div>
    </section>
  )
}

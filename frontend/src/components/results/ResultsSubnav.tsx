import { RESULTS_VIEW_IDS, RESULTS_VIEW_META, type ResultsViewId } from '../../guiSemantics'

export type ViewMeta = {
  label: string
  count: number
  blurb: string
}

export function ResultsSubnav({
  activeView,
  onViewChange,
  viewMeta,
  english
}: {
  activeView: ResultsViewId
  onViewChange: (view: ResultsViewId) => void
  viewMeta: (view: ResultsViewId) => ViewMeta
  english: boolean
}) {
  const primaryViews = RESULTS_VIEW_IDS.filter((view) =>
    view !== 'hypotheses' && view !== 'contrast' && view !== 'verified')

  return (
    <nav className="results-subnav results-subnav--workbench" aria-label={english ? 'Results sub-views' : '审计结果子页面'}>
      {primaryViews.map((view) => {
        const meta = viewMeta(view)
        return (
          <button
            key={view}
            type="button"
            className={activeView === view ? 'active' : ''}
            aria-current={activeView === view ? 'page' : undefined}
            title={meta.blurb}
            onClick={() => onViewChange(view)}
          >
            <strong>{meta.label}</strong>
            <small>{meta.count}</small>
          </button>
        )
      })}
      <div className="results-subnav__secondary">
        {(['hypotheses', 'contrast', 'verified'] as const).map((view) => {
          const meta = viewMeta(view)
          const contractMeta = RESULTS_VIEW_META[view]
          return (
            <button
              key={view}
              type="button"
              className={activeView === view ? 'active' : ''}
              aria-current={activeView === view ? 'page' : undefined}
              title={english ? contractMeta.blurbEn : contractMeta.blurbZh}
              onClick={() => onViewChange(view)}
            >
              <strong>{meta.label}</strong>
              <small>{meta.count}</small>
            </button>
          )
        })}
      </div>
    </nav>
  )
}

import {
  RESULTS_VIEW_IDS,
  RESULTS_VIEW_META,
  RESULTS_VIEWS_HIDDEN_FROM_NAV,
  type ResultsViewId
} from '../../guiSemantics'

export type ViewMeta = {
  label: string
  count: number
  blurb: string
}

const HIDDEN = new Set<string>(RESULTS_VIEWS_HIDDEN_FROM_NAV)
const SECONDARY = new Set<string>(['hypotheses', 'contrast', 'verified', 'aiMemory'])

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
    view !== 'downloads'
    && !SECONDARY.has(view)
    && !HIDDEN.has(view))

  const secondaryViews = (['hypotheses', 'contrast', 'verified', 'aiMemory'] as const)
  const renderTab = (view: ResultsViewId, titleOverride?: string) => {
    const meta = viewMeta(view)
    return (
      <button
        key={view}
        type="button"
        className={activeView === view ? 'active' : ''}
        aria-current={activeView === view ? 'page' : undefined}
        title={titleOverride ?? meta.blurb}
        onClick={() => onViewChange(view)}
      >
        <strong>{meta.label}</strong>
        <small>{meta.count}</small>
      </button>
    )
  }

  return (
    <nav className="results-subnav results-subnav--workbench" aria-label={english ? 'Results sub-views' : '审计结果子页面'}>
      {primaryViews.map((view) => renderTab(view))}
      <div className="results-subnav__secondary">
        {secondaryViews.map((view) => {
          const contractMeta = RESULTS_VIEW_META[view]
          return renderTab(view, english ? contractMeta.blurbEn : contractMeta.blurbZh)
        })}
      </div>
      <div className="results-subnav__trailing">
        {renderTab('downloads')}
      </div>
    </nav>
  )
}

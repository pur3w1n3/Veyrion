import type { Entry, FocusEntryProbeDto, PathRunDto } from '../../api'
import { PathRunPanel } from '../PathRunPanel'
import { isDiagnosticPathRun } from './resultsUtils'

export function PathRunsView({
  pathRuns,
  entries,
  scanId,
  english,
  onFocusEntry,
  onSelectPathRun
}: {
  pathRuns: PathRunDto[]
  entries: Entry[]
  scanId?: string
  english: boolean
  onFocusEntry: (entryId: string) => Promise<FocusEntryProbeDto>
  onSelectPathRun?: (pathRun: PathRunDto) => void
}) {
  const sessionRuns = pathRuns.filter((run) => !isDiagnosticPathRun(run))
  const diagnosticCount = pathRuns.length - sessionRuns.length

  return (
    <div className="results-view results-view--path-runs">
      <p className="form-help">
        {english
          ? `Showing ${sessionRuns.length} session PathRuns. ${diagnosticCount} diagnostic runs (HTTP -1 / UNKNOWN / UNREACHED) are in Dynamic Diagnostics.`
          : `显示 ${sessionRuns.length} 条会话 PathRun。${diagnosticCount} 条诊断项（HTTP -1 / UNKNOWN / UNREACHED）见动态诊断子页。`}
      </p>
      <PathRunPanel
        pathRuns={sessionRuns}
        entries={entries}
        scanId={scanId}
        english={english}
        onFocusEntry={onFocusEntry}
        onSelectRun={onSelectPathRun}
      />
    </div>
  )
}

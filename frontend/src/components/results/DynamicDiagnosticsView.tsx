import type { PathRunDto, ProbeBudgetDto } from '../../api'
import { outcomeClassLabel } from '../../labels'
import { StatusPill } from '../Common'
import { isDiagnosticPathRun } from './resultsUtils'

export function DynamicDiagnosticsView({
  english,
  pathRuns,
  probeBudget
}: {
  english: boolean
  pathRuns: PathRunDto[]
  probeBudget?: ProbeBudgetDto
}) {
  const diagnosticRuns = pathRuns.filter(isDiagnosticPathRun)

  return (
    <div className="results-view results-view--diagnostics">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'DYNAMIC DIAGNOSTICS' : '动态诊断'}</p>
          <h2>{english ? 'Probe and sandbox failures' : '探针与沙箱失败'}</h2>
        </div>
        <span>{diagnosticRuns.length}</span>
      </div>

      <p className="form-help">
        {english
          ? 'Startup failures, UNREACHED, UNKNOWN/-1 and MOCK dependency notes. These are not vulnerability findings.'
          : '启动失败、UNREACHED、UNKNOWN/-1 与 MOCK 依赖说明。这些不是漏洞发现。'}
      </p>

      {probeBudget && (
        <p className="form-help">
          {english
            ? `Probe budget: planned ${probeBudget.plannedProbes}/${probeBudget.maxProbes}, unreached entries ${probeBudget.unreachedEntries}. ${probeBudget.strategy}`
            : `探针预算：已规划 ${probeBudget.plannedProbes}/${probeBudget.maxProbes}，未达入口 ${probeBudget.unreachedEntries}。${probeBudget.strategy}`}
        </p>
      )}

      <div className="results-table-list">
        {diagnosticRuns.map((run) => (
          <div className="results-row status-tone-unreached" key={run.pathRunId}>
            <div className="results-row__body">
              <strong className="veyrion-long-text">{run.method} {run.entrypointRef}</strong>
              <small>
                {run.track} · HTTP {run.httpStatus < 0 ? '-1' : run.httpStatus} · {outcomeClassLabel(run.outcomeClass, english)}
              </small>
              <small className="veyrion-long-text">{run.stopReason || (english ? 'No stop reason' : '无停止原因')}</small>
              <small>{run.identityProvenance ?? 'MOCK'}</small>
            </div>
            <StatusPill status={run.verificationStatus} english={english} />
          </div>
        ))}
        {diagnosticRuns.length === 0 && (
          <p className="empty-state">{english ? 'No diagnostic PathRuns for this scan.' : '当前扫描无诊断 PathRun。'}</p>
        )}
      </div>
    </div>
  )
}

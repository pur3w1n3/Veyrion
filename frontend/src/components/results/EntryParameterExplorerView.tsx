import type { Entry, ExperimentPlanDto } from '../../api'
import { StatusPill } from '../Common'

export function EntryParameterExplorerView({
  english,
  entries,
  experimentPlans,
  selectedEntryId,
  onSelectEntry
}: {
  english: boolean
  entries: Entry[]
  experimentPlans: ExperimentPlanDto[]
  selectedEntryId?: string
  onSelectEntry: (entry: Entry) => void
}) {
  const readinessLabel = (entry: Entry): string => {
    if (entry.status === 'UNREACHED') {
      return english ? 'Unreachable / blocked' : '未覆盖 / 阻断'
    }
    const plan = experimentPlans.find((item) => item.entrypointRef.includes(entry.route) || item.entrypointRef.includes(entry.id))
    if (plan) return english ? 'Plan accepted' : '计划已接受'
    return english ? 'Static only' : '仅静态'
  }

  return (
    <div className="results-view results-view--entry-exploration">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'ENTRY EXPLORATION' : '入口参数探索'}</p>
          <h2>{english ? 'Entry × parameter matrix' : '入口 × 参数矩阵'}</h2>
        </div>
        <span>{entries.length}</span>
      </div>

      <p className="form-help">
        {english
          ? 'Zero-parameter and empty-body inputs are valid shapes; server compiles experiment plans.'
          : '0 参数与空 body/query 是合法输入形态；实验计划由服务端编译。'}
      </p>

      <table className="results-data-table">
        <thead>
          <tr>
            <th>{english ? 'Entry' : '入口'}</th>
            <th>{english ? 'Handler' : '处理器'}</th>
            <th>{english ? 'Params' : '参数'}</th>
            <th>{english ? 'Readiness' : '就绪'}</th>
            <th>{english ? 'Coverage' : '覆盖'}</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => {
            const paramCount = entry.parameters?.length ?? 0
            const paramSummary = paramCount === 0
              ? (english ? '0 params · empty-input valid' : '0 参数 · 空输入合法')
              : entry.parameters!.join(', ')
            return (
              <tr
                key={entry.id}
                className={entry.id === selectedEntryId ? 'selected' : ''}
                onClick={() => onSelectEntry(entry)}
              >
                <td className="veyrion-long-text"><strong>{entry.method} {entry.route}</strong><small>{entry.protocol} · {entry.module}</small></td>
                <td className="veyrion-long-text">{entry.declaringClass ?? entry.module}</td>
                <td className="veyrion-long-text">{paramSummary}</td>
                <td>{readinessLabel(entry)}</td>
                <td><StatusPill status={entry.status} english={english} /> {entry.coverage}%</td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {entries.length === 0 && (
        <p className="empty-state">{english ? 'No entries; does not imply empty attack surface.' : '暂无入口；不表示攻击面为空。'}</p>
      )}

      <div className="section-gap">
        <p className="eyebrow">{english ? 'PARAMETER MATRIX (placeholder)' : '参数矩阵（占位）'}</p>
        <p className="form-help">
          {english
            ? 'Matrix rows bind query/body/header/path from snapshot.entries and experimentPlans when the server provides them.'
            : '矩阵行在服务端提供 snapshot.entries 与 experimentPlans 时绑定 query/body/header/path。'}
        </p>
        {experimentPlans.length > 0 ? (
          <div className="results-table-list">
            {experimentPlans.slice(0, 12).map((plan) => (
              <div className="results-row" key={plan.planId}>
                <strong>{plan.planId}</strong>
                <small className="veyrion-long-text">{plan.method} {plan.entrypointRef} · {plan.track}</small>
                <span>{plan.fuzzStrategy ? 'fuzz' : '—'}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="empty-state">{english ? 'No accepted experiment plans yet.' : '尚无已接受实验计划。'}</p>
        )}
      </div>
    </div>
  )
}

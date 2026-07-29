import { outcomeClassLabel } from '../../labels'
import { StatusPill } from '../Common'
import { familyOfFinding, type EvidenceSelection } from './resultsUtils'

export function EvidenceInspector({
  selection,
  english,
  hypothesisById
}: {
  selection: EvidenceSelection
  english: boolean
  hypothesisById: Map<string, import('../../api').SecurityHypothesisDto>
}) {
  if (!selection) {
    return (
      <aside className="evidence-inspector evidence-inspector--empty" aria-label={english ? 'Evidence inspector' : '证据检查器'}>
        <p className="evidence-inspector__empty">
          {english ? 'Select an item to inspect evidence boundaries.' : '选择一项查看证据边界'}
        </p>
      </aside>
    )
  }

  return (
    <aside className="evidence-inspector" aria-label={english ? 'Evidence inspector' : '证据检查器'}>
      {selection.kind === 'finding' && (
        <>
          <p className="eyebrow">{english ? 'FINDING' : '发现'}</p>
          <h3 className="evidence-inspector__title veyrion-long-text">{selection.finding.title}</h3>
          <StatusPill status={selection.finding.status} />
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Family' : '假设族'}</dt><dd>{familyOfFinding(selection.finding, hypothesisById)}</dd></div>
            <div><dt>{english ? 'Entry' : '入口'}</dt><dd className="veyrion-long-text">{selection.finding.entry}</dd></div>
            <div><dt>{english ? 'Sink' : 'Sink'}</dt><dd className="veyrion-long-text">{selection.finding.sink}</dd></div>
            <div><dt>{english ? 'Evidence refs' : '证据引用'}</dt><dd>{selection.finding.evidenceRefs?.length ?? selection.finding.evidence}</dd></div>
          </dl>
          {selection.finding.rootCause?.rootCauseStatement && (
            <p className="form-help veyrion-long-text">{selection.finding.rootCause.rootCauseStatement}</p>
          )}
        </>
      )}
      {selection.kind === 'pathRun' && (
        <>
          <p className="eyebrow">{english ? 'PATH RUN' : 'PathRun'}</p>
          <h3 className="evidence-inspector__title veyrion-long-text">{selection.pathRun.requestSummary || selection.pathRun.entrypointRef}</h3>
          <StatusPill status={selection.pathRun.verificationStatus} />
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Track' : '身份轨'}</dt><dd>{selection.pathRun.track}</dd></div>
            <div><dt>{english ? 'Outcome' : '结果'}</dt><dd>{selection.pathRun.outcomeClass} · {outcomeClassLabel(selection.pathRun.outcomeClass)}</dd></div>
            <div><dt>HTTP</dt><dd>{selection.pathRun.httpStatus < 0 ? '—' : selection.pathRun.httpStatus}</dd></div>
            <div><dt>{english ? 'Stop reason' : '停止原因'}</dt><dd className="veyrion-long-text">{selection.pathRun.stopReason || '—'}</dd></div>
          </dl>
        </>
      )}
      {selection.kind === 'hypothesis' && (
        <>
          <p className="eyebrow">{english ? 'HYPOTHESIS' : '假设'}</p>
          <h3 className="evidence-inspector__title">{selection.hypothesis.hypothesisId}</h3>
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Family' : '族'}</dt><dd>{selection.hypothesis.family}</dd></div>
            <div><dt>{english ? 'Property' : '属性'}</dt><dd>{selection.hypothesis.securityProperty}</dd></div>
            <div><dt>{english ? 'Lifecycle' : '生命周期'}</dt><dd>{selection.hypothesis.lifecycle}</dd></div>
            <div><dt>{english ? 'Supporting refs' : '支持引用'}</dt><dd>{selection.hypothesis.supportingEvidenceRefs.length}</dd></div>
          </dl>
        </>
      )}
      {selection.kind === 'entry' && (
        <>
          <p className="eyebrow">{english ? 'ENTRY' : '入口'}</p>
          <h3 className="evidence-inspector__title veyrion-long-text">{selection.entry.method} {selection.entry.route}</h3>
          <StatusPill status={selection.entry.status} />
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Module' : '模块'}</dt><dd className="veyrion-long-text">{selection.entry.module}</dd></div>
            <div><dt>{english ? 'Precondition' : '前置'}</dt><dd className="veyrion-long-text">{selection.entry.precondition}</dd></div>
            <div><dt>{english ? 'Coverage' : '覆盖'}</dt><dd>{selection.entry.coverage}%</dd></div>
            <div><dt>{english ? 'Parameters' : '参数'}</dt><dd>{selection.entry.parameters?.length ?? 0}</dd></div>
          </dl>
        </>
      )}
      {selection.kind === 'graphNode' && (
        <>
          <p className="eyebrow">{english ? 'GRAPH NODE' : '图谱节点'}</p>
          <h3 className="evidence-inspector__title veyrion-long-text">{selection.node.symbol || selection.node.id}</h3>
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Kind' : '类型'}</dt><dd>{selection.node.kind}{selection.node.kindRaw && selection.node.kindRaw !== selection.node.kind ? ` · raw=${selection.node.kindRaw}` : ''}</dd></div>
            <div><dt>{english ? 'Language' : '语言'}</dt><dd>{selection.node.language || '—'}</dd></div>
            <div><dt>{english ? 'Location' : '位置'}</dt><dd className="veyrion-long-text">{selection.node.location || '—'}</dd></div>
            <div><dt>{english ? 'Provenance' : '来源'}</dt><dd>{selection.node.provenanceKind}</dd></div>
            <div><dt>{english ? 'Evidence refs' : '证据引用'}</dt><dd>{selection.node.evidenceRefs.length}</dd></div>
            <div><dt>ID</dt><dd className="veyrion-long-text">{selection.node.id}</dd></div>
          </dl>
        </>
      )}
    </aside>
  )
}

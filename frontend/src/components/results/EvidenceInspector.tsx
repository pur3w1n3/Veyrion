import { hypothesisFamilyBlurb, hypothesisFamilyLabel, outcomeClassLabel } from '../../labels'
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
  if (!selection) return null

  return (
    <aside className="evidence-inspector" aria-label={english ? 'Evidence inspector' : '证据检查器'}>
      {selection.kind === 'finding' && (
        <>
          <p className="eyebrow">{english ? 'FINDING' : '发现'}</p>
          <h3 className="evidence-inspector__title veyrion-long-text">{selection.finding.title}</h3>
          <StatusPill status={selection.finding.status} english={english} />
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Family' : '假设族'}</dt><dd>{hypothesisFamilyLabel(familyOfFinding(selection.finding, hypothesisById), english)} <span className="term-chip">{familyOfFinding(selection.finding, hypothesisById)}</span></dd></div>
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
          <StatusPill status={selection.pathRun.verificationStatus} english={english} />
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Track' : '身份轨'}</dt><dd>{selection.pathRun.track}</dd></div>
            <div><dt>{english ? 'Outcome' : '结果'}</dt><dd>{selection.pathRun.outcomeClass} · {outcomeClassLabel(selection.pathRun.outcomeClass, english)}</dd></div>
            <div><dt>HTTP</dt><dd>{selection.pathRun.httpStatus < 0 ? '—' : selection.pathRun.httpStatus}</dd></div>
            <div><dt>{english ? 'Stop reason' : '停止原因'}</dt><dd className="veyrion-long-text">{selection.pathRun.stopReason || '—'}</dd></div>
          </dl>
        </>
      )}
      {selection.kind === 'hypothesis' && (
        <>
          <p className="eyebrow">{english ? 'HYPOTHESIS' : '假设'}</p>
          <h3 className="evidence-inspector__title veyrion-long-text">{selection.hypothesis.securityProperty}</h3>
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Id' : '编号'}</dt><dd className="veyrion-long-text">{selection.hypothesis.hypothesisId}</dd></div>
            <div>
              <dt>{english ? 'Family' : '族'}</dt>
              <dd>
                {hypothesisFamilyLabel(selection.hypothesis.family, english)}{' '}
                <span className="term-chip">{selection.hypothesis.family}</span>
              </dd>
            </div>
            <div><dt>{english ? 'Property' : '属性'}</dt><dd className="veyrion-long-text">{selection.hypothesis.securityProperty}</dd></div>
            <div><dt>{english ? 'Lifecycle' : '生命周期'}</dt><dd>{selection.hypothesis.lifecycle}</dd></div>
            <div><dt>{english ? 'Evidence count' : '证据数量'}</dt><dd>{selection.hypothesis.supportingEvidenceRefs.length}</dd></div>
            {selection.hypothesis.source && (
              <div><dt>{english ? 'Source' : '源'}</dt><dd className="veyrion-long-text">{selection.hypothesis.source}</dd></div>
            )}
            {selection.hypothesis.effect && (
              <div><dt>{english ? 'Effect' : '效应'}</dt><dd className="veyrion-long-text">{selection.hypothesis.effect}</dd></div>
            )}
          </dl>
        </>
      )}
      {selection.kind === 'hypothesisFamily' && (
        <>
          <p className="eyebrow">{english ? 'FAMILY' : '假设族'}</p>
          <h3 className="evidence-inspector__title">
            {hypothesisFamilyLabel(selection.family, english)}{' '}
            <span className="term-chip">{selection.family}</span>
          </h3>
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Count' : '数量'}</dt><dd>{selection.items.length}</dd></div>
            <div><dt>{english ? 'Summary' : '说明'}</dt><dd>{hypothesisFamilyBlurb(selection.family, english)}</dd></div>
            <div>
              <dt>{english ? 'Hypothesis ids' : '假设编号'}</dt>
              <dd className="veyrion-long-text">
                {selection.items.length === 0
                  ? (english ? 'Empty (not a safety claim).' : '空（不等于安全）。')
                  : selection.items.map((item) => item.hypothesisId).join(', ')}
              </dd>
            </div>
          </dl>
        </>
      )}
      {selection.kind === 'rankedSink' && (
        <>
          <p className="eyebrow">{english ? 'DATAFLOW' : '代码流向'}</p>
          <h3 className="evidence-inspector__title veyrion-long-text">
            {selection.sink.symbol || selection.sink.sinkId}
          </h3>
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Rank' : '编号'}</dt><dd>#{selection.sink.rank}</dd></div>
            <div><dt>{english ? 'Type' : '类型'}</dt><dd><span className="term-chip">{selection.sink.category || '—'}</span></dd></div>
            <div><dt>{english ? 'Score' : '评分'}</dt><dd>{selection.sink.score.toFixed(2)}</dd></div>
            <div><dt>{english ? 'Sink symbol' : 'Sink 符号'}</dt><dd className="veyrion-long-text">{selection.sink.symbol || '—'}</dd></div>
            <div><dt>Sink ID</dt><dd className="veyrion-long-text">{selection.sink.sinkId}</dd></div>
            <div>
              <dt>{english ? 'Path / call chain' : '路径 / 调用链'}</dt>
              <dd className="veyrion-long-text">{selection.sink.symbol || selection.sink.sinkId}</dd>
            </div>
            <div>
              <dt>{english ? 'Rank reasons' : '排序原因'}</dt>
              <dd className="veyrion-long-text">
                {selection.sink.rankReasons.length > 0
                  ? selection.sink.rankReasons.join(' · ')
                  : '—'}
              </dd>
            </div>
            <div>
              <dt>{english ? 'Evidence refs' : '证据引用'}</dt>
              <dd>{selection.sink.rankReasons.length > 0 ? selection.sink.rankReasons.length : 0}</dd>
            </div>
          </dl>
        </>
      )}
      {selection.kind === 'entry' && (
        <>
          <p className="eyebrow">{english ? 'ENTRY' : '入口'}</p>
          <h3 className="evidence-inspector__title veyrion-long-text">{selection.entry.method} {selection.entry.route}</h3>
          <StatusPill status={selection.entry.status} english={english} />
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

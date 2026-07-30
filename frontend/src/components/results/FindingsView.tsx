import { useMemo } from 'react'
import {
  HYPOTHESIS_FAMILIES,
  normalizeHypothesisFamily,
  type Entry,
  type ExperimentPlanDto,
  type Finding,
  type FindingReplayDto,
  type HypothesisFamily,
  type PathRunDto,
  type PathTrace,
  type SecurityHypothesisDto,
  type SqlExperimentCardDto
} from '../../api'
import { useListPagination } from '../../hooks/useListPagination'
import { hypothesisFamilyBlurb, hypothesisFamilyLabel } from '../../labels'
import { ListPagination } from '../ListPagination'
import { Notice, StatusPill } from '../Common'
import {
  familyOfFinding,
  isAuthGapFinding,
  resolveFindingApi,
  resolveFindingPoc,
  sortFindings
} from './resultsUtils'

export function FindingsView({
  english,
  findings,
  hypotheses,
  hypothesisById,
  entries,
  experimentPlans,
  sqlCards,
  pathRuns,
  selectedFindingId,
  onSelectFinding,
  findingQuery,
  onFindingQueryChange,
  findingStatus,
  onFindingStatusChange,
  findingFamily,
  onFindingFamilyChange,
  showAuthGap,
  onShowAuthGapChange,
  selectedPath,
  selectedStepIndex,
  onSelectStepIndex,
  replayLoading,
  replayError,
  replayResult,
  onReplayFinding,
  evidencePath,
  selectedHypothesisFamily,
  onSelectHypothesisFamily
}: {
  english: boolean
  findings: Finding[]
  hypotheses: SecurityHypothesisDto[]
  hypothesisById: Map<string, SecurityHypothesisDto>
  entries: Entry[]
  experimentPlans: ExperimentPlanDto[]
  sqlCards: SqlExperimentCardDto[]
  pathRuns: PathRunDto[]
  selectedFindingId?: string
  onSelectFinding: (finding: Finding) => void
  findingQuery: string
  onFindingQueryChange: (value: string) => void
  findingStatus: 'ALL' | Finding['status']
  onFindingStatusChange: (value: typeof findingStatus) => void
  findingFamily: 'ALL' | HypothesisFamily
  onFindingFamilyChange: (value: typeof findingFamily) => void
  showAuthGap: boolean
  onShowAuthGapChange: (value: boolean) => void
  selectedPath?: PathTrace
  selectedStepIndex: number
  onSelectStepIndex: (index: number) => void
  replayLoading: boolean
  replayError?: string
  replayResult?: FindingReplayDto
  onReplayFinding: () => void
  evidencePath: PathTrace['steps']
  selectedHypothesisFamily?: HypothesisFamily
  onSelectHypothesisFamily?: (family: HypothesisFamily, items: SecurityHypothesisDto[]) => void
}) {
  const filteredFindings = useMemo(() => {
    const query = findingQuery.trim().toLocaleLowerCase()
    return sortFindings(findings.filter((finding) => {
      if (!showAuthGap && isAuthGapFinding(finding)) return false
      if (findingStatus !== 'ALL' && finding.status !== findingStatus) return false
      if (findingFamily !== 'ALL' && familyOfFinding(finding, hypothesisById) !== findingFamily) return false
      if (!query) return true
      return [finding.title, finding.entry, finding.sink, finding.dependency, finding.securityProperty, finding.hypothesisId]
        .filter((value): value is string => typeof value === 'string')
        .some((value) => value.toLocaleLowerCase().includes(query))
    }))
  }, [findings, findingQuery, findingStatus, findingFamily, showAuthGap, hypothesisById])

  const pagination = useListPagination(
    filteredFindings,
    findingQuery,
    findingStatus,
    findingFamily,
    showAuthGap
  )

  const selectedFinding = filteredFindings.find((finding) => finding.id === selectedFindingId)
    ?? filteredFindings[0]
  const selectedStep = selectedPath?.steps[Math.min(selectedStepIndex, Math.max(0, (selectedPath?.steps.length ?? 1) - 1))]
  const selectedFindingFamily = selectedFinding ? familyOfFinding(selectedFinding, hypothesisById) : undefined

  const hypothesesByFamily = useMemo(() => {
    const buckets = new Map<HypothesisFamily, SecurityHypothesisDto[]>()
    for (const family of HYPOTHESIS_FAMILIES) buckets.set(family, [])
    for (const item of hypotheses) {
      buckets.get(normalizeHypothesisFamily(item.family))?.push(item)
    }
    return buckets
  }, [hypotheses])

  return (
    <div className="results-view results-view--findings">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'FINDINGS' : '发现'}</p>
          <h2>{english ? 'Vulnerability conclusions' : '漏洞结论'}</h2>
        </div>
        <span>{filteredFindings.length}</span>
      </div>

      <p className="form-help">
        {english
          ? 'Sorted by verification status (confirmed first), then severity. PathRun failures and diagnostics never appear here.'
          : '按验证态排序（动态确认优先），再按严重度。PathRun 失败与诊断项不会出现在此列表。'}
      </p>

      <div className="finding-toolbar">
        <label className="field">
          <span>{english ? 'Filter' : '筛选'}</span>
          <input value={findingQuery} onChange={(event) => onFindingQueryChange(event.target.value)} placeholder={english ? 'Title, entry, sink…' : '标题、入口、sink…'} />
        </label>
        <label className="field">
          <span>{english ? 'Status' : '状态'}</span>
          <select value={findingStatus} onChange={(event) => onFindingStatusChange(event.target.value as typeof findingStatus)}>
            <option value="ALL">{english ? 'All' : '全部'}</option>
            <option value="STATIC_INFERRED">STATIC_INFERRED</option>
            <option value="DYNAMIC_SUSPECTED">DYNAMIC_SUSPECTED</option>
            <option value="DYNAMIC_CONFIRMED">DYNAMIC_CONFIRMED</option>
            <option value="VERIFIED">VERIFIED</option>
            <option value="UNREACHED">UNREACHED</option>
          </select>
        </label>
        <label className="field">
          <span>{english ? 'Family' : '族'}</span>
          <select value={findingFamily} onChange={(event) => onFindingFamilyChange(event.target.value as typeof findingFamily)}>
            <option value="ALL">{english ? 'All' : '全部'}</option>
            {HYPOTHESIS_FAMILIES.map((family) => (
              <option key={family} value={family}>
                {hypothesisFamilyLabel(family, english)} ({family})
              </option>
            ))}
          </select>
        </label>
        <label className="field checkbox-field">
          <span>AUTH_GAP</span>
          <input type="checkbox" checked={showAuthGap} onChange={(event) => onShowAuthGapChange(event.target.checked)} />
        </label>
      </div>

      <div className="results-table-list">
        {pagination.pageItems.map((finding) => (
          <button
            type="button"
            key={finding.id}
            className={`results-row ${finding.id === selectedFinding?.id ? 'selected' : ''} status-tone-${finding.status.toLowerCase()}`}
            onClick={() => onSelectFinding(finding)}
          >
            <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
            <div className="results-row__body">
              <strong className="veyrion-long-text">{finding.title}</strong>
              <small className="veyrion-long-text">{familyOfFinding(finding, hypothesisById)} · {finding.entry} → {finding.sink}</small>
            </div>
            <StatusPill status={finding.status} english={english} />
          </button>
        ))}
        {filteredFindings.length === 0 && (
          <p className="empty-state">{english ? 'No findings match the filter.' : '没有符合筛选条件的发现。'}</p>
        )}
        <ListPagination
          english={english}
          ariaLabel={english ? 'Findings pagination' : '发现分页'}
          page={pagination.page}
          totalPages={pagination.totalPages}
          pageSize={pagination.pageSize}
          onPageSizeChange={pagination.setPageSize}
          rangeStart={pagination.rangeStart}
          rangeEnd={pagination.rangeEnd}
          total={pagination.total}
          onPrev={pagination.goPrev}
          onNext={pagination.goNext}
          canPrev={pagination.canPrev}
          canNext={pagination.canNext}
        />
      </div>

      {selectedFinding && (() => {
        const apiInfo = resolveFindingApi(selectedFinding, entries)
        const poc = resolveFindingPoc(
          selectedFinding,
          apiInfo.api,
          apiInfo.entryRef,
          experimentPlans,
          sqlCards,
          pathRuns
        )
        return (
        <div className="results-detail-block section-gap">
          <div className="results-view__head">
            <h3 className="veyrion-long-text">{selectedFinding.title}</h3>
            <StatusPill status={selectedFinding.status} english={english} />
          </div>
          <div className="button-row">
            <button type="button" className="secondary-button" onClick={onReplayFinding} disabled={replayLoading || selectedFinding.status === 'VERIFIED'}>
              {replayLoading ? (english ? 'Requesting…' : '正在请求…') : (english ? 'Request sandbox replay' : '请求沙箱重放')}
            </button>
          </div>
          {replayError && <Notice kind="error">{replayError}</Notice>}
          {replayResult && <Notice kind="info">{english ? `Replay task ${replayResult.taskId} is ${replayResult.lifecycle}.` : `重放任务 ${replayResult.taskId} 当前为 ${replayResult.lifecycle}。`}</Notice>}
          <dl className="evidence-inspector__dl">
            <div><dt>{english ? 'Family' : '族'}</dt><dd>{selectedFindingFamily}{selectedFinding.hypothesisId ? ` · ${selectedFinding.hypothesisId}` : ''}</dd></div>
            <div><dt>{english ? 'API / entry' : '接口 / 入口'}</dt><dd className="veyrion-long-text">{apiInfo.api}</dd></div>
            <div><dt>{english ? 'Sink' : 'Sink'}</dt><dd className="veyrion-long-text">{selectedFinding.sink}</dd></div>
            <div><dt>PoC</dt><dd className="veyrion-long-text">
              {poc.kind === 'none'
                ? (english ? 'No PoC yet' : '暂无 PoC')
                : <>{poc.summary}<small> · {poc.provenance}</small></>}
            </dd></div>
          </dl>
          {selectedPath && (
            <div className="chain-board section-gap" role="list">
              {selectedPath.steps.map((step, index) => (
                <div className="chain-node-wrap" key={`${step.label}-${index}`}>
                  <button type="button" role="listitem" className={`chain-node chain-node-${step.kind} ${index === selectedStepIndex ? 'selected' : ''}`} onClick={() => onSelectStepIndex(index)}>
                    <span>{index + 1}</span>
                    <strong>{step.label}</strong>
                    <small>{step.kind}</small>
                  </button>
                  {index < selectedPath.steps.length - 1 && <span className="chain-connector" aria-hidden="true">→</span>}
                </div>
              ))}
            </div>
          )}
          {selectedStep && <p className="form-help veyrion-long-text">{selectedStep.detail}</p>}
        </div>
        )
      })()}

      <div className="section-gap">
        <p className="eyebrow">{english ? 'HYPOTHESES BY FAMILY' : '按族假设'}</p>
        <table className="results-data-table hyp-family-table">
          <thead>
            <tr>
              <th>{english ? 'No.' : '编号'}</th>
              <th>{english ? 'Family' : '类型（族）'}</th>
              <th>{english ? 'Count' : '数量'}</th>
              <th>{english ? 'Summary' : '说明'}</th>
            </tr>
          </thead>
          <tbody>
            {HYPOTHESIS_FAMILIES
              .filter((family) => findingFamily === 'ALL' || findingFamily === family)
              .map((family, index) => {
                const items = hypothesesByFamily.get(family) ?? []
                return (
                  <tr
                    key={family}
                    className={selectedHypothesisFamily === family ? 'selected' : undefined}
                    onClick={() => onSelectHypothesisFamily?.(family, items)}
                  >
                    <td className="hyp-family-table__num">{index + 1}</td>
                    <td>
                      <strong>{hypothesisFamilyLabel(family, english)}</strong>
                      <span className="term-chip">{family}</span>
                    </td>
                    <td className="hyp-family-table__count">{items.length}</td>
                    <td className="veyrion-long-text">
                      {items.length === 0
                        ? (english ? 'Empty' : '空')
                        : hypothesisFamilyBlurb(family, english)}
                    </td>
                  </tr>
                )
              })}
          </tbody>
        </table>
      </div>

      {evidencePath.length > 0 && (
        <ol className="evidence-timeline section-gap">
          {evidencePath.map((step, index) => (
            <li key={`${step.label}-${index}`}>
              <span>{index + 1}</span>
              <div><strong>{step.label}</strong><small className="veyrion-long-text">{step.detail}</small></div>
              {step.verificationStatus && <StatusPill status={step.verificationStatus} english={english} />}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

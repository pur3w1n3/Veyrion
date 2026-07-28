import type { SummaryCounts } from './resultsUtils'

export function EvidenceSummaryStrip({
  counts,
  english
}: {
  counts: SummaryCounts
  english: boolean
}) {
  const items = [
    {
      label: english ? 'Static findings' : '静态发现',
      value: counts.staticFindings,
      hint: english ? 'STATIC_INFERRED rows' : 'STATIC_INFERRED 行'
    },
    {
      label: english ? 'Dynamic supported' : '动态支持',
      value: counts.dynamicSupported,
      hint: english ? 'Confirmed / suspected sessions' : '确认 / 疑似会话'
    },
    {
      label: english ? 'Dynamic failed' : '动态失败',
      value: counts.dynamicFailed,
      hint: english ? 'UNREACHED / UNKNOWN / -1' : 'UNREACHED / UNKNOWN / -1'
    },
    {
      label: english ? 'Coverage gaps' : '覆盖缺口',
      value: counts.coverageGaps,
      hint: english ? 'Unresolved or unreached' : '未解析或未覆盖'
    },
    {
      label: english ? 'High-risk sinks' : '高风险 Sink',
      value: counts.highRiskSinks,
      hint: english ? 'Top ranked sinks' : '排序前列 Sink'
    }
  ]

  return (
    <div className="evidence-summary-strip" aria-label={english ? 'Evidence summary' : '证据摘要'}>
      {items.map((item) => (
        <div className="evidence-summary-strip__item" key={item.label}>
          <span className="evidence-summary-strip__label">{item.label}</span>
          <strong className="evidence-summary-strip__value">{item.value}</strong>
          <small className="evidence-summary-strip__hint">{item.hint}</small>
        </div>
      ))}
    </div>
  )
}

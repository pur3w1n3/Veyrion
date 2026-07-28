import type { DashboardSnapshot } from '../../api'
import { DOWNLOAD_ARTIFACTS } from '../../guiSemantics'

export function DownloadsView({
  english,
  snapshot,
  hasReport,
  onDownloadReport,
  onDownloadHtml,
  onDownloadJson
}: {
  english: boolean
  snapshot: DashboardSnapshot | null
  hasReport: boolean
  onDownloadReport: () => void
  onDownloadHtml: () => void
  onDownloadJson: () => void
}) {
  const items = [
    {
      id: DOWNLOAD_ARTIFACTS.reportMarkdown.id,
      title: english ? DOWNLOAD_ARTIFACTS.reportMarkdown.en : DOWNLOAD_ARTIFACTS.reportMarkdown.zh,
      desc: english
        ? 'REPORT_GENERATION markdown body — audit conclusion narrative.'
        : 'REPORT_GENERATION 最终 Markdown — 审计结论文本。',
      enabled: hasReport,
      onClick: onDownloadReport
    },
    {
      id: DOWNLOAD_ARTIFACTS.findingsHtml.id,
      title: english ? DOWNLOAD_ARTIFACTS.findingsHtml.en : DOWNLOAD_ARTIFACTS.findingsHtml.zh,
      desc: english
        ? 'Structured findings table export — not the final report or dashboard JSON.'
        : '结构化发现表格导出 — 不等于最终报告或仪表盘 JSON。',
      enabled: !!snapshot?.scanId,
      onClick: onDownloadHtml
    },
    {
      id: DOWNLOAD_ARTIFACTS.dashboardJson.id,
      title: english ? DOWNLOAD_ARTIFACTS.dashboardJson.en : DOWNLOAD_ARTIFACTS.dashboardJson.zh,
      desc: english
        ? 'Full scan dashboard snapshot with verificationStatus, MOCK flags and evidence refs.'
        : '完整扫描仪表盘快照，含 verificationStatus、MOCK 标识与 evidence refs。',
      enabled: !!snapshot?.scanId,
      onClick: onDownloadJson
    }
  ]

  return (
    <div className="results-view results-view--downloads">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'DOWNLOADS' : '下载'}</p>
          <h2>{english ? 'Three distinct artifacts' : '三种不等价制品'}</h2>
        </div>
      </div>

      <p className="form-help">
        {english
          ? 'Markdown, HTML and JSON serve different purposes and must not be described as equivalent formats.'
          : 'Markdown、HTML 与 JSON 用途不同，不得描述为等价格式。'}
      </p>

      <div className="downloads-list">
        {items.map((item) => (
          <div className="downloads-list__item" key={item.id}>
            <div>
              <strong>{item.title}</strong>
              <small>{item.id}</small>
              <p className="form-help">{item.desc}</p>
            </div>
            <button type="button" className="secondary-button" disabled={!item.enabled} onClick={item.onClick} title={item.id}>
              {english ? 'Download' : '下载'}
            </button>
          </div>
        ))}
      </div>

      {snapshot && (
        <p className="form-help section-gap">
          scanId · {snapshot.scanId} · {snapshot.verificationStatus} · {snapshot.dependencyMode}
        </p>
      )}
    </div>
  )
}

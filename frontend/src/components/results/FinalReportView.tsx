import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { AiJobDto } from '../../api'
import { DOWNLOAD_ARTIFACTS, RESULTS_VIEW_META, type ResultsViewId } from '../../guiSemantics'
import { jobStatusLabel } from '../../labels'
import { Notice } from '../Common'

const EMPTY_NAV_VIEWS = ['findings', 'pathRuns', 'diagnostics', 'downloads'] as const

export function FinalReportView({
  english,
  reportJob,
  reportSummary,
  reportError,
  reportLoading,
  reportEmpty,
  scanUnreached,
  onDownloadReport,
  onDownloadHtml,
  onNavigate
}: {
  english: boolean
  reportJob?: AiJobDto
  reportSummary?: string
  reportError?: string
  reportLoading: boolean
  reportEmpty: boolean
  scanUnreached: boolean
  onDownloadReport: () => void
  onDownloadHtml: () => void
  onNavigate: (view: ResultsViewId) => void
}) {
  return (
    <div className="results-view results-view--report">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'FINAL REPORT' : '最终报告'}</p>
          <h2>{english ? 'Audit conclusion' : '审计结论'}</h2>
        </div>
        <div className="button-row">
          <span className="inference-badge">{english ? 'MODEL INFERENCE' : '模型推断'}</span>
          {reportSummary && <>
            <button type="button" className="secondary-button" onClick={onDownloadReport} title={DOWNLOAD_ARTIFACTS.reportMarkdown.id}>
              {english ? DOWNLOAD_ARTIFACTS.reportMarkdown.en : DOWNLOAD_ARTIFACTS.reportMarkdown.zh}
            </button>
            <button type="button" className="secondary-button" onClick={onDownloadHtml} title={DOWNLOAD_ARTIFACTS.findingsHtml.id}>
              {english ? DOWNLOAD_ARTIFACTS.findingsHtml.en : DOWNLOAD_ARTIFACTS.findingsHtml.zh}
            </button>
          </>}
        </div>
      </div>

      {reportError && <Notice kind="error">{reportError}</Notice>}
      {reportLoading && (
        <p className="empty-state">
          {english ? 'Loading report events for this scan…' : '正在加载当前扫描的报告事件…'}
        </p>
      )}

      {!reportLoading && reportSummary && (
        <>
          <div className="ai-report veyrion-long-text">
            <ReactMarkdown skipHtml remarkPlugins={[remarkGfm]}>{reportSummary}</ReactMarkdown>
          </div>
          <p className="form-help">
            {reportJob?.aiJobId} · {reportJob?.providerId} · {reportJob?.model} ·{' '}
            {reportJob?.outputLanguage === 'ZH_CN'
              ? (english ? 'Simplified Chinese' : '简体中文')
              : (reportJob?.outputLanguage ?? (english ? 'UNKNOWN' : '未知'))}
            。
            {english ? 'Evidence-grounded model inference, not VERIFIED.' : '受证据约束的模型推断，不等于已验证。'}
          </p>
        </>
      )}

      {reportEmpty && (
        <div className="results-empty-report">
          {reportJob ? (
            <p className="empty-state">
              {english
                ? `Report job ${reportJob.aiJobId} is ${reportJob.status}${reportJob.errorCode ? ` · ${reportJob.errorCode}` : ''}; no final inference summary.`
                : `报告任务 ${reportJob.aiJobId} 当前为 ${jobStatusLabel(reportJob.status, false)}${reportJob.errorCode ? ` · ${reportJob.errorCode}` : ''}，尚无最终推断摘要。`}
            </p>
          ) : !reportError ? (
            <p className="empty-state">
              {scanUnreached
                ? (english
                  ? 'Scan verification status is UNREACHED — no final report body yet.'
                  : '当前扫描验证状态为 UNREACHED，尚无最终报告正文。')
                : (english
                  ? 'No REPORT_GENERATION summary for this scan yet.'
                  : '当前扫描尚未生成 REPORT_GENERATION 摘要。')}
            </p>
          ) : null}
          <p className="form-help">
            {english
              ? 'Structured findings and PathRuns remain available in other sub-views.'
              : '结构化发现与 PathRun 仍可在其他子页审阅。'}
          </p>
          <div className="results-view-links">
            {EMPTY_NAV_VIEWS.map((view) => (
              <button key={view} type="button" className="secondary-button" onClick={() => onNavigate(view)}>
                {english ? RESULTS_VIEW_META[view].en : RESULTS_VIEW_META[view].zh}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

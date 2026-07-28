/**
 * P1-23 GUI semantics contract — labels/views/download artifacts must stay consistent
 * across report, PathRun, and export surfaces. Asserted by GuiSemanticsContractAcceptanceTest.
 *
 * Audited scope = contract tests (not manual visual regression).
 * Production privacy / retention / MODEL_THINKING durable policy remains deferred with SSO
 * (ProductionFeatures.DISABLED / ADR-0003 PROPOSED).
 */

export const GUI_CONTRACT_AUDIT = {
  scope: 'contract-tests-not-manual-visual',
  productionPrivacyDeferredWithSso: true,
  modelThinkingRetentionDeferred: true
} as const

export const DOWNLOAD_ARTIFACTS = {
  reportMarkdown: {
    id: 'FINAL_REPORT_MARKDOWN',
    filenamePattern: 'veyrion-report-{scanId}.md',
    zh: '下载最终报告 Markdown',
    en: 'Download final report Markdown',
    contentKind: 'REPORT_GENERATION_MARKDOWN'
  },
  findingsHtml: {
    id: 'FINDINGS_SUMMARY_HTML',
    filenamePattern: 'veyrion-findings-{scanId}.html',
    zh: '导出发现摘要 HTML',
    en: 'Export findings summary HTML',
    contentKind: 'FINDINGS_SUMMARY_HTML'
  },
  dashboardJson: {
    id: 'SCAN_DASHBOARD_JSON',
    filenamePattern: 'veyrion-scan-{scanId}.json',
    zh: '导出扫描仪表盘 JSON',
    en: 'Export scan dashboard JSON',
    contentKind: 'DASHBOARD_SNAPSHOT_JSON'
  }
} as const

/** Results sub-views from GUI_DESIGN §2 / §4 — not interchangeable with downloads. */
export const RESULTS_VIEW_IDS = [
  'report',
  'pathRuns',
  'coverage',
  'hypotheses',
  'evidenceGraph',
  'contrast',
  'findings',
  'verified',
  'experiments'
] as const

export type ResultsViewId = (typeof RESULTS_VIEW_IDS)[number]

export const RESULTS_VIEW_META: Record<ResultsViewId, { zh: string; en: string; blurbZh: string; blurbEn: string }> = {
  report: {
    zh: '最终报告',
    en: 'Final report',
    blurbZh: 'REPORT_GENERATION 最终报告正文（非发现 HTML / 非仪表盘 JSON）',
    blurbEn: 'REPORT_GENERATION markdown body (not findings HTML / not dashboard JSON)'
  },
  pathRuns: {
    zh: 'PathRun 会话',
    en: 'PathRun sessions',
    blurbZh: '入口 × 身份轨 × probe attempt 会话证据',
    blurbEn: 'Entry × identity-track × probe attempt sessions'
  },
  coverage: {
    zh: 'Coverage Matrix',
    en: 'Coverage Matrix',
    blurbZh: '覆盖矩阵与未解析缺口；成功≠安全',
    blurbEn: 'Coverage matrix and unresolved gaps; success ≠ safe'
  },
  hypotheses: {
    zh: '安全假设',
    en: 'Security hypotheses',
    blurbZh: '按 family / securityProperty 的假设池',
    blurbEn: 'Hypothesis pool by family / securityProperty'
  },
  evidenceGraph: {
    zh: 'Evidence Graph',
    en: 'Evidence Graph',
    blurbZh: '局部证据图；未知 kind 可降级',
    blurbEn: 'Local evidence graph; unknown kinds degrade safely'
  },
  contrast: {
    zh: 'Sink 与对照账本',
    en: 'Sinks & ledger',
    blurbZh: '候选 Sink 排序与对照差分',
    blurbEn: 'Ranked sinks and contrast ledger diff'
  },
  findings: {
    zh: '发现与攻击链',
    en: 'Findings & chain',
    blurbZh: '次级发现、入口覆盖与攻击链',
    blurbEn: 'Secondary findings, entries, attack chain'
  },
  verified: {
    zh: '已验证',
    en: 'Verified',
    blurbZh: 'VerifiedStatusGate 门禁结果（当前应为空）',
    blurbEn: 'VerifiedStatusGate rows (currently empty)'
  },
  experiments: {
    zh: '实验计划',
    en: 'Experiments',
    blurbZh: 'SQL D3 实验卡与已接受计划',
    blurbEn: 'SQL D3 cards and accepted plans'
  }
}

/** Pipeline / job terminal and blocked states that must be text-visible (not color-only). */
export const PIPELINE_STATUS_LABELS = {
  BLOCKED: { zh: '已阻断', en: 'Blocked' },
  WORKER_UNAVAILABLE: { zh: '无 Worker / Worker 不可用', en: 'Worker unavailable' },
  PROJECTION_FAILED: { zh: '证据投影失败', en: 'Evidence projection failed' },
  CANCELLED: { zh: '已取消', en: 'Cancelled' },
  FAILED: { zh: '失败', en: 'Failed' },
  QUEUED: { zh: '排队中', en: 'Queued' },
  RUNNING: { zh: '执行中', en: 'Running' },
  COMPLETED: { zh: '已完成', en: 'Completed' },
  IDENTITY_UNAVAILABLE: { zh: '身份不可用', en: 'Identity unavailable' },
  MODEL_THINKING: {
    zh: '模型思考（不可信审计元数据）',
    en: 'Model thinking (untrusted audit metadata)'
  }
} as const

export const downloadFilename = (
  kind: keyof typeof DOWNLOAD_ARTIFACTS,
  scanId: string
): string => {
  const safe = scanId.replace(/[^A-Za-z0-9._-]/g, '_')
  return DOWNLOAD_ARTIFACTS[kind].filenamePattern.replace('{scanId}', safe)
}

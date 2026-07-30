/**
 * P1-23 GUI 语义合同 — labels/views/download 制品须在
 * report、PathRun 与 export 面保持一致。由 GuiSemanticsContractAcceptanceTest 断言。
 *
 * 审计范围 = 合同测试（非手动视觉回归）。
 * 生产 privacy / retention / MODEL_THINKING 持久策略仍与 SSO 一并延期
 *（ProductionFeatures.DISABLED / ADR-0003 PROPOSED）。
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

/** 来自 GUI_DESIGN §2 / §4 的 Results 子视图 — 与 downloads 不可互换。 */
export const RESULTS_VIEW_IDS = [
  'report',
  'findings',
  'entryExploration',
  'pathRuns',
  'evidenceGraph',
  'coverage',
  'diagnostics',
  'experiments',
  'hypotheses',
  'contrast',
  'verified',
  'aiMemory',
  'downloads'
] as const

export type ResultsViewId = (typeof RESULTS_VIEW_IDS)[number]

/**
 * 自 ResultsSubnav chrome 隐藏（P1-25 report UX）。
 * ID 仍留在 RESULTS_VIEW_IDS 供 P1-23 合同 + API prefetch；面板不展示。
 */
export const RESULTS_VIEWS_HIDDEN_FROM_NAV = ['evidenceGraph', 'coverage'] as const

export const RESULTS_VIEW_META: Record<ResultsViewId, { zh: string; en: string; blurbZh: string; blurbEn: string }> = {
  report: {
    zh: '最终报告',
    en: 'Final report',
    blurbZh: 'REPORT_GENERATION 可交付审计报告正文（封面/摘要/按严重度分组的关键发现/利用链/附录；非发现 HTML / 非仪表盘 JSON）',
    blurbEn: 'REPORT_GENERATION deliverable audit report (cover/summary/severity-grouped key findings/exploit chains/appendix; not findings HTML / not dashboard JSON)'
  },
  findings: {
    zh: '发现',
    en: 'Findings',
    blurbZh: '静态优先排序；PathRun 失败不进入发现列表',
    blurbEn: 'Static-first sort; PathRun failures are not findings'
  },
  entryExploration: {
    zh: '入口参数探索',
    en: 'Entry exploration',
    blurbZh: '入口 × 0-n 参数矩阵与实验 readiness',
    blurbEn: 'Entry × 0-n parameter matrix and experiment readiness'
  },
  pathRuns: {
    zh: 'PathRun 会话',
    en: 'PathRun sessions',
    blurbZh: '入口 × 身份轨 × probe attempt 会话证据',
    blurbEn: 'Entry × identity-track × probe attempt sessions'
  },
  evidenceGraph: {
    zh: '证据图',
    en: 'Evidence Graph',
    blurbZh: '局部证据图；未知 kind 可降级',
    blurbEn: 'Local evidence graph; unknown kinds degrade safely'
  },
  coverage: {
    zh: '覆盖矩阵',
    en: 'Coverage Matrix',
    blurbZh: '覆盖矩阵与未解析缺口；成功≠安全',
    blurbEn: 'Coverage matrix and unresolved gaps; success ≠ safe'
  },
  diagnostics: {
    zh: '动态诊断',
    en: 'Dynamic diagnostics',
    blurbZh: '启动失败、UNREACHED、UNKNOWN/-1 与 MOCK 依赖说明',
    blurbEn: 'Startup failures, UNREACHED, UNKNOWN/-1 and MOCK dependency notes'
  },
  experiments: {
    zh: '实验与重放',
    en: 'Experiments & replay',
    blurbZh: 'SQL D3 实验卡与已接受计划',
    blurbEn: 'SQL D3 cards and accepted plans'
  },
  downloads: {
    zh: '下载',
    en: 'Downloads',
    blurbZh: 'Markdown / HTML / JSON 三种不等价制品',
    blurbEn: 'Three distinct artifacts: Markdown, HTML, JSON'
  },
  hypotheses: {
    zh: '安全假设',
    en: 'Security hypotheses',
    blurbZh: '按 family / securityProperty 的假设池',
    blurbEn: 'Hypothesis pool by family / securityProperty'
  },
  contrast: {
    zh: 'Sink 与对照账本',
    en: 'Sinks & ledger',
    blurbZh: '候选 Sink 排序与对照差分',
    blurbEn: 'Ranked sinks and contrast ledger diff'
  },
  verified: {
    zh: '已验证',
    en: 'Verified',
    blurbZh: 'VerifiedStatusGate 门禁结果（当前应为空）',
    blurbEn: 'VerifiedStatusGate rows (currently empty)'
  },
  aiMemory: {
    zh: 'AI 记忆',
    en: 'AI memory',
    blurbZh: '同扫描共享记忆索引与工具说明（只读调试）',
    blurbEn: 'Same-scan shared memory index and tool catalog (read-only)'
  }
}

/** 须文本可见（非仅颜色）的 pipeline / job 终态与阻塞状态。 */
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

import { useEffect, useMemo, useState } from 'react'
import { api, type DashboardSnapshot, type Entry, type EvidenceDto, type Finding, type PathStep, type VerificationStatus } from './api'

type View = 'overview' | 'entries' | 'paths' | 'findings'

const navItems: Array<{ id: View; label: string; hint: string; icon: string }> = [
  { id: 'overview', label: '项目总览', hint: 'Overview', icon: '⌂' },
  { id: 'entries', label: '入口地图', hint: 'Entry surface', icon: '⌁' },
  { id: 'paths', label: '路径探索', hint: 'Path explorer', icon: '◈' },
  { id: 'findings', label: '发现与攻击链', hint: 'Findings', icon: '◇' }
]

function StatusPill({ status }: { status: VerificationStatus }) {
  const labels: Record<VerificationStatus, string> = {
    VERIFIED: '已验证',
    DYNAMIC_SUSPECTED: '动态疑似',
    STATIC_INFERRED: '静态推测',
    UNREACHED: '未覆盖'
  }
  return <span className={`status status-${status.toLowerCase()}`}><i />{labels[status]}</span>
}

function Metric({ label, value, trend, tone = 'cyan' }: { label: string; value: string; trend: string; tone?: string }) {
  return <article className={`metric metric-${tone}`}><div className="metric-label">{label}<span className="metric-dot" /></div><strong>{value}</strong><small>{trend}</small></article>
}

function Overview({ snapshot, onView }: { snapshot: DashboardSnapshot; onView: (view: View) => void }) {
  const verified = snapshot.findings.filter((finding) => finding.status === 'VERIFIED').length
  const coverage = snapshot.entries.length === 0
    ? 0
    : Math.round(snapshot.entries.reduce((sum, entry) => sum + entry.coverage, 0) / snapshot.entries.length)
  const scanId = snapshot.scanId ?? 'UNSCANNED'
  const dependencyMode = snapshot.dependencyMode ?? 'UNKNOWN'
  const inferred = snapshot.findings.filter((finding) => finding.status === 'STATIC_INFERRED').length
  const dependencyScore = dependencyMode === 'MOCK' ? 0 : dependencyMode === 'REPLAY' ? 50 : dependencyMode === 'LIVE' ? 100 : undefined
  const dependencyRingScore = dependencyScore ?? 0
  const unreached = snapshot.entries.filter((entry) => entry.status === 'UNREACHED').length
  const dependencyFields = snapshot.path.filter((step) => step.kind === 'dependency').length
  return <>
    <section className="hero-row">
      <div><p className="eyebrow">LIVE SECURITY WORKSPACE <span>·</span> {scanId}</p><h1>看见每一条<br /><em>可追溯流向。</em></h1><p className="hero-copy">从外部入口到敏感 sink，溯脉将静态推断、依赖事实和可追溯证据汇聚到同一条链路；当前切片不执行制品。</p></div>
      <div className="scan-card"><div className="scan-orbit" style={{ background: `radial-gradient(circle, #12283b 52%, transparent 54%), conic-gradient(var(--cyan) 0 ${coverage}%, #22364d ${coverage}% 100%)` }}><span>{coverage}%</span></div><div><p className="card-kicker">{scanId === 'UNSCANNED' ? '等待扫描' : '扫描状态'}</p><strong>{scanId}</strong><small>{snapshot.entries.length} 个入口 · 依赖模式 {dependencyMode}</small></div><button className="ghost-button" onClick={() => onView('paths')}>打开实时路径 <span>↗</span></button></div>
    </section>
    <section className="metrics-grid">
      <Metric label="外部入口" value={`${snapshot.entries.length}`} trend={`${snapshot.entries.length - unreached} 个已覆盖 · ${unreached} 个未覆盖`} />
      <Metric label="路径覆盖度" value={`${coverage}%`} trend="由入口 DTO 覆盖度计算" tone="violet" />
      <Metric label="已验证发现" value={`${verified}`} trend={`${inferred} 条仍为静态推断`} tone="orange" />
      <Metric label="依赖替身命中" value={dependencyScore === undefined ? '—' : `${dependencyScore}%`} trend={`${dependencyMode} · ${dependencyFields} 个依赖节点`} tone="green" />
    </section>
    <section className="content-grid overview-grid">
      <article className="panel panel-large"><div className="panel-head"><div><p className="eyebrow">ATTACK SURFACE</p><h2>入口与风险流</h2></div><button className="text-button" onClick={() => onView('entries')}>查看全部 <span>→</span></button></div><div className="surface-chart"><div className="chart-y"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div><div className="chart-main"><div className="grid-lines" /><svg viewBox="0 0 660 190" preserveAspectRatio="none" aria-label="覆盖度趋势图"><defs><linearGradient id="area" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#43e6d0" stopOpacity=".24" /><stop offset="1" stopColor="#43e6d0" stopOpacity="0" /></linearGradient></defs><path className="chart-area" d="M0,152 C52,139 73,143 107,119 S166,112 193,126 S243,90 275,102 S327,74 357,89 S410,57 439,72 S490,52 521,61 S583,28 660,35 L660,190 L0,190Z" /><path className="chart-line" d="M0,152 C52,139 73,143 107,119 S166,112 193,126 S243,90 275,102 S327,74 357,89 S410,57 439,72 S490,52 521,61 S583,28 660,35" /><circle cx="439" cy="72" r="5" className="chart-point" /></svg><div className="chart-x"><span>静态</span><span>入口</span><span>依赖</span><span>sink</span><span>当前</span></div></div></div><div className="chart-legend"><span><i className="legend-cyan" />路径覆盖</span><span><i className="legend-violet" />sink 可达性</span><span className="legend-note">覆盖率来自 DTO · 曲线为静态示意 · 依赖模式 {dependencyMode}</span></div></article>
      <article className="panel chain-panel"><div className="panel-head"><div><p className="eyebrow">CORRELATION BRAIN</p><h2>攻击链候选</h2></div><span className="live-tag">● {api.mode === 'demo' ? 'DEMO' : 'LIVE'}</span></div><div className="chain-list">{snapshot.findings.slice(0, 3).map((finding, index) => <div className="chain-item" key={finding.id}><span className="chain-number">{String(index + 1).padStart(2, '0')}</span><div><strong>{finding.entry} → {finding.sink}</strong><small>{finding.dependency} · {finding.evidence} 条证据</small></div><span className={`chain-score ${finding.status === 'VERIFIED' ? '' : 'muted'}`}>{finding.confidence === undefined ? finding.status === 'VERIFIED' ? '100%' : '—' : `${Math.round(finding.confidence * 100)}%`}</span></div>)}{snapshot.findings.length === 0 && <div className="chain-item"><span className="chain-number">—</span><div><strong>暂无攻击链候选</strong><small>等待扫描发现</small></div></div>}</div><button className="wide-button" onClick={() => onView('findings')}>打开攻击链画布 <span>↗</span></button></article>
    </section>
      <section className="content-grid bottom-grid"><article className="panel"><div className="panel-head"><div><p className="eyebrow">RECENT EVIDENCE</p><h2>最近证据</h2></div><button className="text-button" onClick={() => onView('paths')}>全部轨迹 →</button></div><div className="evidence-list">{snapshot.path.slice(0, 4).map((step) => <EvidenceRow key={step.label} step={step} />)}</div></article><article className="panel dependency-panel"><div className="panel-head"><div><p className="eyebrow">DEPENDENCY MODE</p><h2>替身与外部依赖</h2></div><span className="mode-badge">{dependencyMode}</span></div><div className="dependency-ring"><div className="ring"><span>{dependencyScore === undefined ? '—' : dependencyScore}<small>{dependencyScore === undefined ? '' : '%'}</small></span></div><div><strong>{dependencyFields} 个依赖节点</strong><small>来自当前扫描 DTO</small><strong>{dependencyMode === 'MOCK' ? '0 个真实连接' : '连接由 Control Plane 管理'}</strong><small>出站网络策略需查看扫描策略</small></div></div><div className="safe-note"><span>✓</span> 当前证据不会绕过 Control Plane 安全边界</div></article></section>
  </>
}

function EvidenceRow({ step }: { step: PathStep }) { const stateLabel = step.state === 'done' ? '已记录' : step.state === 'blocked' ? '未执行' : '进行中'; return <div className="evidence-row"><span className={`evidence-icon icon-${step.kind}`}>{step.kind === 'dependency' ? 'DB' : step.kind === 'sink' ? '!' : '·'}</span><div><strong>{step.label}</strong><small>{step.detail}</small></div><span className={`row-state ${step.state}`}>{stateLabel}</span></div> }

function Entries({ entries, onSelect }: { entries: Entry[]; onSelect: (entry: Entry) => void }) { const unreached = entries.filter((entry) => entry.status === 'UNREACHED').length; return <section className="page-section"><div className="page-title"><div><p className="eyebrow">ENTRY SURFACE / {String(entries.length).padStart(2, '0')}</p><h1>入口地图</h1><p>所有外部可达入口的静态清单、运行状态和风险邻近度。</p></div><button className="primary-button" disabled title="探索计划 API 尚未接入">＋ 加入探索计划（待接入）</button></div><div className="toolbar"><div className="search-box">⌕ <input aria-label="搜索入口" placeholder="搜索路由、类或模块" /></div><button className="filter-button">协议 <b>全部</b>⌄</button><button className="filter-button">状态 <b>全部</b>⌄</button><span className="toolbar-count">{entries.length} 个入口 · {unreached} 个未覆盖</span></div><div className="table-wrap"><table><thead><tr><th>入口</th><th>协议</th><th>模块</th><th>前置条件</th><th>覆盖度</th><th>状态</th><th /></tr></thead><tbody>{entries.map((entry) => <tr key={entry.id} tabIndex={0} onClick={() => onSelect(entry)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') onSelect(entry) }}><td><strong className="route">{entry.route}</strong><small>{entry.method} · {entry.id}</small></td><td><span className="protocol">{entry.protocol}</span></td><td>{entry.module}</td><td><span className="precondition">{entry.precondition}</span></td><td><div className="mini-progress"><span style={{ width: `${entry.coverage}%` }} /></div><small>{entry.coverage}%</small></td><td><StatusPill status={entry.status} /></td><td className="row-arrow">→</td></tr>)}</tbody></table></div></section> }

function Paths({ path, entries, dependencyMode }: { path: PathStep[]; entries: Entry[]; dependencyMode?: string }) {
  const current = entries[0]
  return <section className="page-section"><div className="page-title"><div><p className="eyebrow">TRACE EVIDENCE / {current?.id ?? 'UNSCANNED'}</p><h1>路径探索器</h1><p>入口参数、分支约束和外部依赖的可追溯时间线；动态重放需等待沙箱 Worker。</p></div><div className="title-actions"><span className="mode-badge">STATIC ONLY</span><button className="primary-button" disabled title="沙箱 Worker 尚未接入">↻ 动态重放（待接入）</button></div></div><div className="trace-layout"><aside className="path-tree panel"><div className="panel-head"><h2>路径树</h2><span>{entries.length} 条入口</span></div>{entries.map((entry, index) => <div className={`tree-node ${index === 0 ? 'selected' : ''} ${entry.status === 'UNREACHED' ? 'muted-tree' : ''}`} key={entry.id}><i />{entry.method} {entry.route}<small>{entry.precondition} · {entry.coverage}%</small></div>)}{entries.length === 0 && <div className="tree-node muted-tree"><i />暂无入口<small>等待 Control Plane 扫描</small></div>}</aside><main className="trace-main panel"><div className="trace-head"><div><p className="eyebrow">TRACE TIMELINE</p><h2>{path[0]?.label ?? '暂无路径证据'}{path.length > 1 ? ` → ${path[path.length - 1].label}` : ''}</h2></div><StatusPill status={current?.status ?? 'UNREACHED'} /></div><div className="trace-line">{path.map((step, index) => <div className={`trace-step ${step.state}`} key={`${step.label}-${index}`}><div className={`trace-dot dot-${step.kind}`}><span>{index + 1}</span></div><div className="trace-card"><div><strong>{step.label}</strong><span className={`kind-label kind-${step.kind}`}>{step.kind}</span></div><p>{step.detail}</p>{step.kind === 'dependency' && <div className="trace-meta"><span>evidence refs <b>{step.evidenceRefs?.length ?? 0}</b></span><span>mode <b>{dependencyMode ?? 'UNKNOWN'}</b></span></div>}</div></div>)}{path.length === 0 && <p className="trace-empty">暂无可展示路径；请先创建扫描并等待证据。</p>}</div></main></div></section>
}

function Findings({ findings, onEvidence }: { findings: Finding[]; onEvidence: (evidenceId: string) => void }) {
  const primary = findings[0]
  const score = primary?.confidence === undefined ? undefined : Math.round(primary.confidence * 100)
  const evidenceId = primary?.evidenceRefs?.[0]
  const evidenceKey = typeof evidenceId === 'string' ? evidenceId : evidenceId?.evidenceId
  return <section className="page-section"><div className="page-title"><div><p className="eyebrow">FINDINGS / CORRELATION</p><h1>发现与攻击链</h1><p>以证据状态为中心，审阅单点风险和跨入口关联。</p></div><button className="primary-button" disabled title="报告导出 API 尚未接入">导出审计报告（待接入）</button></div><div className="finding-layout"><div className="finding-list panel">{findings.map((finding) => <div className="finding-card" key={finding.id}><div className={`severity severity-${finding.severity}`}>{finding.severity === 'critical' ? 'CRIT' : finding.severity.toUpperCase()}</div><div className="finding-body"><div className="finding-title"><strong>{finding.title}</strong><StatusPill status={finding.status} /></div><p>{finding.entry} <span>→</span> {finding.sink}</p><small>{finding.dependency} · {finding.evidence} 条证据</small></div><span className="row-arrow">→</span></div>)}{findings.length === 0 && <div className="finding-card"><div className="finding-body"><strong>暂无发现</strong><small>等待 Control Plane 返回证据</small></div></div>}</div><div className="chain-canvas panel"><div className="panel-head"><div><p className="eyebrow">CHAIN / {primary?.id ?? 'NONE'}</p><h2>{primary ? `${primary.entry} → ${primary.sink}` : '暂无攻击链候选'}</h2></div>{score === undefined ? <span className="chain-score muted">—</span> : <span className="chain-score">{score}%</span>}</div><div className="attack-graph"><div className="graph-node node-entry"><span>ENTRY</span><strong>{primary?.entry ?? '—'}</strong><small>{primary?.status ?? 'UNREACHED'}</small></div><div className="graph-edge edge-one"><i />证据关联</div><div className="graph-node node-file"><span>DEPENDENCY</span><strong>{primary?.dependency ?? '—'}</strong><small>{primary ? `${primary.evidence} 条证据` : '暂无证据'}</small></div><div className="graph-edge edge-two"><i />sink 映射</div><div className="graph-node node-exec"><span>SINK</span><strong>{primary?.sink ?? '—'}</strong><small>{primary?.status ?? 'UNREACHED'}</small></div></div><div className="chain-foot"><span><i className="legend-red" />已验证边</span><span><i className="legend-orange" />动态疑似边</span><button className="text-button" disabled={!evidenceKey} onClick={() => { if (evidenceKey) onEvidence(evidenceKey) }}>查看证据 →</button></div></div></div></section>
}

export default function App() {
  const [view, setView] = useState<View>('overview')
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [selectedEntry, setSelectedEntry] = useState<Entry | null>(null)
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceDto | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  useEffect(() => {
    let disposed = false
    let unsubscribe: () => void = () => undefined
    const reconcile = () => api.loadDashboard().then((next) => {
      if (!disposed) {
        setSnapshot(next)
        setLoadError(null)
      }
      return next
    }).catch((error: unknown) => {
      if (!disposed) setLoadError(error instanceof Error ? error.message : 'Control Plane 请求失败')
      return undefined
    })
    void reconcile().then((next) => {
      if (disposed || !next) return
      const scanId = (next.scanId && next.scanId !== 'unscanned' ? next.scanId : '') || import.meta.env.VITE_SCAN_ID || (api.mode === 'demo' ? 'scan-07f2' : '')
      if (!scanId) return
      unsubscribe = api.subscribe(scanId, () => undefined, {
        onReconcile: () => { void reconcile() },
        onError: (error) => { if (!disposed) setLoadError(error instanceof Error ? error.message : 'SSE 连接失败') }
      })
    })
    return () => {
      disposed = true
      unsubscribe()
    }
  }, [])
  const loadEvidence = (evidenceId: string) => {
    void api.getEvidence(evidenceId).then(setSelectedEvidence).catch((error: unknown) => {
      setLoadError(error instanceof Error ? error.message : '证据请求失败')
    })
  }
  const title = useMemo(() => navItems.find((item) => item.id === view)?.label ?? '项目总览', [view])
  if (loadError && !snapshot) return <div className="loading-screen"><div className="loading-mark">!</div><p>{loadError}</p><button className="primary-button" onClick={() => window.location.reload()}>重新连接</button></div>
  if (!snapshot) return <div className="loading-screen"><div className="loading-mark">S</div><p>正在载入安全工作区…</p></div>
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark">V</div><div><strong>VEYRION</strong><small>溯脉 · JVM SECURITY</small></div></div><div className="workspace-switch"><span className="workspace-dot" /><div><small>当前工作区</small><strong>{snapshot.projectId ?? '未选择项目'}</strong></div><span>⌄</span></div><nav>{navItems.map((item) => <button className={view === item.id ? 'nav-item active' : 'nav-item'} onClick={() => setView(item.id)} key={item.id}><span className="nav-icon">{item.icon}</span><span><strong>{item.label}</strong><small>{item.hint}</small></span>{item.id === 'findings' && <b className="nav-count">{snapshot.findings.length}</b>}</button>)}</nav><div className="sidebar-bottom"><div className="sandbox-status"><span className="pulse" /><div><strong>{api.mode === 'demo' ? '演示工作区' : 'Control Plane 已连接'}</strong><small>{api.mode === 'demo' ? '未连接真实制品或沙箱' : `依赖模式 ${snapshot.dependencyMode ?? 'UNKNOWN'}`}</small></div></div><button className="nav-item"><span className="nav-icon">⚙</span><span><strong>策略与审计</strong><small>Policy center</small></span></button><div className="user-chip"><div className="avatar">L</div><div><strong>Lin · Analyst</strong><small>安全分析师</small></div><span>⋮</span></div></div></aside><main className="main-content"><header className="topbar"><div className="crumb"><span>WORKSPACE</span><b>/</b><strong>{title}</strong></div><div className="top-actions"><span className="demo-label">{api.mode === 'demo' ? 'DEMO DATA' : 'CONTROL PLANE'}</span><span className="secure-label"><i />{api.mode === 'demo' ? 'LOCAL-ONLY' : 'API CONNECTED'}</span><button className="icon-button" aria-label="通知">♢<b>{snapshot.findings.length}</b></button><button className="avatar avatar-small" aria-label="用户菜单">L</button></div></header><div className="page-container">{view === 'overview' && <Overview snapshot={snapshot} onView={setView} />}{view === 'entries' && <Entries entries={snapshot.entries} onSelect={setSelectedEntry} />}{view === 'paths' && <Paths path={snapshot.path} entries={snapshot.entries} dependencyMode={snapshot.dependencyMode} />}{view === 'findings' && <Findings findings={snapshot.findings} onEvidence={loadEvidence} />}</div></main>{selectedEntry && <div className="modal-backdrop" role="presentation" onClick={() => setSelectedEntry(null)}><div className="entry-modal" role="dialog" aria-modal="true" aria-labelledby="entry-detail-title" onClick={(event) => event.stopPropagation()}><button className="modal-close" aria-label="关闭" onClick={() => setSelectedEntry(null)}>×</button><p className="eyebrow">ENTRY DETAIL / {selectedEntry.id}</p><h2 id="entry-detail-title">{selectedEntry.route}</h2><StatusPill status={selectedEntry.status} /><div className="modal-grid"><span>协议<strong>{selectedEntry.protocol}</strong></span><span>模块<strong>{selectedEntry.module}</strong></span><span>前置条件<strong>{selectedEntry.precondition}</strong></span><span>覆盖度<strong>{selectedEntry.coverage}%</strong></span></div><button className="primary-button" onClick={() => setSelectedEntry(null)}>加入探索计划</button></div></div>}{selectedEvidence && <div className="modal-backdrop" role="presentation" onClick={() => setSelectedEvidence(null)}><div className="entry-modal evidence-modal" role="dialog" aria-modal="true" aria-labelledby="evidence-detail-title" onClick={(event) => event.stopPropagation()}><button className="modal-close" aria-label="关闭" onClick={() => setSelectedEvidence(null)}>×</button><p className="eyebrow">EVIDENCE / {selectedEvidence.evidenceId}</p><h2 id="evidence-detail-title">{selectedEvidence.summary}</h2><div className="modal-grid"><span>来源<strong>{selectedEvidence.source}</strong></span><span>类型<strong>{selectedEvidence.kind}</strong></span><span>置信度<strong>{Math.round(selectedEvidence.confidence * 100)}%</strong></span><span>快照<strong>{selectedEvidence.snapshotRef ?? '未提供'}</strong></span></div><small>observedAt: {selectedEvidence.observedAt ?? '未提供'} · tool: {selectedEvidence.toolVersion ?? '未提供'} · model: {selectedEvidence.modelVersion ?? '未提供'}</small></div></div>}</div>
}

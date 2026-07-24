import type { DashboardSnapshot } from '../api'
import { PageHeader, StatusPill } from './Common'

export function ResultsPage({ snapshot }: { snapshot: DashboardSnapshot | null }) {
  const findings = snapshot?.findings ?? []
  const entries = snapshot?.entries ?? []
  return <section>
    <PageHeader eyebrow={`RESULTS / ${snapshot?.scanId ?? 'NO SCAN'}`} title="审计结果">
      每项结论保留独立证据状态；无动态证据时不得将静态命中描述为可利用漏洞。
    </PageHeader>
    <div className="metrics-grid">
      <article className="metric"><span>入口</span><strong>{entries.length}</strong><small>{entries.filter((item) => item.status === 'UNREACHED').length} 未覆盖</small></article>
      <article className="metric"><span>静态推断</span><strong>{findings.filter((item) => item.status === 'STATIC_INFERRED').length}</strong><small>需运行时证据</small></article>
      <article className="metric"><span>动态疑似</span><strong>{findings.filter((item) => item.status === 'DYNAMIC_SUSPECTED').length}</strong><small>需可重放验证</small></article>
      <article className="metric"><span>已验证</span><strong>{findings.filter((item) => item.status === 'VERIFIED').length}</strong><small>证据边界最高等级</small></article>
    </div>
    <div className="result-grid">
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">FINDINGS</p><h2>发现</h2></div><span>{findings.length}</span></div>
        <div className="card-list">{findings.map((finding) => <div className="finding-card" key={finding.id}><div className={`severity severity-${finding.severity}`}>{finding.severity}</div><div><strong>{finding.title}</strong><small>{finding.entry} → {finding.sink}</small><small>{finding.evidence} 条证据 · {finding.dependency}</small></div><StatusPill status={finding.status} /></div>)}{findings.length === 0 && <p className="empty-state">后端尚未返回发现。</p>}</div>
      </article>
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">ENTRY COVERAGE</p><h2>入口与覆盖</h2></div><span>{snapshot?.dependencyMode ?? 'UNKNOWN'}</span></div>
        <div className="card-list">{entries.map((entry) => <div className="list-card" key={entry.id}><div><strong>{entry.method} {entry.route}</strong><small>{entry.module} · {entry.precondition} · coverage {entry.coverage}%</small></div><StatusPill status={entry.status} /></div>)}{entries.length === 0 && <p className="empty-state">暂无入口；这不表示攻击面为空。</p>}</div>
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">EVIDENCE PATH</p><h2>证据时间线</h2></div><span>{snapshot?.path.length ?? 0} steps</span></div>
      <ol className="evidence-timeline">{snapshot?.path.map((step, index) => <li key={`${step.label}-${index}`}><span>{index + 1}</span><div><strong>{step.label}</strong><small>{step.detail}</small></div>{step.verificationStatus && <StatusPill status={step.verificationStatus} />}</li>)}{!snapshot?.path.length && <p className="empty-state">尚无证据路径。</p>}</ol>
    </article>
  </section>
}

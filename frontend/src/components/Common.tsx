import type { ReactNode } from 'react'
import type { VerificationStatus } from '../api'

const labels: Record<VerificationStatus, string> = {
  STATIC_INFERRED: '静态推断',
  DYNAMIC_SUSPECTED: '动态疑似',
  DYNAMIC_CONFIRMED: '动态确认',
  VERIFIED: '已验证',
  UNREACHED: '未覆盖'
}

export function StatusPill({ status }: { status: VerificationStatus }) {
  return <span className={`status status-${status.toLowerCase()}`}><i />{labels[status]}</span>
}

export function BoundaryLegend() {
  return <section className="boundary-banner" aria-label="证据状态边界">
    <strong>结论边界</strong>
    <StatusPill status="STATIC_INFERRED" />
    <span>代码与结构推断</span>
    <StatusPill status="DYNAMIC_SUSPECTED" />
    <span>运行时观察，尚未重放确认</span>
    <StatusPill status="DYNAMIC_CONFIRMED" />
    <span>SQL 恶意片段无过滤入库（MOCK，非生产证实）</span>
    <StatusPill status="VERIFIED" />
    <span>仅限强化沙箱可重放证据</span>
  </section>
}

export function PageHeader({ eyebrow, title, children, action }: { eyebrow: string; title: string; children: ReactNode; action?: ReactNode }) {
  return <header className="page-title"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{children}</p></div>{action}</header>
}

export function Notice({ kind = 'info', children }: { kind?: 'info' | 'error' | 'success'; children: ReactNode }) {
  return <div className={`notice notice-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>{children}</div>
}

export const errorMessage = (error: unknown) => error instanceof Error ? error.message : '请求不可用'

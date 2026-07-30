import type { ReactNode } from 'react'
import type { VerificationStatus } from '../api'

const zhLabels: Record<VerificationStatus, string> = {
  STATIC_INFERRED: '静态推断',
  DYNAMIC_SUSPECTED: '动态疑似',
  DYNAMIC_CONFIRMED: '动态确认',
  VERIFIED: '已验证',
  UNREACHED: '未覆盖'
}

/** EN keeps verification status codes as professional terms. */
export function StatusPill({ status, english = false }: { status: VerificationStatus; english?: boolean }) {
  return (
    <span className={`status status-${status.toLowerCase()}`}>
      <i />
      {english ? status : zhLabels[status]}
    </span>
  )
}

export function BoundaryLegend({ english = false }: { english?: boolean }) {
  return (
    <section className="boundary-banner" aria-label={english ? 'Evidence status boundary' : '证据状态边界'}>
      <strong>{english ? 'Conclusion boundary' : '结论边界'}</strong>
      <StatusPill status="STATIC_INFERRED" english={english} />
      <span>{english ? 'Code / structure inference' : '代码与结构推断'}</span>
      <StatusPill status="DYNAMIC_SUSPECTED" english={english} />
      <span>{english ? 'Runtime observation, not yet replay-confirmed' : '运行时观察，尚未重放确认'}</span>
      <StatusPill status="DYNAMIC_CONFIRMED" english={english} />
      <span>{english ? 'SQL malicious fragment stored unfiltered (MOCK, not production proof)' : 'SQL 恶意片段无过滤入库（MOCK，非生产证实）'}</span>
      <StatusPill status="VERIFIED" english={english} />
      <span>{english ? 'Hardened-sandbox replayable evidence only' : '仅限强化沙箱可重放证据'}</span>
    </section>
  )
}

export function PageHeader({ eyebrow, title, children, action }: { eyebrow: string; title: string; children: ReactNode; action?: ReactNode }) {
  return <header className="page-title"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{children}</p></div>{action}</header>
}

export function Notice({ kind = 'info', children }: { kind?: 'info' | 'error' | 'success'; children: ReactNode }) {
  return <div className={`notice notice-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>{children}</div>
}

export const errorMessage = (error: unknown, english = false) =>
  error instanceof Error ? error.message : (english ? 'Request unavailable' : '请求不可用')

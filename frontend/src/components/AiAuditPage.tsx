import type { DashboardSnapshot } from '../api'
import { AiAuditPanel } from './AiAuditPanel'
import { PageHeader } from './Common'

export function AiAuditPage({ projectId, snapshot }: { projectId: string; snapshot: DashboardSnapshot | null }) {
  return <section>
    <PageHeader eyebrow="AI AUDIT / EVENTS" title="AI 审计过程">
      查看模型请求、Provider 响应、工具调用、模型推断摘要及失败诊断；不记录或还原模型隐藏思维链。
    </PageHeader>
    <AiAuditPanel projectId={projectId} scanId={snapshot?.scanId} />
  </section>
}

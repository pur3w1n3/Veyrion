import type { DashboardSnapshot, OutputLanguage } from '../api'
import { AiAuditPanel } from './AiAuditPanel'
import { PageHeader } from './Common'

export function AiAuditPage({ projectId, snapshot, language }: { projectId: string; snapshot: DashboardSnapshot | null; language: OutputLanguage }) {
  const english = language === 'EN'
  return <section>
    <PageHeader eyebrow={english ? 'MODEL AUDIT' : '模型审计'} title={english ? 'Model audit process' : '模型审计过程'}>
      {english
        ? 'Inspect model requests, provider responses, tool calls, inference summaries, and failures. Hidden chain-of-thought is neither stored nor reconstructed.'
        : '查看模型请求、模型服务响应、工具调用、推断摘要及失败诊断；不记录或还原模型隐藏思维链。'}
    </PageHeader>
    <AiAuditPanel projectId={projectId} scanId={snapshot?.scanId} language={language} />
  </section>
}

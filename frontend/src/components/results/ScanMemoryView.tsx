import { useEffect, useState } from 'react'
import { api as defaultApi } from '../../api'
import { Notice } from '../Common'

type MemoryPayload = {
  schemaVersion?: number
  section?: string
  memory?: Record<string, unknown>
}

export function ScanMemoryView({
  api = defaultApi,
  scanId,
  english
}: {
  api?: typeof defaultApi
  scanId: string | null | undefined
  english: boolean
}) {
  const [section, setSection] = useState('FULL')
  const [payload, setPayload] = useState<MemoryPayload | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!scanId) {
      setPayload(null)
      return
    }
    let cancelled = false
    setLoading(true)
    setError(null)
    api.getScanAiMemory(scanId, section)
      .then((body) => {
        if (!cancelled) setPayload(body as MemoryPayload)
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setPayload(null)
          setError(err instanceof Error ? err.message : String(err))
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [api, scanId, section])

  if (!scanId) {
    return <Notice kind="info">{english ? 'Select a scan to inspect AI shared memory.' : '选择扫描后可查看 AI 共享记忆。'}</Notice>
  }

  const memory = payload?.memory ?? {}
  const counts = (memory.counts as Record<string, unknown> | undefined) ?? {}
  const tools = (memory.toolsCatalog as Array<Record<string, string>> | undefined)
    ?? ((memory as { toolsCatalog?: Array<Record<string, string>> }).toolsCatalog)

  return (
    <section className="scan-memory-view">
      <header className="scan-memory-view__header">
        <div>
          <h2>{english ? 'AI shared memory (read-only)' : 'AI 共享记忆（只读）'}</h2>
          <p>
            {english
              ? 'Same-scan FACTS / WORK / INFERENCE index used by the six AI roles. Models cannot write FACT.'
              : '同一次扫描内六个 AI 角色共用的事实/工作/推断索引。模型不能改写 FACT。'}
          </p>
        </div>
        <label>
          {english ? 'Section' : '切片'}
          <select value={section} onChange={(event) => setSection(event.target.value)}>
            {['FULL', 'INDEX', 'FACTS', 'WORK', 'INFERENCE', 'TOOLS_CATALOG', 'ROLE_SLICE'].map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>
        </label>
      </header>

      {loading && <Notice kind="info">{english ? 'Loading…' : '加载中…'}</Notice>}
      {error && <Notice kind="error">{error}</Notice>}

      {!loading && !error && (
        <>
          <div className="scan-memory-view__counts">
            {Object.entries(counts).map(([key, value]) => (
              <div key={key} className="scan-memory-view__count">
                <strong>{String(value)}</strong>
                <span>{key}</span>
              </div>
            ))}
          </div>

          {Array.isArray(tools) && tools.length > 0 && (
            <div className="scan-memory-view__tools">
              <h3>{english ? 'Tools (what they return)' : '工具说明（能拿到什么）'}</h3>
              <ul className="scan-memory-view__tool-list">
                {tools.map((tool) => (
                  <li key={tool.name} className="scan-memory-view__tool">
                    <header>
                      <code>{tool.name}</code>
                      <span>{tool.rolesZh ?? tool.roles ?? '—'}</span>
                    </header>
                    <p>{tool.purposeZh ?? tool.purpose ?? '—'}</p>
                    <dl>
                      <div>
                        <dt>{english ? 'Args' : '参数'}</dt>
                        <dd>{tool.argsZh ?? tool.args ?? '—'}</dd>
                      </div>
                      <div>
                        <dt>{english ? 'Returns' : '返回'}</dt>
                        <dd>{tool.returnsZh ?? tool.returns ?? '—'}</dd>
                      </div>
                    </dl>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <details open className="scan-memory-view__json">
            <summary>{english ? 'Raw JSON' : '原始 JSON'}</summary>
            <pre>{JSON.stringify(payload, null, 2)}</pre>
          </details>
        </>
      )}
    </section>
  )
}

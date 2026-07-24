import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, type AiJobDto, type AiRole, type ProviderDto, type ProviderKind, type ProviderModelInventoryDto, type RoleAssignmentDto } from '../api'
import { errorMessage, Notice, PageHeader } from './Common'

const roles: Array<{ id: AiRole; name: string; description: string }> = [
  { id: 'PRE_ANALYSIS', name: '预分析', description: '解释入口、业务对象与前置条件' },
  { id: 'PATH_EXPLORATION', name: '路径探索', description: '提出受策略约束的探索输入' },
  { id: 'VULNERABILITY_TRIAGE', name: '漏洞研判', description: '关联事实与证据，但不能单独确认漏洞' },
  { id: 'REPORT_GENERATION', name: '报告生成', description: '汇总证据等级、限制与未覆盖区域' }
]

const providerKindLabel = (kind: ProviderKind) => {
  if (kind === 'OPENAI_COMPATIBLE') return 'OPENAI_COMPATIBLE（旧类型兼容）'
  if (kind === 'AZURE_OPENAI') return 'AZURE_OPENAI（不支持模型清单）'
  if (kind === 'LOCAL') return 'LOCAL（旧类型兼容）'
  return kind
}

export function SettingsPage({ projectId, theme, onTheme }: { projectId: string; theme: 'light' | 'dark'; onTheme: () => void }) {
  const [providers, setProviders] = useState<ProviderDto[]>([])
  const [assignments, setAssignments] = useState<RoleAssignmentDto[]>([])
  const [jobs, setJobs] = useState<AiJobDto[]>([])
  const [inventories, setInventories] = useState<Record<string, ProviderModelInventoryDto>>({})
  const [roleProviders, setRoleProviders] = useState<Partial<Record<AiRole, string>>>({})
  const [loadingProvider, setLoadingProvider] = useState<string>()
  const [error, setError] = useState<string>()
  const [message, setMessage] = useState<string>()
  const keyRef = useRef<HTMLInputElement>(null)

  const refresh = async () => {
    setError(undefined)
    const results = await Promise.allSettled([
      api.listProviders(),
      projectId ? api.listRoleAssignments(projectId) : Promise.resolve([]),
      projectId ? api.listAiJobs(projectId) : Promise.resolve([])
    ])
    if (results[0].status === 'fulfilled') setProviders(results[0].value)
    if (results[1].status === 'fulfilled') {
      setAssignments(results[1].value)
      setRoleProviders(Object.fromEntries(results[1].value.map((item) => [item.role, item.providerId])))
    }
    if (results[2].status === 'fulfilled') setJobs(results[2].value)
    const rejected = results.find((item): item is PromiseRejectedResult => item.status === 'rejected')
    if (rejected) setError(errorMessage(rejected.reason))
  }

  useEffect(() => { void refresh() }, [projectId])

  const saveProvider = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    setError(undefined); setMessage(undefined)
    void api.createProvider({
      name: String(data.get('name')),
      kind: String(data.get('kind')) as ProviderKind,
      baseUrl: String(data.get('baseUrl') ?? '') || undefined,
      model: String(data.get('model') ?? '') || undefined,
      apiKey: String(data.get('apiKey') ?? '') || undefined,
      enabled: true
    }).then(async () => {
      setMessage('Provider 已由后端接受')
      form.reset()
      await refresh()
    }).catch((cause) => setError(errorMessage(cause))).finally(() => {
      if (keyRef.current) keyRef.current.value = ''
    })
  }

  const fetchModels = (providerId: string) => {
    setError(undefined); setMessage(undefined); setLoadingProvider(providerId)
    void api.refreshProviderModels(providerId).then((inventory) => {
      setInventories((current) => ({ ...current, [providerId]: inventory }))
      setMessage(`已获取 ${inventory.models.length} 个 inventory-only 模型；未自动启用或绑定`)
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setLoadingProvider(undefined))
  }

  const assign = (role: AiRole, providerId: string, providerModelName: string) => {
    if (!projectId || !providerId || !providerModelName) return
    setError(undefined)
    void api.saveRoleAssignment(projectId, role, { providerId, model: providerModelName })
      .then(refresh).catch((cause) => setError(errorMessage(cause)))
  }

  const startJob = (role: AiRole) => {
    if (!projectId) return
    if (!window.confirm('确认授权该 AI Job 使用当前项目已持久化、受限且可能发送至远端 Provider 的脱敏事实？')) return
    setError(undefined)
    void api.createAiJob(projectId, { role, authorized: true }).then(refresh).catch((cause) => setError(errorMessage(cause)))
  }

  return <section>
    <PageHeader eyebrow="SETTINGS / AI GOVERNANCE" title="全局设置">
      Provider 凭据仅随当前 HTTPS/API 请求提交，不写入 localStorage；AI 角色不能改变工具权限或证据等级。
    </PageHeader>
    {error && <Notice kind="error">{error}。对应后端路由 unavailable，界面未伪造保存结果。</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    <div className="settings-grid">
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">APPEARANCE & SAFETY</p><h2>通用</h2></div></div>
        <div className="setting-row"><div><strong>界面主题</strong><small>当前：{theme === 'light' ? '亮色' : '暗色'}；仅主题偏好持久化</small></div><button className="secondary-button" onClick={onTheme}>切换主题</button></div>
        <div className="setting-row"><div><strong>默认出站网络</strong><small>固定 DENY；前端不能放宽</small></div><span className="locked-tag">LOCKED</span></div>
        <div className="setting-row"><div><strong>危险动作</strong><small>固定 DRY_RUN / SIMULATE</small></div><span className="locked-tag">LOCKED</span></div>
      </article>
      <article className="panel">
        <div className="panel-head"><div><p className="eyebrow">PROVIDER</p><h2>新增模型服务</h2></div><span>{providers.length}</span></div>
        <form className="stack-form" onSubmit={saveProvider} autoComplete="off">
          <div className="form-grid"><label className="field"><span>名称</span><input required name="name" /></label><label className="field"><span>类型</span><select name="kind"><option>OPENAI_CHAT</option><option>ANTHROPIC_MESSAGES</option><option>OPENAI_COMPATIBLE</option><option>AZURE_OPENAI</option><option>LOCAL</option></select></label></div>
          <label className="field"><span>Base URL</span><input name="baseUrl" type="url" placeholder="由后端执行 allowlist 校验" /></label>
          <div className="form-grid"><label className="field"><span>默认模型</span><input name="model" /></label><label className="field"><span>API Key</span><input ref={keyRef} name="apiKey" type="password" autoComplete="new-password" /></label></div>
          <p className="form-help">提交成功或失败后，密钥输入都会立即清空。</p>
          <button className="primary-button">保存 Provider</button>
        </form>
        <div className="card-list section-gap">{providers.map((provider) => <div className="list-card" key={provider.providerId}><div><strong>{provider.name}</strong><small>{providerKindLabel(provider.kind)} · {provider.enabled ? '已启用' : '已禁用'} · {provider.hasCredential ? '凭据已配置' : '无凭据'}</small></div><button className="secondary-button" type="button" disabled={loadingProvider === provider.providerId || !provider.enabled || !provider.hasCredential || provider.kind === 'AZURE_OPENAI'} onClick={() => fetchModels(provider.providerId)}>{loadingProvider === provider.providerId ? '获取中…' : '获取模型'}</button></div>)}</div>
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">ROLE ASSIGNMENTS</p><h2>AI 四角色分配</h2></div><span>{projectId || 'NO PROJECT'}</span></div>
      <div className="role-grid">{roles.map((role) => {
        const assignment = assignments.find((item) => item.role === role.id)
        const selectedProvider = roleProviders[role.id] ?? assignment?.providerId ?? ''
        const inventoryModels = inventories[selectedProvider]?.models ?? []
        const assignedModel = assignment?.providerId === selectedProvider ? assignment.model : undefined
        const hasLegacyAssignment = assignedModel && !inventoryModels.some((item) => item.providerModelName === assignedModel)
        return <article className="role-card" key={role.id}><span>{role.id}</span><strong>{role.name}</strong><p>{role.description}</p><label className="field"><span>Provider</span><select value={selectedProvider} disabled={!projectId} onChange={(event) => setRoleProviders((current) => ({ ...current, [role.id]: event.target.value }))}><option value="">未分配</option>{providers.map((provider) => <option value={provider.providerId} key={provider.providerId}>{provider.name} · {providerKindLabel(provider.kind)}</option>)}</select></label><label className="field"><span>providerModelName</span><select value={assignedModel ?? ''} disabled={!projectId || !selectedProvider} onChange={(event) => assign(role.id, selectedProvider, event.target.value)}><option value="">{inventoryModels.length ? '选择 inventory-only 模型' : '请先获取模型'}</option>{hasLegacyAssignment && <option value={assignedModel}>{assignedModel}（旧绑定兼容）</option>}{inventoryModels.map((model) => <option value={model.providerModelName} key={model.modelId}>{model.providerModelName}</option>)}</select></label><button className="secondary-button" disabled={!assignment} onClick={() => startJob(role.id)}>创建 AI Job</button></article>
      })}</div>
    </article>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">AI JOBS</p><h2>任务队列</h2></div><button className="text-button" onClick={() => void refresh()}>刷新</button></div>
      <div className="card-list">{jobs.map((job) => <div className="list-card" key={job.aiJobId}><div><strong>{job.role}</strong><small>{job.aiJobId} · {job.createdAt}</small></div><span className="locked-tag">{job.status}</span></div>)}{jobs.length === 0 && <p className="empty-state">暂无 AI Job。</p>}</div>
    </article>
  </section>
}

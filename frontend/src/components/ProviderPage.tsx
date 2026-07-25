import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, type AiRole, type ProviderDto, type ProviderKind, type ProviderModelInventoryDto, type RoleAssignmentDto } from '../api'
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

export function ProviderPage({ projectId }: { projectId: string }) {
  const [providers, setProviders] = useState<ProviderDto[]>([])
  const [selectedProviderId, setSelectedProviderId] = useState<string>()
  const [assignments, setAssignments] = useState<RoleAssignmentDto[]>([])
  const [inventories, setInventories] = useState<Record<string, ProviderModelInventoryDto>>({})
  const [roleProviders, setRoleProviders] = useState<Partial<Record<AiRole, string>>>({})
  const [roleModels, setRoleModels] = useState<Partial<Record<AiRole, string>>>({})
  const [roleBusy, setRoleBusy] = useState<AiRole>()
  const [loadingProvider, setLoadingProvider] = useState<string>()
  const [error, setError] = useState<string>()
  const [message, setMessage] = useState<string>()
  const keyRef = useRef<HTMLInputElement>(null)

  const refresh = async () => {
    setError(undefined)
    const results = await Promise.allSettled([
      api.listProviders(),
      projectId ? api.listRoleAssignments(projectId) : Promise.resolve([])
    ])
    const providerResult = results[0]
    if (providerResult.status === 'fulfilled') {
      const availableProviders = providerResult.value
      setProviders(availableProviders)
      setSelectedProviderId((current) =>
        current && availableProviders.some((provider) => provider.providerId === current)
          ? current
          : availableProviders[0]?.providerId
      )
    }
    if (results[1].status === 'fulfilled') {
      setAssignments(results[1].value)
      setRoleProviders(Object.fromEntries(results[1].value.map((item) => [item.role, item.providerId])))
      setRoleModels(Object.fromEntries(results[1].value.map((item) => [item.role, item.model ?? ''])))
    }
    const rejected = results.find((item): item is PromiseRejectedResult => item.status === 'rejected')
    if (rejected) setError(errorMessage(rejected.reason))
  }

  useEffect(() => { void refresh() }, [projectId])

  const selectedProvider = providers.find((provider) => provider.providerId === selectedProviderId)

  const saveProvider = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    const request = {
      name: String(data.get('name')),
      kind: String(data.get('kind')) as ProviderKind,
      baseUrl: String(data.get('baseUrl') ?? '') || undefined,
      model: String(data.get('model') ?? '') || undefined,
      apiKey: String(data.get('apiKey') ?? '') || undefined,
      enabled: true
    }
    setError(undefined); setMessage(undefined)
    const operation = selectedProvider
      ? api.updateProvider(selectedProvider.providerId, request)
      : api.createProvider(request)
    void operation.then(async (saved) => {
      setSelectedProviderId(saved.providerId)
      setMessage(selectedProvider ? 'Provider 配置已更新' : 'Provider 已由后端接受')
      await refresh()
    }).catch((cause) => setError(errorMessage(cause))).finally(() => {
      if (keyRef.current) keyRef.current.value = ''
    })
  }

  const fetchModels = (providerId: string) => {
    setError(undefined); setMessage(undefined); setLoadingProvider(providerId)
    void api.refreshProviderModels(providerId).then((inventory) => {
      setInventories((current) => ({ ...current, [providerId]: inventory }))
      setMessage(`已获取 ${inventory.models.length} 个模型；清单不会自动改变角色绑定`)
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setLoadingProvider(undefined))
  }

  const removeProvider = () => {
    if (!selectedProvider || !window.confirm(`删除模型服务“${selectedProvider.name}”？已有角色绑定必须重新配置。`)) return
    setError(undefined); setMessage(undefined); setLoadingProvider(selectedProvider.providerId)
    void api.deleteProvider(selectedProvider.providerId).then(async () => {
      setSelectedProviderId(undefined)
      setMessage('Provider 已删除')
      await refresh()
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setLoadingProvider(undefined))
  }

  const saveAssignment = (role: AiRole, providerId: string, model: string) => {
    if (!projectId || !providerId || !model) return
    setError(undefined); setMessage(undefined); setRoleBusy(role)
    void api.saveRoleAssignment(projectId, role, { providerId, model })
      .then(async () => {
        setMessage(`${role} 角色绑定已保存；任务将由审计流程在对应阶段创建`)
        await refresh()
      })
      .catch((cause) => setError(errorMessage(cause)))
      .finally(() => setRoleBusy(undefined))
  }

  return <section>
    <PageHeader eyebrow="PROVIDERS / MODELS" title="模型服务" action={<button className="primary-button" type="button" onClick={() => {
      setSelectedProviderId(undefined)
      setError(undefined)
      setMessage(undefined)
    }}>新增模型服务</button>}>
      左侧选择后端已保存的 API，右侧维护连接与模型；这里只配置角色，不直接创建审计任务。
    </PageHeader>
    {error && <Notice kind="error">{error}。对应后端路由 unavailable，界面未伪造保存结果。</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    <div className="provider-layout">
      <aside className="panel provider-sidebar">
        <div className="panel-head"><div><p className="eyebrow">SAVED APIS</p><h2>已保存服务</h2></div><span>{providers.length}</span></div>
        <div className="provider-select-list">{providers.map((provider) => <button type="button" className={provider.providerId === selectedProviderId ? 'active' : ''} key={provider.providerId} onClick={() => setSelectedProviderId(provider.providerId)}><strong>{provider.name}</strong><small>{providerKindLabel(provider.kind)} · {provider.model ?? '未设默认模型'}</small><span>{provider.enabled && provider.hasCredential ? 'READY' : 'CHECK'}</span></button>)}{providers.length === 0 && <p className="empty-state">尚未保存模型服务。</p>}</div>
      </aside>
      <article className="panel provider-editor">
        <div className="panel-head"><div><p className="eyebrow">PROVIDER CONFIGURATION</p><h2>{selectedProvider ? `编辑 ${selectedProvider.name}` : '新增模型服务'}</h2></div>{selectedProvider && <button className="danger-button" type="button" onClick={removeProvider}>删除</button>}</div>
        <form className="stack-form" key={selectedProvider?.providerId ?? 'new'} onSubmit={saveProvider} autoComplete="off">
          <div className="form-grid"><label className="field"><span>名称</span><input required name="name" defaultValue={selectedProvider?.name} /></label><label className="field"><span>类型</span><select name="kind" defaultValue={selectedProvider?.kind ?? 'OPENAI_CHAT'}><option>OPENAI_CHAT</option><option>ANTHROPIC_MESSAGES</option><option>OPENAI_COMPATIBLE</option><option>AZURE_OPENAI</option><option>LOCAL</option></select></label></div>
          <label className="field"><span>Base URL</span><input name="baseUrl" type="url" defaultValue={selectedProvider?.baseUrl} placeholder="支持 http:// 或 https://" /></label>
          <div className="form-grid"><label className="field"><span>默认模型</span><input name="model" defaultValue={selectedProvider?.model} /></label><label className="field"><span>API Key</span><input ref={keyRef} name="apiKey" type="password" autoComplete="new-password" placeholder={selectedProvider?.hasCredential ? '留空则保留后端现有凭据' : '输入 API Key'} /></label></div>
          <p className="form-help">API Key 只提交到后端加密存储。非本机 HTTP 会明文传输模型数据，仅应连接受信内网网关。</p>
          <div className="button-row"><button className="primary-button">{selectedProvider ? '保存更改' : '保存 Provider'}</button>{selectedProvider && <button className="secondary-button" type="button" disabled={loadingProvider === selectedProvider.providerId || !selectedProvider.enabled || !selectedProvider.hasCredential || selectedProvider.kind === 'AZURE_OPENAI'} onClick={() => fetchModels(selectedProvider.providerId)}>{loadingProvider === selectedProvider.providerId ? '获取中…' : '获取模型清单'}</button>}</div>
        </form>
        {selectedProvider && inventories[selectedProvider.providerId] && <div className="model-inventory section-gap"><small>最近获取的模型</small><div>{inventories[selectedProvider.providerId].models.map((model) => <span key={model.modelId}>{model.providerModelName}</span>)}</div></div>}
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">ROLE ASSIGNMENTS</p><h2>AI 四角色分配</h2></div><span>{projectId || 'NO PROJECT'}</span></div>
      <p className="form-help">角色绑定是项目配置；AI Job 由“审计执行”按前置建模、路径探索、漏洞研判、报告生成的顺序创建。</p>
      <div className="role-grid">{roles.map((role) => {
        const assignment = assignments.find((item) => item.role === role.id)
        const selectedRoleProvider = roleProviders[role.id] ?? assignment?.providerId ?? ''
        const provider = providers.find((item) => item.providerId === selectedRoleProvider)
        const inventoryModels = inventories[selectedRoleProvider]?.models ?? []
        const assignedModel = assignment?.providerId === selectedRoleProvider ? assignment.model : undefined
        const modelDraft = roleModels[role.id] ?? assignedModel ?? provider?.model ?? ''
        const availableModels = Array.from(new Set([...(provider?.model ? [provider.model] : []), ...(assignedModel ? [assignedModel] : []), ...inventoryModels.map((item) => item.providerModelName)]))
        const listId = `models-${role.id.toLowerCase()}`
        return <article className="role-card" key={role.id}>
          <span>{role.id}</span><strong>{role.name}</strong><p>{role.description}</p>
          <label className="field"><span>Provider</span><select value={selectedRoleProvider} disabled={!projectId} onChange={(event) => {
            const nextProvider = event.target.value
            setRoleProviders((current) => ({ ...current, [role.id]: nextProvider }))
            setRoleModels((current) => ({ ...current, [role.id]: providers.find((item) => item.providerId === nextProvider)?.model ?? '' }))
          }}><option value="">未分配</option>{providers.map((item) => <option value={item.providerId} key={item.providerId}>{item.name} · {providerKindLabel(item.kind)}</option>)}</select></label>
          <label className="field"><span>模型（可搜索或输入）</span><input list={listId} value={modelDraft} disabled={!projectId || !selectedRoleProvider} placeholder={inventoryModels.length ? '搜索模型名称' : '输入 Provider 模型名称'} onChange={(event) => setRoleModels((current) => ({ ...current, [role.id]: event.target.value }))} /></label>
          <datalist id={listId}>{availableModels.map((model) => <option value={model} key={model} />)}</datalist>
          <button className="secondary-button" disabled={!projectId || !selectedRoleProvider || !modelDraft.trim() || roleBusy !== undefined} onClick={() => saveAssignment(role.id, selectedRoleProvider, modelDraft.trim())}>{roleBusy === role.id ? '保存中…' : '保存角色分配'}</button>
        </article>
      })}</div>
    </article>
  </section>
}

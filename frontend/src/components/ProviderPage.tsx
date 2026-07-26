import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, type AiRole, type ProviderDto, type ProviderKind, type ProviderModelInventoryDto, type RoleAssignmentDto } from '../api'
import { AI_ROLE_META, AI_ROLES, DEFAULT_ROLE_PROMPTS, roleLabel } from '../labels'
import { errorMessage, Notice, PageHeader } from './Common'

const providerKindLabel = (kind: ProviderKind) => {
  if (kind === 'OPENAI_CHAT') return 'OpenAI Chat 协议'
  if (kind === 'ANTHROPIC_MESSAGES') return 'Anthropic Messages 协议'
  if (kind === 'OPENAI_COMPATIBLE') return 'OpenAI 兼容（旧类型）'
  if (kind === 'AZURE_OPENAI') return 'Azure OpenAI（不支持模型清单）'
  if (kind === 'LOCAL') return '本地（旧类型兼容）'
  return kind
}

export function ProviderPage({ projectId }: { projectId: string }) {
  const [providers, setProviders] = useState<ProviderDto[]>([])
  const [selectedProviderId, setSelectedProviderId] = useState<string>()
  const [assignments, setAssignments] = useState<RoleAssignmentDto[]>([])
  const [inventories, setInventories] = useState<Record<string, ProviderModelInventoryDto>>({})
  const [roleProviders, setRoleProviders] = useState<Partial<Record<AiRole, string>>>({})
  const [roleModels, setRoleModels] = useState<Partial<Record<AiRole, string>>>({})
  const [rolePrompts, setRolePrompts] = useState<Partial<Record<AiRole, { zh: string; en: string }>>>({})
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
      setRolePrompts(Object.fromEntries(results[1].value.map((item) => [item.role, {
        zh: item.promptZh ?? DEFAULT_ROLE_PROMPTS[item.role].zh,
        en: item.promptEn ?? DEFAULT_ROLE_PROMPTS[item.role].en
      }])))
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
      setMessage(selectedProvider ? '模型服务配置已更新' : '模型服务已由后端接受')
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
      setMessage('模型服务已删除')
      await refresh()
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setLoadingProvider(undefined))
  }

  const saveAssignment = (role: AiRole, providerId: string, model: string) => {
    if (!projectId || !providerId || !model) return
    setError(undefined); setMessage(undefined); setRoleBusy(role)
    const prompts = rolePrompts[role] ?? DEFAULT_ROLE_PROMPTS[role]
    void api.saveRoleAssignment(projectId, role, { providerId, model, promptZh: prompts.zh, promptEn: prompts.en })
      .then(async () => {
        setMessage(`「${roleLabel(role)}」角色绑定已保存；任务将由审计流程在对应阶段创建`)
        await refresh()
      })
      .catch((cause) => setError(errorMessage(cause)))
      .finally(() => setRoleBusy(undefined))
  }

  return <section>
    <PageHeader eyebrow="模型服务" title="模型服务" action={<button className="primary-button" type="button" onClick={() => {
      setSelectedProviderId(undefined)
      setError(undefined)
      setMessage(undefined)
    }}>新增模型服务</button>}>
      左侧选择后端已保存的接口，右侧维护连接与模型；这里只配置角色，不直接创建审计任务。
    </PageHeader>
    {error && <Notice kind="error">{error}。对应后端路由不可用，界面未伪造保存结果。</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    <div className="provider-layout">
      <aside className="panel provider-sidebar">
        <div className="panel-head"><div><p className="eyebrow">已保存</p><h2>已保存服务</h2></div><span>{providers.length}</span></div>
        <div className="provider-select-list">{providers.map((provider) => <button type="button" className={provider.providerId === selectedProviderId ? 'active' : ''} key={provider.providerId} onClick={() => setSelectedProviderId(provider.providerId)}><strong>{provider.name}</strong><small>{providerKindLabel(provider.kind)} · {provider.model ?? '未设默认模型'}</small><span>{provider.enabled && provider.hasCredential ? '就绪' : '待检查'}</span></button>)}{providers.length === 0 && <p className="empty-state">尚未保存模型服务。</p>}</div>
      </aside>
      <article className="panel provider-editor">
        <div className="panel-head"><div><p className="eyebrow">连接配置</p><h2>{selectedProvider ? `编辑 ${selectedProvider.name}` : '新增模型服务'}</h2></div>{selectedProvider && <button className="danger-button" type="button" onClick={removeProvider}>删除</button>}</div>
        <form className="stack-form" key={selectedProvider?.providerId ?? 'new'} onSubmit={saveProvider} autoComplete="off">
          <div className="form-grid"><label className="field"><span>名称</span><input required name="name" defaultValue={selectedProvider?.name} /></label><label className="field"><span>协议类型</span><select name="kind" defaultValue={selectedProvider?.kind ?? 'OPENAI_CHAT'}><option value="OPENAI_CHAT">OpenAI Chat 协议</option><option value="ANTHROPIC_MESSAGES">Anthropic Messages 协议</option><option value="OPENAI_COMPATIBLE">OpenAI 兼容（旧类型）</option><option value="AZURE_OPENAI">Azure OpenAI</option><option value="LOCAL">本地（旧类型）</option></select></label></div>
          <label className="field"><span>服务地址</span><input name="baseUrl" type="url" defaultValue={selectedProvider?.baseUrl} placeholder="支持 http:// 或 https://" /></label>
          <div className="form-grid"><label className="field"><span>默认模型</span><input name="model" defaultValue={selectedProvider?.model} /></label><label className="field"><span>访问密钥</span><input ref={keyRef} name="apiKey" type="password" autoComplete="new-password" placeholder={selectedProvider?.hasCredential ? '留空则保留后端现有凭据' : '输入访问密钥'} /></label></div>
          <p className="form-help">访问密钥只提交到后端加密存储。非本机 HTTP 会明文传输模型数据，仅应连接受信内网网关。</p>
          <div className="button-row"><button className="primary-button">{selectedProvider ? '保存更改' : '保存模型服务'}</button>{selectedProvider && <button className="secondary-button" type="button" disabled={loadingProvider === selectedProvider.providerId || !selectedProvider.enabled || !selectedProvider.hasCredential || selectedProvider.kind === 'AZURE_OPENAI'} onClick={() => fetchModels(selectedProvider.providerId)}>{loadingProvider === selectedProvider.providerId ? '获取中…' : '获取模型清单'}</button>}</div>
        </form>
        {selectedProvider && inventories[selectedProvider.providerId] && <div className="model-inventory section-gap"><small>最近获取的模型</small><div>{inventories[selectedProvider.providerId].models.map((model) => <span key={model.modelId}>{model.providerModelName}</span>)}</div></div>}
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">角色分配</p><h2>五个模型角色</h2></div><span>{projectId || '未选择工作区'}</span></div>
      <p className="form-help">角色绑定是项目配置；可分别编辑中文与英文提示词。审计任务按前置建模 → 动态验证 → 路径探索 → 漏洞研判 → 报告生成顺序创建，服务端会把提示词快照写入任务。</p>
      <div className="role-grid">{AI_ROLES.map((roleId) => {
        const role = AI_ROLE_META[roleId]
        const assignment = assignments.find((item) => item.role === roleId)
        const selectedRoleProvider = roleProviders[roleId] ?? assignment?.providerId ?? ''
        const provider = providers.find((item) => item.providerId === selectedRoleProvider)
        const inventoryModels = inventories[selectedRoleProvider]?.models ?? []
        const assignedModel = assignment?.providerId === selectedRoleProvider ? assignment.model : undefined
        const modelDraft = roleModels[roleId] ?? assignedModel ?? provider?.model ?? ''
        const promptDraft = rolePrompts[roleId] ?? {
          zh: assignment?.promptZh ?? DEFAULT_ROLE_PROMPTS[roleId].zh,
          en: assignment?.promptEn ?? DEFAULT_ROLE_PROMPTS[roleId].en
        }
        const availableModels = Array.from(new Set([...(provider?.model ? [provider.model] : []), ...(assignedModel ? [assignedModel] : []), ...inventoryModels.map((item) => item.providerModelName)]))
        const listId = `models-${roleId.toLowerCase()}`
        return <article className="role-card" key={roleId}>
          <span>{role.name}</span><strong>{role.name}</strong><p>{role.description}</p>
          <label className="field"><span>模型服务</span><select value={selectedRoleProvider} disabled={!projectId} onChange={(event) => {
            const nextProvider = event.target.value
            setRoleProviders((current) => ({ ...current, [roleId]: nextProvider }))
            setRoleModels((current) => ({ ...current, [roleId]: providers.find((item) => item.providerId === nextProvider)?.model ?? '' }))
          }}><option value="">未分配</option>{providers.map((item) => <option value={item.providerId} key={item.providerId}>{item.name} · {providerKindLabel(item.kind)}</option>)}</select></label>
          <label className="field"><span>模型（可搜索或输入）</span><input list={listId} value={modelDraft} disabled={!projectId || !selectedRoleProvider} placeholder={inventoryModels.length ? '搜索模型名称' : '输入模型名称'} onChange={(event) => setRoleModels((current) => ({ ...current, [roleId]: event.target.value }))} /></label>
          <datalist id={listId}>{availableModels.map((model) => <option value={model} key={model} />)}</datalist>
          <label className="field"><span>中文提示词</span><textarea className="prompt-editor" rows={5} value={promptDraft.zh} disabled={!projectId} onChange={(event) => setRolePrompts((current) => ({ ...current, [roleId]: { ...promptDraft, zh: event.target.value } }))} /></label>
          <label className="field"><span>English prompt</span><textarea className="prompt-editor" rows={5} value={promptDraft.en} disabled={!projectId} onChange={(event) => setRolePrompts((current) => ({ ...current, [roleId]: { ...promptDraft, en: event.target.value } }))} /></label>
          <button className="secondary-button" disabled={!projectId || !selectedRoleProvider || !modelDraft.trim() || roleBusy !== undefined} onClick={() => saveAssignment(roleId, selectedRoleProvider, modelDraft.trim())}>{roleBusy === roleId ? '保存中…' : '保存角色分配'}</button>
        </article>
      })}</div>
    </article>
  </section>
}

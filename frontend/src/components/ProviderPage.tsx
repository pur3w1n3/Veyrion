import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, type AiRole, type ProviderDto, type ProviderKind, type ProviderModelInventoryDto, type ProtocolDetectResultDto, type RoleAssignmentDto } from '../api'
import { AI_ROLE_META, AI_ROLES, DEFAULT_ROLE_PROMPTS, roleLabel } from '../labels'
import { providerKindLabel, viableCandidates } from '../providerKindInfer'
import { errorMessage, Notice, PageHeader } from './Common'

const ALL_KINDS: ProviderKind[] = [
  'OPENAI_CHAT',
  'ANTHROPIC_MESSAGES',
  'OPENAI_COMPATIBLE',
  'AZURE_OPENAI',
  'LOCAL'
]

export function ProviderPage({ projectId, english = false }: { projectId: string; english?: boolean }) {
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
  const [name, setName] = useState('')
  const [kind, setKind] = useState<ProviderKind>('OPENAI_CHAT')
  const [baseUrl, setBaseUrl] = useState('')
  const [model, setModel] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [detecting, setDetecting] = useState(false)
  const [detection, setDetection] = useState<ProtocolDetectResultDto>()
  const [detectError, setDetectError] = useState<string>()
  const keyRef = useRef<HTMLInputElement>(null)
  const detectGen = useRef(0)
  const kindManualRef = useRef(false)

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

  useEffect(() => {
    setName(selectedProvider?.name ?? '')
    setKind(selectedProvider?.kind ?? 'OPENAI_CHAT')
    setBaseUrl(selectedProvider?.baseUrl ?? '')
    setModel(selectedProvider?.model ?? '')
    setApiKey('')
    kindManualRef.current = false
    setDetection(undefined)
    setDetectError(undefined)
    setDetecting(false)
    detectGen.current += 1
  }, [selectedProvider?.providerId])

  const trimmedBaseUrl = baseUrl.trim()
  const trimmedApiKey = apiKey.trim()
  const canReuseStoredCredential = Boolean(selectedProvider?.hasCredential) && trimmedApiKey.length === 0
  const canDetectProtocol = trimmedBaseUrl.length > 0
    && (trimmedApiKey.length > 0 || canReuseStoredCredential)

  const detectProtocol = () => {
    if (!canDetectProtocol || detecting) return
    const generation = ++detectGen.current
    setDetecting(true)
    setDetectError(undefined)
    setDetection(undefined)
    const request = {
      baseUrl: trimmedBaseUrl,
      ...(trimmedApiKey.length > 0
        ? { apiKey: trimmedApiKey }
        : { providerId: selectedProvider!.providerId })
    }
    void api.detectProviderProtocol(request).then((result) => {
      if (generation !== detectGen.current) return
      setDetection(result)
      setDetecting(false)
      if (!kindManualRef.current && result.recommendedKind
          && (result.status === 'UNIQUE' || result.status === 'MULTIPLE')) {
        setKind(result.recommendedKind)
      }
    }).catch((cause) => {
      if (generation !== detectGen.current) return
      setDetecting(false)
      setDetection(undefined)
      setDetectError(errorMessage(cause))
    })
  }

  const saveProvider = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const request = {
      name: name.trim(),
      kind,
      baseUrl: baseUrl.trim() || undefined,
      model: model.trim() || undefined,
      apiKey: apiKey.trim() || undefined,
      enabled: true
    }
    setError(undefined); setMessage(undefined)
    const operation = selectedProvider
      ? api.updateProvider(selectedProvider.providerId, request)
      : api.createProvider(request)
    void operation.then(async (saved) => {
      setSelectedProviderId(saved.providerId)
      setMessage(selectedProvider
        ? (english ? 'Provider settings updated' : '模型服务配置已更新')
        : (english ? 'Provider accepted by the control plane' : '模型服务已由后端接受'))
      setApiKey('')
      await refresh()
    }).catch((cause) => setError(errorMessage(cause))).finally(() => {
      if (keyRef.current) keyRef.current.value = ''
    })
  }

  const fetchModels = (providerId: string) => {
    setError(undefined); setMessage(undefined); setLoadingProvider(providerId)
    void api.refreshProviderModels(providerId).then((inventory) => {
      setInventories((current) => ({ ...current, [providerId]: inventory }))
      setMessage(english
        ? `Fetched ${inventory.models.length} models; inventory does not change role bindings`
        : `已获取 ${inventory.models.length} 个模型；清单不会自动改变角色绑定`)
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setLoadingProvider(undefined))
  }

  const removeProvider = () => {
    if (!selectedProvider || !window.confirm(english
      ? `Delete provider “${selectedProvider.name}”? Existing role bindings must be reconfigured.`
      : `删除模型服务“${selectedProvider.name}”？已有角色绑定必须重新配置。`)) return
    setError(undefined); setMessage(undefined); setLoadingProvider(selectedProvider.providerId)
    void api.deleteProvider(selectedProvider.providerId).then(async () => {
      setSelectedProviderId(undefined)
      setMessage(english ? 'Provider deleted' : '模型服务已删除')
      await refresh()
    }).catch((cause) => setError(errorMessage(cause))).finally(() => setLoadingProvider(undefined))
  }

  const saveAssignment = (role: AiRole, providerId: string, modelName: string) => {
    if (!projectId || !providerId || !modelName) return
    setError(undefined); setMessage(undefined); setRoleBusy(role)
    const prompts = rolePrompts[role] ?? DEFAULT_ROLE_PROMPTS[role]
    void api.saveRoleAssignment(projectId, role, { providerId, model: modelName, promptZh: prompts.zh, promptEn: prompts.en })
      .then(async () => {
        setMessage(english
          ? `“${roleLabel(role, true)}” role binding saved; jobs are created by the audit pipeline at the matching stage`
          : `「${roleLabel(role)}」角色绑定已保存；任务将由审计流程在对应阶段创建`)
        await refresh()
      })
      .catch((cause) => setError(errorMessage(cause)))
      .finally(() => setRoleBusy(undefined))
  }

  const viable = detection ? viableCandidates(detection) : []

  return <section>
    <PageHeader eyebrow={english ? 'MODEL PROVIDERS' : '模型服务'} title={english ? 'Model providers' : '模型服务'} action={<button className="primary-button" type="button" onClick={() => {
      setSelectedProviderId(undefined)
      setError(undefined)
      setMessage(undefined)
    }}>{english ? 'Add provider' : '新增模型服务'}</button>}>
      {english
        ? 'Select a saved API on the left; configure connection and models on the right. Roles are bound here — audit jobs are not created from this page.'
        : '左侧选择后端已保存的接口，右侧维护连接与模型；这里只配置角色，不直接创建审计任务。'}
    </PageHeader>
    {error && <Notice kind="error">{error}{english ? '. Matching backend routes are unavailable; the UI did not forge a save result.' : '。对应后端路由不可用，界面未伪造保存结果。'}</Notice>}
    {message && <Notice kind="success">{message}</Notice>}
    <div className="provider-layout">
      <aside className="panel provider-sidebar">
        <div className="panel-head"><div><p className="eyebrow">{english ? 'SAVED' : '已保存'}</p><h2>{english ? 'Saved providers' : '已保存服务'}</h2></div><span>{providers.length}</span></div>
        <div className="provider-select-list">{providers.map((provider) => <button type="button" className={provider.providerId === selectedProviderId ? 'active' : ''} key={provider.providerId} onClick={() => setSelectedProviderId(provider.providerId)}><strong>{provider.name}</strong><small>{providerKindLabel(provider.kind, english)} · {provider.model ?? (english ? 'No default model' : '未设默认模型')}</small><span>{provider.enabled && provider.hasCredential ? (english ? 'Ready' : '就绪') : (english ? 'Check' : '待检查')}</span></button>)}{providers.length === 0 && <p className="empty-state">{english ? 'No providers saved yet.' : '尚未保存模型服务。'}</p>}</div>
      </aside>
      <article className="panel provider-editor">
        <div className="panel-head"><div><p className="eyebrow">{english ? 'CONNECTION' : '连接配置'}</p><h2>{selectedProvider ? (english ? `Edit ${selectedProvider.name}` : `编辑 ${selectedProvider.name}`) : (english ? 'Add provider' : '新增模型服务')}</h2></div>{selectedProvider && <button className="danger-button" type="button" onClick={removeProvider}>{english ? 'Delete' : '删除'}</button>}</div>
        <form className="stack-form" onSubmit={saveProvider} autoComplete="off">
          <div className="form-grid">
            <label className="field"><span>{english ? 'Name' : '名称'}</span><input required name="name" value={name} onChange={(event) => setName(event.target.value)} /></label>
            <div className="field protocol-kind-field">
              <span>{english ? 'Protocol' : '协议类型'}</span>
              <div className="protocol-kind-row">
                <select name="kind" value={kind} onChange={(event) => {
                  kindManualRef.current = true
                  setKind(event.target.value as ProviderKind)
                }}>
                  {ALL_KINDS.map((item) => <option value={item} key={item}>{providerKindLabel(item, english)}</option>)}
                </select>
                <button
                  className="secondary-button"
                  type="button"
                  disabled={!canDetectProtocol || detecting}
                  onClick={detectProtocol}
                  title={!canDetectProtocol
                    ? (english
                      ? 'Enter a base URL and API key (or keep a stored credential) before probing'
                      : '请先填写服务地址，并输入访问密钥（或使用已保存凭据）')
                    : undefined}
                >{detecting
                  ? (english ? 'Detecting…' : '探测中…')
                  : (english ? 'Detect protocol' : '协议探测')}</button>
              </div>
            </div>
          </div>
          <label className="field"><span>{english ? 'Base URL' : '服务地址'}</span><input name="baseUrl" type="url" value={baseUrl} onChange={(event) => {
            kindManualRef.current = false
            detectGen.current += 1
            setDetecting(false)
            setBaseUrl(event.target.value)
            setDetection(undefined)
            setDetectError(undefined)
          }} placeholder={english ? 'http:// or https://' : '支持 http:// 或 https://'} /></label>
          <div className="form-grid">
            <label className="field"><span>{english ? 'Default model' : '默认模型'}</span><input name="model" value={model} onChange={(event) => setModel(event.target.value)} /></label>
            <label className="field"><span>{english ? 'API key' : '访问密钥'}</span><input ref={keyRef} name="apiKey" type="password" autoComplete="new-password" value={apiKey} onChange={(event) => {
              kindManualRef.current = false
              detectGen.current += 1
              setDetecting(false)
              setApiKey(event.target.value)
              setDetection(undefined)
              setDetectError(undefined)
            }} placeholder={selectedProvider?.hasCredential ? (english ? 'Leave blank to keep stored credential' : '留空则保留后端现有凭据') : (english ? 'Enter API key' : '输入访问密钥')} /></label>
          </div>
          <div className="protocol-detect" aria-live="polite">
            {detecting && <p className="form-help protocol-detect-status">{english
              ? 'Probing protocols with a bounded models request…'
              : '正在用有界模型清单请求探测可用协议…'}</p>}
            {!detecting && detectError && <p className="form-help protocol-detect-status is-error">{english
              ? `Protocol probe failed: ${detectError}. You can still choose a protocol and save.`
              : `协议探测失败：${detectError}。仍可手动选择协议并保存。`}</p>}
            {!detecting && !detectError && detection?.status === 'NONE' && <p className="form-help protocol-detect-status is-error">{english
              ? 'No protocol accepted the probe. You can still choose a protocol and save.'
              : '探测未确认任何可用协议。仍可手动选择协议并保存。'}{detection.hint === 'AZURE_OPENAI_MANUAL'
              ? (english ? ' Host looks like Azure OpenAI — select Azure manually if that is the target.' : ' 主机名像 Azure OpenAI，若确认为该服务请手动选择。')
              : ''}</p>}
            {!detecting && viable.length > 0 && (
              <div className="protocol-detect-options">
                <small>{english
                  ? (detection?.status === 'UNIQUE' ? 'Probe confirmed one protocol (editable)' : 'Probe confirmed multiple protocols — pick one')
                  : (detection?.status === 'UNIQUE' ? '探测确认唯一协议（仍可改）' : '探测确认多种协议 — 请点选')}</small>
                <div className="protocol-detect-chips">
                  {viable.map((candidate, index) => (
                    <button
                      type="button"
                      key={candidate.kind}
                      className={`protocol-chip${kind === candidate.kind ? ' active' : ''}${index === 0 ? ' recommended' : ''}`}
                      onClick={() => {
                        kindManualRef.current = true
                        setKind(candidate.kind)
                      }}
                      title={candidate.detail}
                    >
                      {providerKindLabel(candidate.kind, english)}
                      {index === 0 && <em>{english ? 'Recommended' : '推荐'}</em>}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
          <p className="form-help">{english
            ? 'Keys are submitted only for backend encrypted storage and short protocol probes. Non-loopback HTTP sends model data in cleartext — use a trusted gateway.'
            : '访问密钥只提交到后端加密存储与短时协议探测。非本机 HTTP 会明文传输模型数据，仅应连接受信内网网关。'}</p>
          <div className="button-row"><button className="primary-button">{selectedProvider ? (english ? 'Save changes' : '保存更改') : (english ? 'Save provider' : '保存模型服务')}</button>{selectedProvider && <button className="secondary-button" type="button" disabled={loadingProvider === selectedProvider.providerId || !selectedProvider.enabled || !selectedProvider.hasCredential || selectedProvider.kind === 'AZURE_OPENAI'} onClick={() => fetchModels(selectedProvider.providerId)}>{loadingProvider === selectedProvider.providerId ? (english ? 'Fetching…' : '获取中…') : (english ? 'Fetch model list' : '获取模型清单')}</button>}</div>
        </form>
        {selectedProvider && inventories[selectedProvider.providerId] && <div className="model-inventory section-gap"><small>{english ? 'Recently fetched models' : '最近获取的模型'}</small><div>{inventories[selectedProvider.providerId].models.map((item) => <span key={item.modelId}>{item.providerModelName}</span>)}</div></div>}
      </article>
    </div>
    <article className="panel section-gap">
      <div className="panel-head"><div><p className="eyebrow">{english ? 'ROLE BINDINGS' : '角色分配'}</p><h2>{english ? 'Six model roles' : '六个模型角色'}</h2></div><span>{projectId || (english ? 'No workspace' : '未选择工作区')}</span></div>
      <p className="form-help">{english
        ? 'Role bindings are project settings; Chinese and English prompts can be edited separately. The pipeline advances pre-analysis → auth → dynamic observation → bypass confirm → dynamic verification → path exploration → triage → report; the server snapshots prompts onto each job.'
        : '角色绑定是项目配置；可分别编辑中文与英文提示词。审计任务按前置建模 → 鉴权分析 → 动态观察 → 绕过确认 → 动态验证 → 路径探索 → 漏洞研判 → 报告生成顺序推进，服务端会把提示词快照写入任务。'}</p>
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
        return <article className="role-card" data-role={roleId} key={roleId}>
          <header className="role-card-head">
            <span className="role-card-chip">{english ? role.chipEn : role.chip}</span>
            <strong>{english ? role.nameEn : role.name}</strong>
          </header>
          <p>{english ? role.descriptionEn : role.description}</p>
          <label className="field"><span>{english ? 'Provider' : '模型服务'}</span><select value={selectedRoleProvider} disabled={!projectId} onChange={(event) => {
            const nextProvider = event.target.value
            setRoleProviders((current) => ({ ...current, [roleId]: nextProvider }))
            setRoleModels((current) => ({ ...current, [roleId]: providers.find((item) => item.providerId === nextProvider)?.model ?? '' }))
          }}><option value="">{english ? 'Unassigned' : '未分配'}</option>{providers.map((item) => <option value={item.providerId} key={item.providerId}>{item.name} · {providerKindLabel(item.kind, english)}</option>)}</select></label>
          <label className="field"><span>{english ? 'Model (search or type)' : '模型（可搜索或输入）'}</span><input list={listId} value={modelDraft} disabled={!projectId || !selectedRoleProvider} placeholder={inventoryModels.length ? (english ? 'Search model name' : '搜索模型名称') : (english ? 'Enter model name' : '输入模型名称')} onChange={(event) => setRoleModels((current) => ({ ...current, [roleId]: event.target.value }))} /></label>
          <datalist id={listId}>{availableModels.map((item) => <option value={item} key={item} />)}</datalist>
          <label className="field"><span>{english ? 'Chinese prompt' : '中文提示词'}</span><textarea className="prompt-editor" rows={4} value={promptDraft.zh} disabled={!projectId} onChange={(event) => setRolePrompts((current) => ({ ...current, [roleId]: { ...promptDraft, zh: event.target.value } }))} /></label>
          <label className="field"><span>English prompt</span><textarea className="prompt-editor" rows={4} value={promptDraft.en} disabled={!projectId} onChange={(event) => setRolePrompts((current) => ({ ...current, [roleId]: { ...promptDraft, en: event.target.value } }))} /></label>
          <button className="secondary-button" disabled={!projectId || !selectedRoleProvider || !modelDraft.trim() || roleBusy !== undefined} onClick={() => saveAssignment(roleId, selectedRoleProvider, modelDraft.trim())}>{roleBusy === roleId ? (english ? 'Saving…' : '保存中…') : (english ? 'Save role binding' : '保存角色分配')}</button>
        </article>
      })}</div>
    </article>
  </section>
}

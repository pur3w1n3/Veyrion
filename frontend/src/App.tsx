import { useCallback, useEffect, useState } from 'react'
import { api, type DashboardSnapshot, type OutputLanguage, type ProjectDto } from './api'
import { AiAuditPage } from './components/AiAuditPage'
import { AuditPage } from './components/AuditPage'
import { BoundaryLegend, Notice, errorMessage } from './components/Common'
import { ProviderPage } from './components/ProviderPage'
import { ResultsPage } from './components/ResultsPage'
import { SettingsPage } from './components/SettingsPage'
import { AuditHistoryPage } from './components/AuditHistoryPage'
import { WorkspacesHomePage } from './components/WorkspacesHomePage'
import { dependencyModeLabel } from './labels'

type View = 'workspaces' | 'audit' | 'history' | 'ai-audit' | 'results' | 'providers' | 'settings'
type Theme = 'light' | 'dark'

const navFor = (english: boolean): Array<{ id: View; label: string; description: string; icon: string }> => [
  { id: 'workspaces', label: english ? 'Workspaces' : '工作区', description: english ? 'Switch, create, delete' : '格子切换、新建与删除', icon: '▦' },
  { id: 'audit', label: english ? 'Audit run' : '审计执行', description: english ? 'Artifact import & pipeline' : '制品导入与自动流水线', icon: '◎' },
  { id: 'ai-audit', label: english ? 'Audit dialogue' : '审计过程', description: english ? 'Prompts, thinking, outputs' : '提示词、思考与输出对话', icon: '≋' },
  { id: 'results', label: english ? 'Audit results' : '审计结果', description: english ? 'Final report & evidence views' : '最终报告与证据子页', icon: '◇' },
  { id: 'history', label: english ? 'Audit history' : '审计历史', description: english ? 'All scans in this workspace' : '本工作区全部扫描记录', icon: '☰' },
  { id: 'providers', label: english ? 'Model providers' : '模型服务', description: english ? 'API config & six roles' : '接口配置与六个角色', icon: '◈' },
  { id: 'settings', label: english ? 'Settings' : '全局设置', description: english ? 'Appearance & defaults' : '外观与安全默认值', icon: '⚙' }
]

const initialTheme = (): Theme => {
  try { return localStorage.getItem('veyrion.theme') === 'dark' ? 'dark' : 'light' } catch { return 'light' }
}

const initialLanguage = (): OutputLanguage => {
  try { return localStorage.getItem('veyrion.language') === 'EN' ? 'EN' : 'ZH_CN' } catch { return 'ZH_CN' }
}

const initialProjectId = (): string => {
  const fromEnv = import.meta.env.VITE_PROJECT_ID
  if (typeof fromEnv === 'string' && fromEnv.trim()) return fromEnv.trim()
  try { return localStorage.getItem('veyrion.projectId') ?? '' } catch { return '' }
}

export default function App() {
  const [view, setView] = useState<View>('workspaces')
  const [theme, setTheme] = useState<Theme>(initialTheme)
  const [language, setLanguage] = useState<OutputLanguage>(initialLanguage)
  const [projects, setProjects] = useState<ProjectDto[]>([])
  const [projectId, setProjectId] = useState(initialProjectId)
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [focusedScanId, setFocusedScanId] = useState<string>()
  const [projectApiError, setProjectApiError] = useState<string>()
  const [dashboardApiError, setDashboardApiError] = useState<string>()

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('veyrion.theme', theme) } catch { /* Theme still applies for this session. */ }
    const color = theme === 'light' ? '#f6f8fc' : '#09111f'
    document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute('content', color)
  }, [theme])

  useEffect(() => {
    document.documentElement.lang = language === 'ZH_CN' ? 'zh-CN' : 'en'
    try { localStorage.setItem('veyrion.language', language) } catch { /* Language still applies for this session. */ }
  }, [language])

  useEffect(() => {
    try {
      if (projectId) localStorage.setItem('veyrion.projectId', projectId)
      else localStorage.removeItem('veyrion.projectId')
    } catch { /* Selection still applies for this session. */ }
  }, [projectId])

  const refreshProjects = useCallback(async () => {
    try {
      const next = await api.listProjects()
      setProjects(next)
      setProjectApiError(undefined)
      // Keep an explicit selection only; never auto-switch to the first workspace on load.
      setProjectId((current) =>
        current && next.some((project) => project.projectId === current) ? current : ''
      )
    } catch (cause) {
      setProjectApiError(errorMessage(cause))
    }
  }, [])

  const refreshDashboard = useCallback(async () => {
    if (!projectId) { setSnapshot(null); return }
    try {
      setSnapshot(await api.loadDashboard(projectId, focusedScanId))
      setDashboardApiError(undefined)
    } catch (cause) {
      setSnapshot(null)
      setDashboardApiError(errorMessage(cause))
    }
  }, [projectId, focusedScanId])

  useEffect(() => { void refreshProjects() }, [refreshProjects])
  useEffect(() => { setFocusedScanId(undefined) }, [projectId])
  useEffect(() => { void refreshDashboard() }, [refreshDashboard])

  // Results view is not mounted with useAuditLiveRefresh; keep path runs / findings fresh here.
  // SSE triggers GET reconcile; bounded polling covers stages that emit no scan events.
  useEffect(() => {
    const scanId = focusedScanId ?? (snapshot?.scanId && snapshot.scanId !== 'unscanned' ? snapshot.scanId : undefined)
    if (!projectId || !scanId || view !== 'results') return

    let closed = false
    let timer: number | undefined
    const terminal = new Set(['COMPLETED', 'FAILED', 'CANCELLED'])

    const schedule = (delayMs: number) => {
      if (closed || timer !== undefined) return
      timer = window.setTimeout(() => {
        timer = undefined
        void tick()
      }, delayMs)
    }

    const tick = async () => {
      if (closed) return
      try {
        const scan = await api.getScan(scanId)
        if (closed) return
        await refreshDashboard()
        if (!terminal.has(scan.status)) schedule(2000)
      } catch {
        if (!closed) schedule(3000)
      }
    }

    const unsubscribe = api.subscribe(scanId, () => undefined, {
      onReconcile: (scan) => {
        if (closed) return
        void refreshDashboard().finally(() => {
          if (!closed && !terminal.has(scan.status)) schedule(2000)
        })
      }
    })
    schedule(1500)

    return () => {
      closed = true
      if (timer !== undefined) window.clearTimeout(timer)
      unsubscribe()
    }
  }, [projectId, focusedScanId, snapshot?.scanId, view, refreshDashboard])

  const currentProject = projects.find((project) => project.projectId === projectId)
  const apiError = projectApiError ?? dashboardApiError
  const english = language === 'EN'
  const nav = navFor(english)
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">V</div><div><strong>溯脉 · Veyrion</strong><small>{english ? 'Closed-source JVM security verification' : '闭源 JVM 安全验证'}</small></div></div>
      <button className="workspace-chip" type="button" onClick={() => setView('workspaces')}>
        <span />
        <div><small>{english ? 'Workspace · home' : '当前工作区 · 返回首页'}</small><strong>{currentProject?.name ?? (english ? 'No workspace' : '未选择工作区')}</strong></div>
      </button>
      <nav aria-label={english ? 'Main navigation' : '主导航'}>{nav.map((item) => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} aria-current={view === item.id ? 'page' : undefined} onClick={() => setView(item.id)}><span className="nav-icon">{item.icon}</span><span><strong>{item.label}</strong><small>{item.description}</small></span></button>)}</nav>
      <div className="sidebar-foot"><span className={`connection-dot ${apiError ? 'offline' : ''}`} /><div><strong>{api.mode === 'demo' ? (english ? 'Explicit demo mode' : '显式演示模式') : apiError ? (english ? 'Some APIs unavailable' : '部分接口不可用') : (english ? 'Control plane reachable' : '控制面可响应')}</strong><small>{apiError ? (english ? 'No silent fallback' : '无静默回退') : snapshot?.dependencyMode ? dependencyModeLabel(snapshot.dependencyMode, english) : (english ? 'Waiting for project data' : '等待项目数据')}</small></div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><button className="mobile-brand" onClick={() => setView('workspaces')} aria-label={english ? 'Back to workspaces' : '返回工作区首页'}>V</button><div><span>{currentProject?.name ?? (english ? 'No workspace' : '未选择工作区')} / </span><strong>{nav.find((item) => item.id === view)?.label}</strong></div><div className="top-actions"><span className="mode-tag">{api.mode === 'demo' ? (english ? 'Demo data' : '演示数据') : (english ? 'Control plane' : '控制面')}</span><button className="icon-button" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')} aria-label={english ? `Switch to ${theme === 'light' ? 'dark' : 'light'} theme` : `切换到${theme === 'light' ? '暗色' : '亮色'}主题`}>{theme === 'light' ? '☾' : '☀'}</button></div></header>
      {view !== 'workspaces' && <BoundaryLegend english={english} />}
      <div className="page-container">
        {apiError && <Notice kind="error">{apiError}{english ? '. Unavailable capabilities stay unavailable — no demo success fallback.' : '。未连接的能力显示为不可用，不会回退到演示成功。'}</Notice>}
        {view === 'workspaces' && <WorkspacesHomePage
          projects={projects}
          projectId={projectId}
          onSelect={setProjectId}
          onOpenAudit={() => setView('audit')}
          onProjectsChanged={refreshProjects}
        />}
        {view === 'audit' && <AuditPage projectId={projectId} snapshot={snapshot} onRefresh={refreshDashboard} language={language} />}
        {view === 'history' && <AuditHistoryPage
          projectId={projectId}
          language={language}
          activeScanId={focusedScanId ?? snapshot?.scanId}
          onOpenScan={(scanId) => { setFocusedScanId(scanId); setView('results') }}
          onOpenAudit={() => setView('audit')}
          onScanDeleted={(scanId) => {
            const nextFocus = focusedScanId === scanId ? undefined : focusedScanId
            setFocusedScanId(nextFocus)
            void (async () => {
              if (!projectId) { setSnapshot(null); return }
              try {
                setSnapshot(await api.loadDashboard(projectId, nextFocus))
                setDashboardApiError(undefined)
              } catch (cause) {
                setSnapshot(null)
                setDashboardApiError(errorMessage(cause, english))
              }
            })()
          }}
        />}
        {view === 'ai-audit' && <AiAuditPage projectId={projectId} snapshot={snapshot} language={language} onRefresh={refreshDashboard} />}
        {view === 'results' && <ResultsPage projectId={projectId} snapshot={snapshot} language={language} />}
        {view === 'providers' && <ProviderPage projectId={projectId} english={english} />}
        {view === 'settings' && <SettingsPage theme={theme} onTheme={() => setTheme(theme === 'light' ? 'dark' : 'light')} language={language} onLanguage={setLanguage} />}
      </div>
      <nav className="mobile-nav" aria-label={english ? 'Mobile navigation' : '移动端主导航'}>{nav.map((item) => <button key={item.id} className={view === item.id ? 'active' : ''} onClick={() => setView(item.id)}><span>{item.icon}</span>{item.label}</button>)}</nav>
    </main>
  </div>
}

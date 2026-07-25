import { useCallback, useEffect, useState } from 'react'
import { api, type DashboardSnapshot, type ProjectDto } from './api'
import { AiAuditPage } from './components/AiAuditPage'
import { AuditPage } from './components/AuditPage'
import { BoundaryLegend, Notice, errorMessage } from './components/Common'
import { ProviderPage } from './components/ProviderPage'
import { ResultsPage } from './components/ResultsPage'
import { SettingsPage } from './components/SettingsPage'
import { WorkspacePage } from './components/WorkspacePage'

type View = 'workspace' | 'audit' | 'results' | 'providers' | 'ai-audit' | 'settings'
type Theme = 'light' | 'dark'

const nav: Array<{ id: View; label: string; description: string; icon: string }> = [
  { id: 'workspace', label: '工作区', description: 'Projects & artifacts', icon: '⌂' },
  { id: 'audit', label: '审计执行', description: 'Policy & timeline', icon: '◎' },
  { id: 'results', label: '审计结果', description: 'Evidence & findings', icon: '◇' },
  { id: 'providers', label: '模型服务', description: 'Provider & AI roles', icon: '◈' },
  { id: 'ai-audit', label: 'AI 审计过程', description: 'Requests & tool events', icon: '≋' },
  { id: 'settings', label: '全局设置', description: 'Appearance & safety', icon: '⚙' }
]

const initialTheme = (): Theme => {
  try { return localStorage.getItem('veyrion.theme') === 'dark' ? 'dark' : 'light' } catch { return 'light' }
}

export default function App() {
  const [view, setView] = useState<View>('workspace')
  const [theme, setTheme] = useState<Theme>(initialTheme)
  const [projects, setProjects] = useState<ProjectDto[]>([])
  const [projectId, setProjectId] = useState(import.meta.env.VITE_PROJECT_ID || 'default')
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [projectApiError, setProjectApiError] = useState<string>()
  const [dashboardApiError, setDashboardApiError] = useState<string>()

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('veyrion.theme', theme) } catch { /* Theme still applies for this session. */ }
    const color = theme === 'light' ? '#f6f8fc' : '#09111f'
    document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute('content', color)
  }, [theme])

  const refreshProjects = useCallback(async () => {
    try {
      const next = await api.listProjects()
      setProjects(next)
      setProjectApiError(undefined)
      if (!projectId && next[0]) setProjectId(next[0].projectId)
    } catch (cause) {
      setProjectApiError(errorMessage(cause))
    }
  }, [projectId])

  const refreshDashboard = useCallback(async () => {
    if (!projectId) { setSnapshot(null); return }
    try {
      setSnapshot(await api.loadDashboard(projectId))
      setDashboardApiError(undefined)
    } catch (cause) {
      setSnapshot(null)
      setDashboardApiError(errorMessage(cause))
    }
  }, [projectId])

  useEffect(() => { void refreshProjects() }, [refreshProjects])
  useEffect(() => { void refreshDashboard() }, [refreshDashboard])

  const currentProject = projects.find((project) => project.projectId === projectId)
  const apiError = projectApiError ?? dashboardApiError
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">V</div><div><strong>VEYRION</strong><small>溯脉 · JVM SECURITY</small></div></div>
      <div className="workspace-chip"><span /><div><small>当前项目</small><strong>{currentProject?.name ?? (projectId || '未选择')}</strong></div></div>
      <nav aria-label="主导航">{nav.map((item) => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} aria-current={view === item.id ? 'page' : undefined} onClick={() => setView(item.id)}><span className="nav-icon">{item.icon}</span><span><strong>{item.label}</strong><small>{item.description}</small></span></button>)}</nav>
      <div className="sidebar-foot"><span className={`connection-dot ${apiError ? 'offline' : ''}`} /><div><strong>{api.mode === 'demo' ? '显式 Demo 模式' : apiError ? '部分 API unavailable' : 'Control Plane 可响应'}</strong><small>{apiError ? '无静默回退' : snapshot?.dependencyMode ?? '等待项目数据'}</small></div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><button className="mobile-brand" onClick={() => setView('workspace')} aria-label="返回工作区">V</button><div><span>VEYRION / </span><strong>{nav.find((item) => item.id === view)?.label}</strong></div><div className="top-actions"><span className="mode-tag">{api.mode === 'demo' ? 'DEMO DATA' : 'CONTROL PLANE'}</span><button className="icon-button" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')} aria-label={`切换到${theme === 'light' ? '暗色' : '亮色'}主题`}>{theme === 'light' ? '☾' : '☀'}</button></div></header>
      <BoundaryLegend />
      <div className="page-container">
        {apiError && <Notice kind="error">{apiError}。未连接的能力显示为 unavailable，不会回退到演示成功。</Notice>}
        {view === 'workspace' && <WorkspacePage projects={projects} projectId={projectId} onSelect={setProjectId} onProjectsChanged={refreshProjects} />}
        {view === 'audit' && <AuditPage projectId={projectId} snapshot={snapshot} onRefresh={refreshDashboard} />}
        {view === 'results' && <ResultsPage snapshot={snapshot} />}
        {view === 'providers' && <ProviderPage projectId={projectId} />}
        {view === 'ai-audit' && <AiAuditPage projectId={projectId} snapshot={snapshot} />}
        {view === 'settings' && <SettingsPage theme={theme} onTheme={() => setTheme(theme === 'light' ? 'dark' : 'light')} />}
      </div>
      <nav className="mobile-nav" aria-label="移动端主导航">{nav.map((item) => <button key={item.id} className={view === item.id ? 'active' : ''} onClick={() => setView(item.id)}><span>{item.icon}</span>{item.label}</button>)}</nav>
    </main>
  </div>
}

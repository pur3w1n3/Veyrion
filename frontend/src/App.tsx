import { useCallback, useEffect, useState } from 'react'
import { api, type DashboardSnapshot, type OutputLanguage, type ProjectDto } from './api'
import { AiAuditPage } from './components/AiAuditPage'
import { AuditPage } from './components/AuditPage'
import { BoundaryLegend, Notice, errorMessage } from './components/Common'
import { ProviderPage } from './components/ProviderPage'
import { ResultsPage } from './components/ResultsPage'
import { SettingsPage } from './components/SettingsPage'
import { WorkspacesHomePage } from './components/WorkspacesHomePage'
import { dependencyModeLabel } from './labels'

type View = 'workspaces' | 'audit' | 'ai-audit' | 'results' | 'providers' | 'settings'
type Theme = 'light' | 'dark'

const nav: Array<{ id: View; label: string; description: string; icon: string }> = [
  { id: 'workspaces', label: '工作区', description: '格子切换、新建与删除', icon: '▦' },
  { id: 'audit', label: '审计执行', description: '制品导入与自动流水线', icon: '◎' },
  { id: 'ai-audit', label: '审计过程', description: '提示词、思考与输出对话', icon: '≋' },
  { id: 'results', label: '审计结果', description: '证据、发现与报告', icon: '◇' },
  { id: 'providers', label: '模型服务', description: '接口配置与五个角色', icon: '◈' },
  { id: 'settings', label: '全局设置', description: '外观与安全默认值', icon: '⚙' }
]

const initialTheme = (): Theme => {
  try { return localStorage.getItem('veyrion.theme') === 'dark' ? 'dark' : 'light' } catch { return 'light' }
}

const initialLanguage = (): OutputLanguage => {
  try { return localStorage.getItem('veyrion.language') === 'EN' ? 'EN' : 'ZH_CN' } catch { return 'ZH_CN' }
}

export default function App() {
  const [view, setView] = useState<View>('workspaces')
  const [theme, setTheme] = useState<Theme>(initialTheme)
  const [language, setLanguage] = useState<OutputLanguage>(initialLanguage)
  const [projects, setProjects] = useState<ProjectDto[]>([])
  const [projectId, setProjectId] = useState(import.meta.env.VITE_PROJECT_ID || '')
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
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

  const refreshProjects = useCallback(async () => {
    try {
      const next = await api.listProjects()
      setProjects(next)
      setProjectApiError(undefined)
      setProjectId((current) =>
        current && next.some((project) => project.projectId === current)
          ? current
          : (next[0]?.projectId ?? '')
      )
    } catch (cause) {
      setProjectApiError(errorMessage(cause))
    }
  }, [])

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
      <div className="brand"><div className="brand-mark">V</div><div><strong>溯脉 · Veyrion</strong><small>闭源 JVM 安全验证</small></div></div>
      <button className="workspace-chip" type="button" onClick={() => setView('workspaces')}>
        <span />
        <div><small>当前工作区 · 返回首页</small><strong>{currentProject?.name ?? '未选择工作区'}</strong></div>
      </button>
      <nav aria-label="主导航">{nav.map((item) => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} aria-current={view === item.id ? 'page' : undefined} onClick={() => setView(item.id)}><span className="nav-icon">{item.icon}</span><span><strong>{item.label}</strong><small>{item.description}</small></span></button>)}</nav>
      <div className="sidebar-foot"><span className={`connection-dot ${apiError ? 'offline' : ''}`} /><div><strong>{api.mode === 'demo' ? '显式演示模式' : apiError ? '部分接口不可用' : '控制面可响应'}</strong><small>{apiError ? '无静默回退' : snapshot?.dependencyMode ? dependencyModeLabel(snapshot.dependencyMode) : '等待项目数据'}</small></div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><button className="mobile-brand" onClick={() => setView('workspaces')} aria-label="返回工作区首页">V</button><div><span>{currentProject?.name ?? '未选择工作区'} / </span><strong>{nav.find((item) => item.id === view)?.label}</strong></div><div className="top-actions"><span className="mode-tag">{api.mode === 'demo' ? '演示数据' : '控制面'}</span><button className="icon-button" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')} aria-label={`切换到${theme === 'light' ? '暗色' : '亮色'}主题`}>{theme === 'light' ? '☾' : '☀'}</button></div></header>
      {view !== 'workspaces' && <BoundaryLegend />}
      <div className="page-container">
        {apiError && <Notice kind="error">{apiError}。未连接的能力显示为不可用，不会回退到演示成功。</Notice>}
        {view === 'workspaces' && <WorkspacesHomePage
          projects={projects}
          projectId={projectId}
          onSelect={setProjectId}
          onOpenAudit={() => setView('audit')}
          onProjectsChanged={refreshProjects}
        />}
        {view === 'audit' && <AuditPage projectId={projectId} snapshot={snapshot} onRefresh={refreshDashboard} language={language} />}
        {view === 'ai-audit' && <AiAuditPage projectId={projectId} snapshot={snapshot} language={language} onRefresh={refreshDashboard} />}
        {view === 'results' && <ResultsPage projectId={projectId} snapshot={snapshot} language={language} />}
        {view === 'providers' && <ProviderPage projectId={projectId} />}
        {view === 'settings' && <SettingsPage theme={theme} onTheme={() => setTheme(theme === 'light' ? 'dark' : 'light')} language={language} onLanguage={setLanguage} />}
      </div>
      <nav className="mobile-nav" aria-label="移动端主导航">{nav.map((item) => <button key={item.id} className={view === item.id ? 'active' : ''} onClick={() => setView(item.id)}><span>{item.icon}</span>{item.label}</button>)}</nav>
    </main>
  </div>
}

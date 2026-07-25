import { PageHeader } from './Common'

export function SettingsPage({ theme, onTheme }: { theme: 'light' | 'dark'; onTheme: () => void }) {
  return <section>
    <PageHeader eyebrow="SETTINGS / SAFETY" title="全局设置">
      管理本地界面与固定安全默认值；模型服务和 AI 审计过程使用左侧独立功能入口。
    </PageHeader>
    <article className="panel">
      <div className="panel-head"><div><p className="eyebrow">APPEARANCE & SAFETY</p><h2>通用</h2></div></div>
      <div className="setting-row"><div><strong>界面主题</strong><small>当前：{theme === 'light' ? '亮色' : '暗色'}；仅主题偏好持久化</small></div><button className="secondary-button" onClick={onTheme}>切换主题</button></div>
      <div className="setting-row"><div><strong>默认出站网络</strong><small>固定 DENY；前端不能放宽</small></div><span className="locked-tag">LOCKED</span></div>
      <div className="setting-row"><div><strong>危险动作</strong><small>固定 DRY_RUN / SIMULATE</small></div><span className="locked-tag">LOCKED</span></div>
    </article>
  </section>
}

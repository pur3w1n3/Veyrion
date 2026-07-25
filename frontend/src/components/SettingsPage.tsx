import type { OutputLanguage } from '../api'
import { PageHeader } from './Common'

export function SettingsPage({
  theme,
  onTheme,
  language,
  onLanguage
}: {
  theme: 'light' | 'dark'
  onTheme: () => void
  language: OutputLanguage
  onLanguage: (language: OutputLanguage) => void
}) {
  return <section>
    <PageHeader eyebrow="SETTINGS / SAFETY" title="全局设置">
      管理本地界面与固定安全默认值；模型服务和 AI 审计过程使用左侧独立功能入口。
    </PageHeader>
    <article className="panel">
      <div className="panel-head"><div><p className="eyebrow">APPEARANCE & SAFETY</p><h2>通用</h2></div></div>
      <div className="setting-row"><div><strong>界面主题</strong><small>当前：{theme === 'light' ? '亮色' : '暗色'}；仅主题偏好持久化</small></div><button className="secondary-button" onClick={onTheme}>切换主题</button></div>
      <div className="setting-row">
        <div><strong>报告与 AI 输出语言</strong><small>只影响新创建的 AI Job；旧结果是不可变快照，不会被翻译或改写。</small></div>
        <label className="language-select">
          <span className="sr-only">报告与 AI 输出语言</span>
          <select value={language} onChange={(event) => onLanguage(event.target.value as OutputLanguage)}>
            <option value="ZH_CN">简体中文</option>
            <option value="EN">English</option>
          </select>
        </label>
      </div>
      <div className="setting-row"><div><strong>默认出站网络</strong><small>固定 DENY；前端不能放宽</small></div><span className="locked-tag">LOCKED</span></div>
      <div className="setting-row"><div><strong>危险动作</strong><small>固定 DRY_RUN / SIMULATE</small></div><span className="locked-tag">LOCKED</span></div>
    </article>
  </section>
}

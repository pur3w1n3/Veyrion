import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { LAYOUT_CONTRACT, NARROW_VIEWPORT_CLASS } from './layoutContract'
import './styles.css'

/** 视口匹配 layout contract 断点时应用 narrow class。 */
const syncNarrowViewportClass = () => {
  const narrow = window.matchMedia(`(max-width: ${LAYOUT_CONTRACT.narrowBreakpointPx}px)`).matches
  document.body.classList.toggle(NARROW_VIEWPORT_CLASS, narrow)
}
syncNarrowViewportClass()
window.matchMedia(`(max-width: ${LAYOUT_CONTRACT.narrowBreakpointPx}px)`)
  .addEventListener('change', syncNarrowViewportClass)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>
)

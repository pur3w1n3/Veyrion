import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { LAYOUT_CONTRACT, NARROW_VIEWPORT_CLASS } from './layoutContract'
import './styles.css'

/** Apply narrow class when viewport matches layout contract breakpoint. */
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

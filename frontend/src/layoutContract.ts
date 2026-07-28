/**
 * P1-23 GUI layout / long-text contract — narrow viewport and overflow rules.
 * Asserted by GuiLayoutContractAcceptanceTest against this file and styles.css.
 */

/** CSS custom properties that bound content width and control long-text wrapping. */
export const LAYOUT_CSS_VARS = {
  contentMaxWidth: '--veyrion-content-max-width',
  narrowBreakpoint: '--veyrion-narrow-breakpoint',
  longTextOverflow: '--veyrion-long-text-overflow',
  longTextWordBreak: '--veyrion-long-text-word-break'
} as const

/** Narrow viewport class applied under the contract breakpoint (see styles.css). */
export const NARROW_VIEWPORT_CLASS = 'veyrion-narrow'

/** Long-text surfaces that must not overflow / overlap filters or timelines. */
export const LONG_TEXT_CLASSES = [
  'veyrion-long-text',
  'chat-markdown',
  'ai-report',
  'audit-flow-body'
] as const

export const LAYOUT_CONTRACT = {
  contentMaxWidthPx: 1280,
  narrowBreakpointPx: 760,
  /** Required CSS declarations (substring match in styles.css). */
  requiredRules: {
    maxWidth: 'max-width',
    overflowWrap: 'overflow-wrap',
    wordBreak: 'word-break',
    overflowX: 'overflow-x'
  },
  cssVars: LAYOUT_CSS_VARS,
  narrowClass: NARROW_VIEWPORT_CLASS,
  longTextClasses: LONG_TEXT_CLASSES
} as const

export type LayoutContract = typeof LAYOUT_CONTRACT

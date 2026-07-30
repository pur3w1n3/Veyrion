/**
 * P1-23 GUI layout / 长文本合同 — 窄视口与溢出规则。
 * 由 GuiLayoutContractAcceptanceTest 针对本文件与 styles.css 断言。
 */

/** 限定内容宽度并控制长文本换行的 CSS 自定义属性。 */
export const LAYOUT_CSS_VARS = {
  contentMaxWidth: '--veyrion-content-max-width',
  narrowBreakpoint: '--veyrion-narrow-breakpoint',
  longTextOverflow: '--veyrion-long-text-overflow',
  longTextWordBreak: '--veyrion-long-text-word-break'
} as const

/** 合同断点下应用的窄视口 class（见 styles.css）。 */
export const NARROW_VIEWPORT_CLASS = 'veyrion-narrow'

/** 不得溢出 / 与 filter 或时间线重叠的长文本面。 */
export const LONG_TEXT_CLASSES = [
  'veyrion-long-text',
  'chat-markdown',
  'ai-report',
  'audit-flow-body'
] as const

export const LAYOUT_CONTRACT = {
  contentMaxWidthPx: 1280,
  narrowBreakpointPx: 760,
  /** 必需的 CSS 声明（在 styles.css 中子串匹配）。 */
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

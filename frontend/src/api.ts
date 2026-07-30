/**
 * GUI 与 Java 控制面之间的唯一边界（薄 re-export 桶）。
 *
 * 拆分模块见 `./api/`；本文件保持 `from '../api'` 等现有导入路径不变。
 */

export {
  FindingRequiredFields,
  SecurityHypothesisRequiredFields,
  CoverageMatrixRequiredFields,
} from './generated/contracts'

export * from './api/types'
export * from './api/scans'
export * from './api/projects'
export * from './api/artifacts'
export * from './api/providers'
export * from './api/ai'
export * from './api/client'
export * from './api/mockClient'
export { api } from './api/index'

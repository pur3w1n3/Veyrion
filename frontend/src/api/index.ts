import { HttpSentinelApi } from './client'
import { MockSentinelApi } from './mockClient'

// 演示模式必须显式开启。未设置标志时现使用真实控制面适配器，防止生产构建静默展示 mock 结果。
const demoMode = import.meta.env.VITE_DEMO_MODE === 'true'
export const api: import('./types').SentinelApi = demoMode
  ? new MockSentinelApi()
  : new HttpSentinelApi(import.meta.env.VITE_API_BASE_URL || '/api/v1', import.meta.env.VITE_PROJECT_ID || '')

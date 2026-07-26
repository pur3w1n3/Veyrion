import type { AiRole, DependencyMode } from './api'

/** Human-readable Chinese labels for fixed model roles. Technical codes stay for API only. */
export const AI_ROLE_META: Record<AiRole, { name: string; description: string }> = {
  PRE_ANALYSIS: {
    name: '前置建模',
    description: '补充入口、业务对象与前置条件；补充项只能作为模型假设，不能改写静态事实'
  },
  DYNAMIC_VERIFICATION: {
    name: '动态验证',
    description: '依据入口和沙箱参数在本地授权沙箱发包，保存请求/响应与触发点结果；不改变沙箱策略'
  },
  PATH_EXPLORATION: {
    name: '路径探索',
    description: '消费前三类入口、请求和响应结果，建立数据/状态转换路径；不把未执行候选写成事实'
  },
  VULNERABILITY_TRIAGE: {
    name: '漏洞研判',
    description: '基于前置建模、动态验证和路径结果研判；动态调试未闭环时不得标记漏洞存在'
  },
  REPORT_GENERATION: {
    name: '报告生成',
    description: '汇总证据等级、限制与未覆盖区域，输出可读审计报告'
  }
}

export const AI_ROLES: AiRole[] = [
  'PRE_ANALYSIS',
  'DYNAMIC_VERIFICATION',
  'PATH_EXPLORATION',
  'VULNERABILITY_TRIAGE',
  'REPORT_GENERATION'
]

export const DEFAULT_ROLE_PROMPTS: Record<AiRole, { zh: string; en: string }> = {
  PRE_ANALYSIS: {
    zh: '建立入口、业务模块、权限前置条件、依赖和敏感触发点模型；补充静态索引可能遗漏的入口候选，并为每项补充标记 MODEL_SUPPLEMENT、理由和证据。不得改写静态事实或声称运行时可达。',
    en: 'Build the entrypoint, business, permission, dependency, and sensitive-trigger model. Add missing entry candidates as MODEL_SUPPLEMENT with reasons and evidence. Never rewrite static facts or claim runtime reachability.'
  },
  DYNAMIC_VERIFICATION: {
    zh: '使用前置建模入口和沙箱反馈参数，提出同一授权沙箱 loopback 范围内的无破坏本地发包；由服务端受控执行器实际发包并保存请求、响应、入口命中、参数绑定和触发点结果。不得访问外网或改变命令、挂载、能力、预算和策略。',
    en: 'Use pre-analysis entries and sandbox feedback parameters to propose non-destructive local requests inside the same authorized sandbox loopback. A server-owned executor performs and persists requests, responses, entry hits, bindings, and trigger results. Never access external network or change commands, mounts, capabilities, budgets, or policy.'
  },
  PATH_EXPLORATION: {
    zh: '仅消费前置建模、动态验证和已保存的请求/响应，建立多条数据与状态转换路径。区分事实、反证和缺口，不把未执行候选写成事实。',
    en: 'Consume only pre-analysis, dynamic verification, and persisted request/response evidence to model distinct data and state paths. Separate facts, counterevidence, and gaps; never turn an unexecuted candidate into fact.'
  },
  VULNERABILITY_TRIAGE: {
    zh: '基于前置建模、动态验证和路径探索研判风险。只有入口命中、参数绑定、触发点执行和可重放动态调试全部闭环，才可标记漏洞存在；否则保持推测或证据不足。',
    en: 'Assess risk from pre-analysis, dynamic verification, and path exploration. Mark a vulnerability present only when entry hit, parameter binding, trigger execution, and replayable dynamic debugging are closed; otherwise keep hypothesis or insufficient evidence.'
  },
  REPORT_GENERATION: {
    zh: '汇总前四个角色的证据、动态覆盖、限制和未覆盖区域，严格区分 STATIC_INFERRED、DYNAMIC_SUSPECTED 与 VERIFIED，不得升级结论。',
    en: 'Summarize evidence, dynamic coverage, limits, and gaps from the four prior roles. Preserve STATIC_INFERRED, DYNAMIC_SUSPECTED, and VERIFIED distinctions and never upgrade conclusions.'
  }
}

export const roleLabel = (role: string) =>
  AI_ROLE_META[role as AiRole]?.name ?? role

export const dependencyModeLabel = (mode: DependencyMode | string | undefined) => {
  switch (mode) {
    case 'MOCK':
      return '替身执行'
    case 'REPLAY':
      return '录制回放'
    case 'LIVE_DISABLED':
      return '真实依赖已禁用'
    case 'LIVE':
      return '真实依赖'
    default:
      return mode && mode !== 'unknown' ? String(mode) : '未知'
  }
}

export const jobStatusLabel = (status: string | undefined) => {
  switch (status) {
    case 'QUEUED':
      return '排队中'
    case 'LEASED':
      return '已领取'
    case 'RUNNING':
      return '执行中'
    case 'COMPLETED':
      return '已完成'
    case 'FAILED':
      return '失败'
    case 'CANCELLED':
      return '已取消'
    case 'BLOCKED':
      return '已阻断'
    default:
      return status ?? '未知'
  }
}

export const stopReasonLabel = (reason: string | undefined) => {
  switch (reason) {
    case 'LEASE_EXPIRED':
      return '租约过期已回收'
    case 'WORKER_FAILURE':
      return 'Worker 失败'
    case 'USER_CANCELLED':
      return '已取消'
    case 'COMPLETED':
      return '已完成'
    default:
      return reason
  }
}

export const timelineStateLabel = (state: string) => {
  switch (state) {
    case 'completed':
      return '已完成'
    case 'active':
      return '进行中'
    case 'waiting':
      return '等待中'
    case 'unavailable':
      return '不可用'
    default:
      return state
  }
}

import type { AiRole, DependencyMode } from './api'

/** Human-readable Chinese labels for fixed model roles. Technical codes stay for API only. */
export const AI_ROLE_META: Record<AiRole, { name: string; description: string }> = {
  PRE_ANALYSIS: {
    name: '前置建模',
    description: '解释入口、业务对象与前置条件，给出探索优先级；不能改写静态事实'
  },
  PATH_EXPLORATION: {
    name: '路径探索',
    description: '提出受策略约束的多条推测链路与候选输入；不声称已经执行'
  },
  DYNAMIC_VERIFICATION: {
    name: '动态验证',
    description: '解读沙箱运行记录，对照入口与触发点，提出可重放验证步骤；不能单独宣布漏洞已验证'
  },
  VULNERABILITY_TRIAGE: {
    name: '漏洞研判',
    description: '关联静态与运行时证据，区分事实与推断；没有可重放证据不得升级为已验证'
  },
  REPORT_GENERATION: {
    name: '报告生成',
    description: '汇总证据等级、限制与未覆盖区域，输出可读审计报告'
  }
}

export const AI_ROLES: AiRole[] = [
  'PRE_ANALYSIS',
  'PATH_EXPLORATION',
  'DYNAMIC_VERIFICATION',
  'VULNERABILITY_TRIAGE',
  'REPORT_GENERATION'
]

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

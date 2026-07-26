import type { AiRole, DependencyMode } from './api'

/** Human-readable Chinese labels for fixed model roles. Technical codes stay for API only. */
export const AI_ROLE_META: Record<AiRole, { name: string; description: string }> = {
  PRE_ANALYSIS: {
    name: '前置建模',
    description: '补充入口、业务对象与前置条件；补充项只能作为模型假设，不能改写静态事实'
  },
  AUTH_ANALYSIS: {
    name: '鉴权分析',
    description: '建立鉴权模型、合成身份策略、身份轨与实验计划草稿；洪水后仅确认绕过，不得改沙箱策略'
  },
  DYNAMIC_VERIFICATION: {
    name: '动态验证',
    description: '依据入口和沙箱参数在本地授权沙箱发包，保存请求/响应与触发点结果；不改变沙箱策略'
  },
  PATH_EXPLORATION: {
    name: '路径探索',
    description: '消费 PathRun、请求和响应结果，建立数据/状态转换路径；不把未执行候选写成事实'
  },
  VULNERABILITY_TRIAGE: {
    name: '漏洞研判',
    description: '基于鉴权分析、动态验证和路径结果研判；动态调试未闭环时不得标记漏洞存在'
  },
  REPORT_GENERATION: {
    name: '报告生成',
    description: '汇总证据等级、限制与未覆盖区域，输出可读审计报告'
  }
}

export const AI_ROLES: AiRole[] = [
  'PRE_ANALYSIS',
  'AUTH_ANALYSIS',
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
  AUTH_ANALYSIS: {
    zh: '建立鉴权模型与可合成身份（MOCK/RULE_GENERATED），指定高价值入口与身份轨，起草实验计划。洪水后仅根据 PathRun 的 401/过闸证据确认绕过。不得改网络/挂载，不得单独升级验证状态。',
    en: 'Build the auth model and synthesizable identities (MOCK/RULE_GENERATED), choose high-value entries and tracks, and draft experiment plans. After the flood, confirm bypass only from PathRun 401/pass-gate evidence. Never change network/mounts or alone upgrade verification status.'
  },
  DYNAMIC_VERIFICATION: {
    zh: '使用鉴权分析实验计划与沙箱 PathRun，提出同一授权沙箱 loopback 范围内的无破坏本地发包；由服务端受控执行器实际发包并保存请求、响应、入口命中、参数绑定和触发点结果。不得访问外网或改变命令、挂载、能力、预算和策略。',
    en: 'Use AUTH_ANALYSIS experiment plans and sandbox PathRuns to propose non-destructive local requests inside the same authorized sandbox loopback. A server-owned executor performs and persists requests, responses, entry hits, bindings, and trigger results. Never access external network or change commands, mounts, capabilities, budgets, or policy.'
  },
  PATH_EXPLORATION: {
    zh: '仅消费前置建模、鉴权分析、动态验证和已保存的 PathRun，建立多条数据与状态转换路径。区分事实、反证和缺口，不把未执行候选写成事实。',
    en: 'Consume only pre-analysis, auth analysis, dynamic verification, and persisted PathRuns to model distinct data and state paths. Separate facts, counterevidence, and gaps; never turn an unexecuted candidate into fact.'
  },
  VULNERABILITY_TRIAGE: {
    zh: '基于前置建模、鉴权分析、动态验证和路径探索研判风险。只有入口命中、参数绑定、触发点执行和可重放动态调试全部闭环，才可标记漏洞存在；否则保持推测或证据不足。DYNAMIC_CONFIRMED 仅服务端 SQL 门禁可写。',
    en: 'Assess risk from pre-analysis, auth analysis, dynamic verification, and path exploration. Mark a vulnerability present only when entry hit, parameter binding, trigger execution, and replayable dynamic debugging are closed; otherwise keep hypothesis or insufficient evidence. DYNAMIC_CONFIRMED is server-gated for SQL only.'
  },
  REPORT_GENERATION: {
    zh: '汇总各角色的证据、PathRun、动态覆盖、限制和未覆盖区域，严格区分 STATIC_INFERRED、DYNAMIC_SUSPECTED、DYNAMIC_CONFIRMED 与 VERIFIED，不得升级结论，不得把 DYNAMIC_CONFIRMED 宣传为生产实库已证实。',
    en: 'Summarize evidence, PathRuns, dynamic coverage, limits, and gaps from prior roles. Preserve STATIC_INFERRED, DYNAMIC_SUSPECTED, DYNAMIC_CONFIRMED, and VERIFIED distinctions and never upgrade conclusions or market DYNAMIC_CONFIRMED as production DB proof.'
  }
}

export const roleLabel = (role: string) =>
  AI_ROLE_META[role as AiRole]?.name ?? role

export const outcomeClassLabel = (code: string | undefined) => {
  switch (code) {
    case 'COLD_START':
      return '冷启动'
    case 'AUTH_CHALLENGE':
      return '鉴权挑战'
    case 'REACHED_NO_BIND':
      return '到达未绑定'
    case 'BUSINESS_TIMEOUT':
      return '业务超时'
    case 'ENGINE_BUSY':
      return '引擎繁忙'
    case 'DEPENDENCY_MOCK_GAP':
      return '依赖替身缺口'
    case 'TRANSPORT_ERROR':
      return '传输错误'
    case 'PROBE_BUDGET':
      return '探针预算用尽'
    case 'IDENTITY_UNAVAILABLE':
      return '身份不可用'
    case 'HTTP_OBSERVED':
      return 'HTTP 已观测'
    case 'UNKNOWN':
      return '未知'
    default:
      return code ?? '未知'
  }
}

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

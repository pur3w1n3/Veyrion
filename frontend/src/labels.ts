import type { AiRole, DependencyMode, HypothesisFamily } from './api'

/** 按 locale 的 hypothesis family 标签（中文 UI 以 ZH 为主；EN code 为次要术语）。 */
export const HYPOTHESIS_FAMILY_META: Record<HypothesisFamily, {
  zh: string
  en: string
  blurbZh: string
  blurbEn: string
}> = {
  DATAFLOW: {
    zh: '数据流',
    en: 'Dataflow',
    blurbZh: '污点/入口到 sink 的数据流假设',
    blurbEn: 'Taint / entry-to-sink dataflow hypotheses'
  },
  GUARD_COVERAGE: {
    zh: '鉴权覆盖',
    en: 'Guard coverage',
    blurbZh: '鉴权、角色与守卫覆盖缺口',
    blurbEn: 'Auth, role, and guard-coverage gaps'
  },
  STATE: {
    zh: '状态',
    en: 'State',
    blurbZh: '业务状态与前置条件假设',
    blurbEn: 'Business-state and precondition hypotheses'
  },
  TYPESTATE: {
    zh: '类型状态',
    en: 'Typestate',
    blurbZh: 'API misuse / typestate 假设',
    blurbEn: 'API misuse / typestate hypotheses'
  },
  CONFIG: {
    zh: '配置',
    en: 'Config',
    blurbZh: '硬编码密钥与危险配置',
    blurbEn: 'Hardcoded secrets and risky configuration'
  },
  DEPENDENCY: {
    zh: '依赖',
    en: 'Dependency',
    blurbZh: '依赖副作用与供应链面',
    blurbEn: 'Dependency side-effects and supply surface'
  },
  CONCURRENCY: {
    zh: '并发',
    en: 'Concurrency',
    blurbZh: '竞态 / TOCTOU 类假设',
    blurbEn: 'Race / TOCTOU-class hypotheses'
  },
  COMPOSITION: {
    zh: '组合',
    en: 'Composition',
    blurbZh: '跨组件组合攻击面',
    blurbEn: 'Cross-component composition surface'
  },
  UNKNOWN: {
    zh: '未知',
    en: 'Unknown',
    blurbZh: '未归类或降级族',
    blurbEn: 'Unclassified or degraded family'
  }
}

export const hypothesisFamilyLabel = (family: string | undefined, english = false) => {
  const key = (family ?? 'UNKNOWN').toUpperCase() as HypothesisFamily
  const meta = HYPOTHESIS_FAMILY_META[key] ?? HYPOTHESIS_FAMILY_META.UNKNOWN
  return english ? meta.en : meta.zh
}

export const hypothesisFamilyBlurb = (family: string | undefined, english = false) => {
  const key = (family ?? 'UNKNOWN').toUpperCase() as HypothesisFamily
  const meta = HYPOTHESIS_FAMILY_META[key] ?? HYPOTHESIS_FAMILY_META.UNKNOWN
  return english ? meta.blurbEn : meta.blurbZh
}

/** 固定模型角色的人类可读标签。技术 code 仅用于 API。 */
export const AI_ROLE_META: Record<AiRole, {
  name: string
  nameEn: string
  chip: string
  chipEn: string
  description: string
  descriptionEn: string
}> = {
  PRE_ANALYSIS: {
    name: '前置建模',
    nameEn: 'Pre-analysis',
    chip: '建模',
    chipEn: 'Pre',
    description: '补充入口、业务对象与前置条件；补充项只能作为模型假设，不能改写静态事实',
    descriptionEn: 'Supplement entries, business objects, and preconditions; supplements are model hypotheses only and must not rewrite static facts'
  },
  AUTH_ANALYSIS: {
    name: '鉴权分析',
    nameEn: 'Auth analysis',
    chip: '鉴权',
    chipEn: 'Auth',
    description: '建立鉴权模型、合成身份策略、身份轨与实验计划草稿；洪水后仅确认绕过，不得改沙箱策略',
    descriptionEn: 'Build auth model, synthetic identity policy, tracks, and experiment drafts; after flood only confirm bypass — never change sandbox policy'
  },
  DYNAMIC_VERIFICATION: {
    name: '动态验证',
    nameEn: 'Dynamic verification',
    chip: '动态',
    chipEn: 'Dynamic',
    description: '依据入口和沙箱参数在本地授权沙箱发包，保存请求/响应与触发点结果；不改变沙箱策略',
    descriptionEn: 'Probe inside the authorized local sandbox from entry/sandbox params; persist request/response and trigger results without changing sandbox policy'
  },
  PATH_EXPLORATION: {
    name: '路径探索',
    nameEn: 'Path exploration',
    chip: '路径',
    chipEn: 'Path',
    description: '消费 PathRun、请求和响应结果，建立数据/状态转换路径；不把未执行候选写成事实',
    descriptionEn: 'Consume PathRuns and request/response results to model data/state paths; never treat unexecuted candidates as facts'
  },
  VULNERABILITY_TRIAGE: {
    name: '漏洞研判',
    nameEn: 'Vulnerability triage',
    chip: '研判',
    chipEn: 'Triage',
    description: '基于鉴权分析、动态验证和路径结果研判；动态调试未闭环时不得标记漏洞存在',
    descriptionEn: 'Triage from auth, dynamic verification, and path results; do not mark a vulnerability present until dynamic debugging closes'
  },
  REPORT_GENERATION: {
    name: '报告生成',
    nameEn: 'Report generation',
    chip: '报告',
    chipEn: 'Report',
    description: '汇总证据等级、限制与未覆盖区域，输出可读审计报告',
    descriptionEn: 'Summarize evidence tiers, limits, and gaps into a readable audit report'
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

export const roleLabel = (role: string, english = false) => {
  const meta = AI_ROLE_META[role as AiRole]
  if (!meta) return role
  return english ? meta.nameEn : meta.name
}

export const outcomeClassLabel = (code: string | undefined, english = false) => {
  switch (code) {
    case 'COLD_START':
      return english ? 'Cold start' : '冷启动'
    case 'AUTH_CHALLENGE':
      return english ? 'Auth challenge' : '鉴权挑战'
    case 'REACHED_NO_BIND':
      return english ? 'Reached, unbound' : '到达未绑定'
    case 'BUSINESS_TIMEOUT':
      return english ? 'Business timeout' : '业务超时'
    case 'ENGINE_BUSY':
      return english ? 'Engine busy' : '引擎繁忙'
    case 'DEPENDENCY_MOCK_GAP':
      return english ? 'Dependency mock gap' : '依赖替身缺口'
    case 'TRANSPORT_ERROR':
      return english ? 'Transport error' : '传输错误'
    case 'PROBE_BUDGET':
      return english ? 'Probe budget exhausted' : '探针预算用尽'
    case 'IDENTITY_UNAVAILABLE':
      return english ? 'Identity unavailable' : '身份不可用'
    case 'HTTP_OBSERVED':
      return english ? 'HTTP observed' : 'HTTP 已观测'
    case 'UNKNOWN':
      return english ? 'Unknown' : '未知'
    default:
      return code ?? (english ? 'Unknown' : '未知')
  }
}

export const dependencyModeLabel = (mode: DependencyMode | string | undefined, english = false) => {
  switch (mode) {
    case 'MOCK':
      return english ? 'Mock execution' : '替身执行'
    case 'REPLAY':
      return english ? 'Recorded replay' : '录制回放'
    case 'LIVE_DISABLED':
      return english ? 'Live dependencies disabled' : '真实依赖已禁用'
    case 'LIVE':
      return english ? 'Live dependencies' : '真实依赖'
    default:
      return mode && mode !== 'unknown' ? String(mode) : (english ? 'Unknown' : '未知')
  }
}

export const jobStatusLabel = (status: string | undefined, english = false) => {
  switch (status) {
    case 'QUEUED':
      return english ? 'Queued' : '排队中'
    case 'LEASED':
      return english ? 'Leased' : '已领取'
    case 'RUNNING':
      return english ? 'Running' : '执行中'
    case 'COMPLETED':
      return english ? 'Completed' : '已完成'
    case 'FAILED':
      return english ? 'Failed' : '失败'
    case 'CANCELLED':
      return english ? 'Cancelled' : '已取消'
    case 'BLOCKED':
      return english ? 'Blocked' : '已阻断'
    default:
      return status ?? (english ? 'Unknown' : '未知')
  }
}

/** BLOCKED / 无 Worker / projection 失败优先使用 errorCode 感知标签（P1-23）。 */
export const pipelineStatusLabel = (status: string | undefined, errorCode?: string | undefined, english = false) => {
  const code = (errorCode ?? '').toUpperCase()
  if (code === 'WORKER_UNAVAILABLE' || code === 'NO_WORKER') {
    return english ? 'No Worker / Worker unavailable' : '无 Worker / Worker 不可用'
  }
  if (code === 'PROJECTION_FAILED' || code === 'TRACE_PROJECTION_FAILED') {
    return english ? 'Evidence projection failed' : '证据投影失败'
  }
  if (status === 'BLOCKED') return english ? 'Blocked' : '已阻断'
  return jobStatusLabel(status, english)
}

export const stopReasonLabel = (reason: string | undefined, english = false) => {
  switch (reason) {
    case 'LEASE_EXPIRED':
      return english ? 'Lease expired / reclaimed' : '租约过期已回收'
    case 'WORKER_FAILURE':
      return english ? 'Worker failure' : 'Worker 失败'
    case 'WORKER_UNAVAILABLE':
      return english ? 'No Worker / Worker unavailable' : '无 Worker / Worker 不可用'
    case 'PROJECTION_FAILED':
      return english ? 'Evidence projection failed' : '证据投影失败'
    case 'USER_CANCELLED':
      return english ? 'Cancelled' : '已取消'
    case 'OPERATOR_PAUSED':
      return english ? 'Paused by operator' : '操作员已暂停'
    case 'OPERATOR_CANCELLED':
      return english ? 'Stopped by operator' : '操作员已停止'
    case 'COMPLETED':
      return english ? 'Completed' : '已完成'
    default:
      return reason ?? ''
  }
}

export const timelineStateLabel = (state: string, english = false) => {
  switch (state) {
    case 'completed':
      return english ? 'Completed' : '已完成'
    case 'active':
      return english ? 'In progress' : '进行中'
    case 'waiting':
      return english ? 'Waiting' : '等待中'
    case 'unavailable':
      return english ? 'Unavailable' : '不可用'
    case 'skipped':
      return english ? 'Skipped' : '已跳过'
    default:
      return state
  }
}

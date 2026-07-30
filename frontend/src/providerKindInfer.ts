import type { ProviderKind } from './api/types'

/** 后端协议探测结果（密钥不得出现在此结构或日志中）。 */
export type ProtocolDetectStatus = 'UNIQUE' | 'MULTIPLE' | 'NONE'

export type ProtocolDetectCandidate = {
  kind: ProviderKind
  viable: boolean
  reasonCode: string
  detail: string
  httpStatus?: number
}

export type ProtocolDetectResult = {
  schemaVersion: number
  baseUrl: string
  status: ProtocolDetectStatus
  recommendedKind?: ProviderKind
  hint?: string
  probedAt: string
  candidates: ProtocolDetectCandidate[]
}

export const providerKindLabel = (kind: ProviderKind, english: boolean): string => {
  if (kind === 'OPENAI_CHAT') return english ? 'OpenAI Chat' : 'OpenAI Chat 协议'
  if (kind === 'ANTHROPIC_MESSAGES') return english ? 'Anthropic Messages' : 'Anthropic Messages 协议'
  if (kind === 'OPENAI_COMPATIBLE') return english ? 'OpenAI-compatible (legacy)' : 'OpenAI 兼容（旧类型）'
  if (kind === 'AZURE_OPENAI') return english ? 'Azure OpenAI' : 'Azure OpenAI'
  if (kind === 'LOCAL') return english ? 'Local (legacy)' : '本地（旧类型）'
  return kind
}

export const viableCandidates = (result: ProtocolDetectResult): ProtocolDetectCandidate[] =>
  result.candidates.filter((item) => item.viable)

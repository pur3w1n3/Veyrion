import type { ProviderDto, ProviderKind, ProviderModelInventoryDto, RoleAssignmentDto, AiRole } from './types'
import {
  asText,
  optionalText,
  strictOptionalText,
  asBoolean,
  schemaVersion,
  isRecord,
  unwrap,
  parseList,
} from './helpers'

export const parseProvider = (value: unknown): ProviderDto => {
  const body = unwrap(value, 'provider')
  if (!isRecord(body)) throw new Error('invalid provider response')
  const kind = asText(body.kind, 'provider.kind') as ProviderKind
  if (!['OPENAI_CHAT', 'ANTHROPIC_MESSAGES', 'OPENAI_COMPATIBLE', 'AZURE_OPENAI', 'LOCAL'].includes(kind)) {
    throw new Error('invalid provider.kind')
  }
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : body.schemaVersion, 'provider.schemaVersion', false),
    providerId: asText(body.providerId ?? body.id, 'provider.providerId'),
    name: asText(body.name, 'provider.name'),
    kind,
    baseUrl: optionalText(body.baseUrl),
    model: optionalText(body.model),
    enabled: body.enabled === undefined ? true : asBoolean(body.enabled, 'provider.enabled'),
    hasCredential: body.hasCredential === undefined ? false : asBoolean(body.hasCredential, 'provider.hasCredential'),
    updatedAt: optionalText(body.updatedAt)
  }
}

export const parseProviderModelInventory = (value: unknown): ProviderModelInventoryDto => {
  if (!isRecord(value) || !Array.isArray(value.models)) throw new Error('invalid provider inventory response')
  const protocol = asText(value.protocol, 'providerInventory.protocol')
  if (protocol !== 'OPENAI_CHAT' && protocol !== 'ANTHROPIC_MESSAGES') {
    throw new Error('invalid providerInventory.protocol')
  }
  if (value.semantics !== 'REMOTE_INVENTORY_ONLY') {
    throw new Error('invalid providerInventory.semantics')
  }
  const providerId = asText(value.providerId, 'providerInventory.providerId')
  return {
    schemaVersion: schemaVersion(value.schemaVersion, 'providerInventory.schemaVersion'),
    workspaceId: asText(value.workspaceId, 'providerInventory.workspaceId'),
    providerId,
    protocol,
    semantics: 'REMOTE_INVENTORY_ONLY',
    fetchedAt: asText(value.fetchedAt, 'providerInventory.fetchedAt'),
    models: value.models.map((item) => {
      if (!isRecord(item)
          || item.providerId !== providerId
          || item.enabled !== false
          || item.contextWindowTokens !== 0) {
        throw new Error('invalid providerInventory.models')
      }
      return {
        schemaVersion: schemaVersion(item.schemaVersion, 'providerInventory.model.schemaVersion'),
        modelId: asText(item.modelId, 'providerInventory.model.modelId'),
        providerId,
        providerModelName: asText(item.providerModelName, 'providerInventory.model.providerModelName'),
        contextWindowTokens: 0,
        enabled: false
      }
    })
  }
}

export const parseRoleAssignment = (value: unknown): RoleAssignmentDto => {
  const body = unwrap(value, 'roleAssignment')
  if (!isRecord(body)) throw new Error('invalid role assignment response')
  const role = asText(body.role, 'roleAssignment.role') as AiRole
  if (!['PRE_ANALYSIS', 'AUTH_ANALYSIS', 'PATH_EXPLORATION', 'DYNAMIC_VERIFICATION', 'VULNERABILITY_TRIAGE', 'REPORT_GENERATION'].includes(role)) throw new Error('invalid roleAssignment.role')
  // 控制面在 promptZh/promptEn 上 wire 后发出 schemaVersion 2（V010+）。
  const rawSchema = isRecord(value) && value.schemaVersion !== undefined
    ? value.schemaVersion
    : body.schemaVersion
  const assignmentSchema = rawSchema === undefined
    ? 2
    : Number.isSafeInteger(rawSchema) && (rawSchema === 1 || rawSchema === 2)
      ? rawSchema
      : (() => { throw new Error('unsupported roleAssignment.schemaVersion') })()
  return {
    schemaVersion: assignmentSchema,
    projectId: asText(body.projectId, 'roleAssignment.projectId'),
    role,
    providerId: asText(body.providerId, 'roleAssignment.providerId'),
    model: optionalText(body.model),
    updatedAt: optionalText(body.updatedAt),
    promptZh: optionalText(body.promptZh),
    promptEn: optionalText(body.promptEn)
  }
}


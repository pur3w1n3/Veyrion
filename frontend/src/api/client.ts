import type {
  SentinelApi,
  ApiMode,
  DashboardSnapshot,
  RetryAuditStageRequest,
  RetryAuditStageResult,
  ProjectDto,
  CreateProjectRequest,
  UpdateProjectRequest,
  UpdateArtifactRequest,
  ArtifactDto,
  RegisterArtifactRequest,
  UploadProgressHandler,
  UploadTask,
  ScanDto,
  CreateScanRequest,
  StartAuditRequest,
  AuditRunDto,
  DynamicTaskDto,
  FindingReplayDto,
  FocusEntryProbeRequest,
  FocusEntryProbeDto,
  UpdateScanRequest,
  ProviderDto,
  SaveProviderRequest,
  DetectProviderProtocolRequest,
  ProtocolDetectResultDto,
  ProviderModelInventoryDto,
  RoleAssignmentDto,
  AiRole,
  SaveRoleAssignmentRequest,
  AiJobDto,
  CreateAiJobRequest,
  AiJobEventDto,
  EntryDto,
  CoverageMatrixDto,
  EvidenceGraphDto,
  ScanHypothesesDto,
  EvidenceDto,
  ScanEvent,
  ScanEventType,
  SubscribeOptions,
} from './types'
import {
  ApiUnavailableError,
  ApiRequestError,
  UploadCancelledError,
  ARTIFACT_UPLOAD_CHUNK_BYTES,
  MAX_BROWSER_HASH_BYTES,
} from './types'
import {
  asText,
  asBoolean,
  asSafeInteger,
  schemaVersion,
  isRecord,
  unwrap,
  parseList,
} from './helpers'
import {
  parseDashboard,
  parseFindingReplay,
  parseFocusEntryProbe,
  parseEntries,
  parseScan,
  parseDynamicTask,
  parseCoverageMatrix,
  parseEvidenceGraph,
  parseScanHypotheses,
  parseEvidence,
  parseScanEvent,
} from './scans'
import { parseProject } from './projects'
import { parseArtifact } from './artifacts'
import { parseProvider, parseProviderModelInventory, parseProtocolDetectResult, parseRoleAssignment } from './providers'
import { parseAiJob, parseAuditRun, parseAiJobEvents } from './ai'

const jsonHeaders = (token?: string): HeadersInit => {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  return headers
}

let idempotencySequence = 0
const generatedIdempotencyKey = (): string => {
  const randomUuid = globalThis.crypto?.randomUUID?.()
  if (randomUuid) return `gui-${randomUuid}`
  idempotencySequence = (idempotencySequence + 1) % 1_000_000
  return `gui-${Date.now().toString(36)}-${idempotencySequence.toString(36)}`
}

const idempotencyKeyFor = (candidate?: string): string => {
  if (candidate === undefined) return generatedIdempotencyKey()
  if (typeof candidate !== 'string' || candidate.trim() === '' || candidate.length > 256 || /\s/.test(candidate)) throw new Error('invalid idempotencyKey')
  return candidate
}

const mutationHeaders = (token: string | undefined, idempotencyKey: string): HeadersInit => ({
  ...jsonHeaders(token),
  'Content-Type': 'application/json',
  'Idempotency-Key': idempotencyKey
})

type FetchLike = typeof fetch

const sha256Hex = async (blob: Blob): Promise<string> => {
  if (!globalThis.crypto?.subtle) throw new Error('当前浏览器不支持 Web Crypto SHA-256')
  const digest = await globalThis.crypto.subtle.digest('SHA-256', await blob.arrayBuffer())
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

const boundedErrorText = async (response: Response, maxBytes = 8192): Promise<string | undefined> => {
  const declaredLength = Number(response.headers.get('content-length'))
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) return undefined
  if (!response.body) {
    const text = await response.text()
    return text.length <= maxBytes ? text : undefined
  }
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let total = 0
  let text = ''
  try {
    while (true) {
      const part = await reader.read()
      if (part.done) break
      total += part.value.byteLength
      if (total > maxBytes) {
        await reader.cancel()
        return undefined
      }
      text += decoder.decode(part.value, { stream: true })
    }
    text += decoder.decode()
    return text
  } catch {
    return undefined
  } finally {
    reader.releaseLock()
  }
}

const safeErrorField = (value: unknown, maxLength: number): string | undefined => {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || /[\u0000-\u001f\u007f-\u009f]/.test(value)) return undefined
  return value
}

const parseAllowlistedError = async (response: Response): Promise<{ code?: string; message?: string; requestId?: string }> => {
  if (response.status < 400 || response.status >= 500
      || !response.headers.get('content-type')?.toLowerCase().includes('application/json')) return {}
  const text = await boundedErrorText(response)
  if (!text) return {}
  try {
    const value: unknown = JSON.parse(text)
    if (!isRecord(value)) return {}
    const code = safeErrorField(value.code, 64)
    const message = safeErrorField(value.message, 512)
    const requestId = safeErrorField(value.requestId, 128)
    return {
      code: code && /^[A-Za-z0-9_.-]+$/.test(code) ? code : undefined,
      message,
      requestId: requestId && /^[A-Za-z0-9_.:-]+$/.test(requestId) ? requestId : undefined
    }
  } catch {
    return {}
  }
}

const uploadTask = (promise: Promise<ArtifactDto>, controller: AbortController): UploadTask =>
  Object.assign(promise, { cancel: () => controller.abort() })

export class HttpSentinelApi implements SentinelApi {
  readonly mode: ApiMode = 'control-plane'
  private readonly fetchFn: FetchLike
  private readonly token?: string

  constructor(private readonly baseUrl: string, private readonly projectId = '', options: { token?: string; fetchFn?: FetchLike; fetch?: FetchLike } = {}) {
    // 构造时 projectId 可选：工作区首页可在选定工作区前列表/创建项目。按项目调用仍需显式 id。
    if (!baseUrl) throw new Error('Control Plane baseUrl is required')
    const fetchFn = options.fetchFn ?? options.fetch ?? fetch
    // 保持原生 fetch 与本 API 实例分离。以 this.fetchFn(...) 调用存储的浏览器 fetch 会绑定错误 receiver，Chrome 会在任何网络请求发出前拒绝调用。
    this.fetchFn = (input, init) => fetchFn(input, init)
    this.token = options.token ?? import.meta.env.VITE_API_TOKEN
  }

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/$/, '')}/${path.replace(/^\//, '')}`
  }

  private async request(path: string, init: RequestInit, operation: string): Promise<unknown> {
    let response: Response
    try {
      response = await this.fetchFn(this.url(path), init)
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw new UploadCancelledError()
      throw new ApiUnavailableError(operation, undefined, { cause: error })
    }
    if (response.ok === false || (typeof response.status === 'number' && response.status >= 400)) {
      // 仅客户端/校验失败的小规模白名单 JSON 形态可安全渲染。HTML、5xx 诊断与任意字段永不传播。
      const detail = await parseAllowlistedError(response)
      if ([404, 405, 501, 502, 503, 504].includes(response.status)) throw new ApiUnavailableError(operation, response.status)
      const requestSuffix = detail.requestId ? `（请求 ${detail.requestId}）` : ''
      const codeSuffix = detail.code ? ` [${detail.code}]` : ''
      if (detail.code === 'AUTHORIZATION_REQUIRED') {
        throw new ApiRequestError(
          `本地授权令牌缺失或已失效${codeSuffix}${requestSuffix}。请用 Start-Veyrion.ps1 同时重启控制面与界面（不要只开前端）；启动器会把令牌写入 frontend/.env.local。`,
          response.status,
          detail.code,
          detail.requestId
        )
      }
      if (detail.code === 'DYNAMIC_TASK_BUSY') {
        throw new ApiRequestError(
          `该扫描仍有进行中的动态任务${codeSuffix}${requestSuffix}。请稍候任务结束，或在「审计执行」对「断网容器按轨动态观察」点重试（服务端会取消卡住的任务后再排队）。请求不会回退到演示数据。`,
          response.status,
          detail.code,
          detail.requestId
        )
      }
      if (detail.code === 'SCAN_ACTIVE') {
        throw new ApiRequestError(
          `无法删除：该扫描仍有进行中的任务或模型作业未能取消${codeSuffix}${requestSuffix}。请稍后重试，或到「审计执行」取消后再删。`,
          response.status,
          detail.code,
          detail.requestId
        )
      }
      throw new ApiRequestError(detail.message ? `${detail.message}${codeSuffix}${requestSuffix}` : `${operation} failed: ${response.status}`, response.status, detail.code, detail.requestId)
    }
    if (response.status === 204) return {}
    try {
      return await response.json()
    } catch (error) {
      throw new Error(`${operation} failed: invalid JSON response`, { cause: error })
    }
  }

  async loadDashboard(projectId = this.projectId, scanId?: string): Promise<DashboardSnapshot> {
    const query = scanId && scanId !== 'unscanned'
      ? `?scanId=${encodeURIComponent(asText(scanId, 'scanId'))}`
      : ''
    const body = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/dashboard${query}`, {
      credentials: 'include',
      headers: jsonHeaders(this.token)
    }, 'dashboard request')
    return parseDashboard(body)
  }

  async retryAuditStage(projectId: string, request: RetryAuditStageRequest): Promise<RetryAuditStageResult> {
    const body: Record<string, unknown> = {
      scanId: request.scanId,
      stage: request.stage,
      authorized: true
    }
    if (request.aiAuthorized) body.aiAuthorized = true
    if (request.outputLanguage) body.outputLanguage = request.outputLanguage
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/audit-stage-retries`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: JSON.stringify(body)
    }, 'retry audit stage')
    if (!isRecord(response)) throw new Error('invalid audit stage retry response')
    return {
      schemaVersion: schemaVersion(response.schemaVersion, 'retry.schemaVersion'),
      projectId: asText(response.projectId, 'retry.projectId'),
      scanId: asText(response.scanId, 'retry.scanId'),
      stage: asText(response.stage, 'retry.stage'),
      pipelineArmed: asBoolean(response.pipelineArmed, 'retry.pipelineArmed'),
      aiJob: response.aiJob === undefined ? undefined : parseAiJob(response.aiJob),
      dynamicTask: response.dynamicTask === undefined ? undefined : parseDynamicTask(response.dynamicTask)
    }
  }

  async listProjects(): Promise<ProjectDto[]> {
    const response = await this.request('projects', { credentials: 'include', headers: jsonHeaders(this.token) }, 'list projects')
    return parseList(response, 'projects', parseProject)
  }

  async getProject(projectId: string): Promise<ProjectDto> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'get project')
    return parseProject(response)
  }

  async createProject(request: CreateProjectRequest | string): Promise<ProjectDto> {
    const body: CreateProjectRequest = typeof request === 'string' ? { name: request } : request
    if (!body || typeof body.name !== 'string' || body.name.trim() === '') throw new Error('project name is required')
    const { idempotencyKey, ...wireBody } = body
    const requestKey = idempotencyKeyFor(idempotencyKey)
    const response = await this.request('projects', {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, requestKey), body: JSON.stringify(wireBody)
    }, 'create project')
    return parseProject(response)
  }

  async updateProject(projectId: string, request: UpdateProjectRequest): Promise<ProjectDto> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'update project')
    return parseProject(response)
  }

  async deleteProject(projectId: string): Promise<void> {
    await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete project')
  }

  async listArtifacts(projectId: string): Promise<ArtifactDto[]> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifacts`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'list artifacts')
    return parseList(response, 'artifacts', parseArtifact)
  }

  async registerArtifact(request: RegisterArtifactRequest | string, projectId = this.projectId): Promise<ArtifactDto> {
    const body: RegisterArtifactRequest = typeof request === 'string' ? { path: request } : request
    if (!body || typeof body.path !== 'string' || body.path.trim() === '') throw new Error('artifact path is required')
    const { idempotencyKey, ...wireBody } = body
    const requestKey = idempotencyKeyFor(idempotencyKey)
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifacts`, {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, requestKey), body: JSON.stringify(wireBody)
    }, 'register artifact')
    return parseArtifact(response)
  }

  uploadArtifact(file: File, projectId: string, onProgress: UploadProgressHandler): UploadTask {
    const controller = new AbortController()
    const promise = this.performArtifactUpload(file, projectId, onProgress, controller.signal)
    return uploadTask(promise, controller)
  }

  private async performArtifactUpload(file: File, projectId: string, onProgress: UploadProgressHandler, signal: AbortSignal): Promise<ArtifactDto> {
    if (!(file instanceof File)) throw new Error('请选择要上传的制品文件')
    const type = file.name.split('.').pop()?.toUpperCase()
    if (type !== 'JAR' && type !== 'WAR' && type !== 'CLASS') throw new Error('仅支持 .jar、.war 或 .class 文件')
    if (file.size <= 0) throw new Error('不能上传空文件')
    if (file.size > MAX_BROWSER_HASH_BYTES) throw new Error(`文件超过浏览器摘要上限 ${MAX_BROWSER_HASH_BYTES / 1024 / 1024} MiB；请使用高级/兼容方式登记`)
    if (typeof onProgress !== 'function') throw new Error('upload progress handler is required')

    let uploadId: string | undefined
    let completed = false
    try {
      if (signal.aborted) throw new UploadCancelledError()
      onProgress(0)
      const fileSha256 = await sha256Hex(file)
      if (signal.aborted) throw new UploadCancelledError()
      const initialized = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifact-uploads`, {
        method: 'POST',
        credentials: 'include',
        headers: mutationHeaders(this.token, generatedIdempotencyKey()),
        body: JSON.stringify({ fileName: file.name, sizeBytes: file.size, sha256: fileSha256 }),
        signal
      }, 'initialize artifact upload')
      const session = unwrap(initialized, 'upload')
      if (!isRecord(session)) throw new Error('invalid artifact upload response')
      uploadId = asText(session.uploadId, 'upload.uploadId')
      if (session.recommendedChunkBytes !== undefined && asSafeInteger(session.recommendedChunkBytes, 'upload.recommendedChunkBytes', 1) !== ARTIFACT_UPLOAD_CHUNK_BYTES) {
        throw new Error('unsupported artifact upload chunk size')
      }
      const uploadPath = `projects/${encodeURIComponent(projectId)}/artifact-uploads/${encodeURIComponent(uploadId)}`

      for (let offset = 0; offset < file.size; offset += ARTIFACT_UPLOAD_CHUNK_BYTES) {
        if (signal.aborted) throw new UploadCancelledError()
        const chunk = file.slice(offset, Math.min(offset + ARTIFACT_UPLOAD_CHUNK_BYTES, file.size))
        const chunkSha256 = await sha256Hex(chunk)
        await this.request(`${uploadPath}?offset=${offset}`, {
          method: 'PUT',
          credentials: 'include',
          headers: {
            ...jsonHeaders(this.token),
            'Content-Type': 'application/octet-stream',
            'X-Chunk-SHA256': chunkSha256
          },
          body: chunk,
          signal
        }, 'upload artifact chunk')
        onProgress(Math.min(99, Math.round(((offset + chunk.size) / file.size) * 100)))
      }

      const result = await this.request(`${uploadPath}/complete`, {
        method: 'POST',
        credentials: 'include',
        headers: mutationHeaders(this.token, generatedIdempotencyKey()),
        body: JSON.stringify({ authorized: true }),
        signal
      }, 'complete artifact upload')
      completed = true
      onProgress(100)
      return parseArtifact(result)
    } finally {
      if (uploadId && !completed) {
        try {
          await this.request(`projects/${encodeURIComponent(projectId)}/artifact-uploads/${encodeURIComponent(uploadId)}`, {
            method: 'DELETE',
            credentials: 'include',
            headers: mutationHeaders(this.token, generatedIdempotencyKey())
          }, 'cancel artifact upload')
        } catch {
          // 取消为尽力而为，不得掩盖原始错误。
        }
      }
    }
  }

  async updateArtifact(projectId: string, artifactId: string, request: UpdateArtifactRequest): Promise<ArtifactDto> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifacts/${encodeURIComponent(asText(artifactId, 'artifactId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'update artifact')
    return parseArtifact(response)
  }

  async deleteArtifact(projectId: string, artifactId: string): Promise<void> {
    await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/artifacts/${encodeURIComponent(asText(artifactId, 'artifactId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete artifact')
  }

  async listScans(projectId: string): Promise<ScanDto[]> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/scans`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'list scans')
    return parseList(response, 'scans', parseScan)
  }

  async createScan(request: CreateScanRequest | string = {}, projectId = this.projectId): Promise<ScanDto> {
    const normalizedRequest: CreateScanRequest = typeof request === 'string' ? { artifactDigest: request } : request
    const { policy, idempotencyKey, ...scanFields } = normalizedRequest
    const requestKey = idempotencyKeyFor(idempotencyKey)
    const body: Record<string, unknown> = { ...scanFields }
    // 保持 wire 合同显式。策略编辑器中的未知值不转发到服务端，不能意外扩大其授权或沙箱策略。
    if (policy) {
      const policyKeys = ['authorized', 'networkMode', 'dangerousActionMode', 'networkAllowlist', 'maxWallClockSeconds', 'maxMemoryBytes', 'maxDiskBytes'] as const
      for (const key of policyKeys) if (body[key] === undefined && policy[key] !== undefined) body[key] = policy[key]
    }
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/scans`, {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, requestKey), body: JSON.stringify(body)
    }, 'create scan')
    return parseScan(response)
  }

  async startAudit(projectId: string, request: StartAuditRequest): Promise<AuditRunDto> {
    const { policy, idempotencyKey, ...auditFields } = request
    const body: Record<string, unknown> = { ...auditFields }
    if (policy) {
      const policyKeys = ['authorized', 'networkMode', 'dangerousActionMode', 'networkAllowlist', 'maxWallClockSeconds', 'maxMemoryBytes', 'maxDiskBytes'] as const
      for (const key of policyKeys) if (body[key] === undefined && policy[key] !== undefined) body[key] = policy[key]
    }
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/audit-runs`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, idempotencyKeyFor(idempotencyKey)),
      body: JSON.stringify(body)
    }, 'start audit')
    return parseAuditRun(response)
  }

  async createDynamicTask(scanId: string): Promise<DynamicTaskDto> {
    const response = await this.request(`scans/${encodeURIComponent(asText(scanId, 'scanId'))}/dynamic-tasks`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: JSON.stringify({ authorized: true })
    }, 'create trusted Docker artifact task')
    return parseDynamicTask(response)
  }

  async listDynamicTasks(scanId: string): Promise<DynamicTaskDto[]> {
    const response = await this.request(`scans/${encodeURIComponent(asText(scanId, 'scanId'))}/dynamic-tasks`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'list dynamic tasks')
    return parseList(response, 'dynamicTasks', parseDynamicTask)
  }

  async replayFinding(findingId: string): Promise<FindingReplayDto> {
    const response = await this.request(`findings/${encodeURIComponent(asText(findingId, 'findingId'))}/replay`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: JSON.stringify({ authorized: true })
    }, 'replay finding')
    return parseFindingReplay(response)
  }

  async focusEntryProbe(scanId: string, entryId: string, body?: FocusEntryProbeRequest): Promise<FocusEntryProbeDto> {
    const payload: FocusEntryProbeRequest = { ...body, authorized: true }
    const response = await this.request(
      `scans/${encodeURIComponent(asText(scanId, 'scanId'))}/entries/${encodeURIComponent(asText(entryId, 'entryId'))}/focus-probe`,
      {
        method: 'POST',
        credentials: 'include',
        headers: mutationHeaders(this.token, generatedIdempotencyKey()),
        body: JSON.stringify(payload)
      },
      'focus entry probe'
    )
    return parseFocusEntryProbe(response)
  }

  async replaySqlExperimentCard(scanId: string, cardId: string): Promise<FocusEntryProbeDto> {
    const response = await this.request(
      `scans/${encodeURIComponent(asText(scanId, 'scanId'))}/experiment-cards/${encodeURIComponent(asText(cardId, 'cardId'))}/replay`,
      {
        method: 'POST',
        credentials: 'include',
        headers: mutationHeaders(this.token, generatedIdempotencyKey()),
        body: JSON.stringify({ authorized: true })
      },
      'replay sql experiment card'
    )
    return parseFocusEntryProbe(response)
  }

  async updateScan(scanId: string, request: UpdateScanRequest): Promise<ScanDto> {
    const body: Record<string, unknown> = {
      action: request.action,
      authorized: true
    }
    if (request.aiAuthorized) body.aiAuthorized = true
    if (request.outputLanguage) body.outputLanguage = request.outputLanguage
    const response = await this.request(`scans/${encodeURIComponent(asText(scanId, 'scanId'))}`, {
      method: 'PATCH',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: JSON.stringify(body)
    }, 'update scan')
    return parseScan(response)
  }

  async deleteScan(projectId: string, scanId: string): Promise<void> {
    // 204 No Content = 成功；409 SCAN_ACTIVE 等错误抛异常（永不静默成功）。
    await this.request(
      `projects/${encodeURIComponent(asText(projectId, 'projectId'))}/scans/${encodeURIComponent(asText(scanId, 'scanId'))}`,
      {
        method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
      },
      'delete scan'
    )
  }

  async listProviders(): Promise<ProviderDto[]> {
    const response = await this.request('providers', { credentials: 'include', headers: jsonHeaders(this.token) }, 'list providers')
    return parseList(response, 'providers', parseProvider)
  }

  async createProvider(request: SaveProviderRequest): Promise<ProviderDto> {
    const response = await this.request('providers', {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'create provider')
    return parseProvider(response)
  }

  async updateProvider(providerId: string, request: Partial<SaveProviderRequest>): Promise<ProviderDto> {
    const response = await this.request(`providers/${encodeURIComponent(asText(providerId, 'providerId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'update provider')
    return parseProvider(response)
  }

  async deleteProvider(providerId: string): Promise<void> {
    await this.request(`providers/${encodeURIComponent(asText(providerId, 'providerId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete provider')
  }

  async detectProviderProtocol(request: DetectProviderProtocolRequest): Promise<ProtocolDetectResultDto> {
    const response = await this.request('providers/detect-protocol', {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: JSON.stringify(request)
    }, 'detect provider protocol')
    return parseProtocolDetectResult(response)
  }

  async refreshProviderModels(providerId: string): Promise<ProviderModelInventoryDto> {
    const response = await this.request(`providers/${encodeURIComponent(asText(providerId, 'providerId'))}/models/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: mutationHeaders(this.token, generatedIdempotencyKey()),
      body: '{}'
    }, 'refresh provider models')
    return parseProviderModelInventory(response)
  }

  async listRoleAssignments(projectId: string): Promise<RoleAssignmentDto[]> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/role-assignments`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'list role assignments')
    return parseList(response, 'roleAssignments', parseRoleAssignment)
  }

  async saveRoleAssignment(projectId: string, role: AiRole, request: SaveRoleAssignmentRequest): Promise<RoleAssignmentDto> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/role-assignments/${encodeURIComponent(role)}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(request)
    }, 'save role assignment')
    return parseRoleAssignment(response)
  }

  async deleteRoleAssignment(projectId: string, role: AiRole): Promise<void> {
    await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/role-assignments/${encodeURIComponent(role)}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete role assignment')
  }

  async listAiJobs(projectId: string): Promise<AiJobDto[]> {
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/ai-jobs`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'list ai jobs')
    return parseList(response, 'aiJobs', parseAiJob)
  }

  async createAiJob(projectId: string, request: CreateAiJobRequest): Promise<AiJobDto> {
    const body: CreateAiJobRequest = {
      role: request.role,
      authorized: request.authorized,
      scanId: request.scanId,
      outputLanguage: request.outputLanguage
    }
    const response = await this.request(`projects/${encodeURIComponent(asText(projectId, 'projectId'))}/ai-jobs`, {
      method: 'POST', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify(body)
    }, 'create ai job')
    return parseAiJob(response)
  }

  async getAiJob(aiJobId: string): Promise<AiJobDto> {
    const response = await this.request(`ai-jobs/${encodeURIComponent(asText(aiJobId, 'aiJobId'))}`, { credentials: 'include', headers: jsonHeaders(this.token) }, 'get ai job')
    return parseAiJob(response)
  }

  async listAiJobEvents(aiJobId: string): Promise<AiJobEventDto[]> {
    const response = await this.request(`ai-jobs/${encodeURIComponent(asText(aiJobId, 'aiJobId'))}/events`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'list AI job events')
    return parseAiJobEvents(response)
  }

  async updateAiJob(aiJobId: string, action: 'cancel' | 'retry'): Promise<AiJobDto> {
    const response = await this.request(`ai-jobs/${encodeURIComponent(asText(aiJobId, 'aiJobId'))}`, {
      method: 'PATCH', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey()), body: JSON.stringify({ action })
    }, 'update ai job')
    return parseAiJob(response)
  }

  async deleteAiJob(aiJobId: string): Promise<void> {
    await this.request(`ai-jobs/${encodeURIComponent(asText(aiJobId, 'aiJobId'))}`, {
      method: 'DELETE', credentials: 'include', headers: mutationHeaders(this.token, generatedIdempotencyKey())
    }, 'delete ai job')
  }

  async getEntries(projectId = this.projectId, scanId?: string): Promise<EntryDto[]> {
    const query = scanId ? `?scanId=${encodeURIComponent(asText(scanId, 'scanId'))}` : ''
    const response = await this.request(`projects/${encodeURIComponent(projectId)}/entries${query}`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'entries request')
    return parseEntries(response)
  }

  async getScan(scanId: string): Promise<ScanDto> {
    const id = asText(scanId, 'scanId')
    const response = await this.request(`scans/${encodeURIComponent(id)}`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'scan request')
    return parseScan(response)
  }

  async getScanCoverage(scanId: string): Promise<CoverageMatrixDto> {
    const id = asText(scanId, 'scanId')
    const response = await this.request(`scans/${encodeURIComponent(id)}/coverage`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'scan coverage request')
    return parseCoverageMatrix(response)
  }

  async getEvidenceGraph(scanId: string): Promise<EvidenceGraphDto> {
    const id = asText(scanId, 'scanId')
    const response = await this.request(`scans/${encodeURIComponent(id)}/evidence-graph`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'evidence graph request')
    return parseEvidenceGraph(response)
  }

  async getScanHypotheses(scanId: string): Promise<ScanHypothesesDto> {
    const id = asText(scanId, 'scanId')
    const response = await this.request(`scans/${encodeURIComponent(id)}/hypotheses`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'scan hypotheses request')
    return parseScanHypotheses(response)
  }

  async getScanAiMemory(scanId: string, section = 'FULL'): Promise<Record<string, unknown>> {
    const id = asText(scanId, 'scanId')
    const sec = encodeURIComponent(section || 'FULL')
    const response = await this.request(`scans/${encodeURIComponent(id)}/ai-memory?section=${sec}`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'scan ai-memory request')
    if (!isRecord(response)) throw new Error('invalid ai-memory response')
    return response
  }

  async getEvidence(evidenceId: string): Promise<EvidenceDto> {
    const id = asText(evidenceId, 'evidenceId')
    const response = await this.request(`evidence/${encodeURIComponent(id)}`, {
      credentials: 'include', headers: jsonHeaders(this.token)
    }, 'evidence request')
    return parseEvidence(response)
  }

  subscribe(scanId: string, onEvent: (event: ScanEvent) => void, options: SubscribeOptions = {}): () => void {
    const id = asText(scanId, 'scanId')
    // EventSource 刻意基于 cookie/凭据。浏览器不允许 EventSource 自定义 Authorization 头；部署应对 SSE 端点使用 HttpOnly 同源 session。
    if (typeof EventSource === 'undefined') {
      const error = new Error('SSE is unavailable in this browser')
      options.onError?.(error)
      return () => undefined
    }
    const source = new EventSource(this.url(`scans/${encodeURIComponent(id)}/events`), { withCredentials: true })
    let closed = false
    let reconciling = false
    // EventSource 重连后可能重放最后事件，服务端也可合法同时发出命名事件与默认 message。保持有界幂等窗口，避免 UI 重复计数 finding。
    const seenEventIds = new Set<string>()
    const seenOrder: string[] = []
    const reconcile = () => {
      if (closed || reconciling) return
      reconciling = true
      void this.getScan(id).then((scan) => options.onReconcile?.(scan)).catch((error) => options.onError?.(error)).finally(() => { reconciling = false })
    }
    const handle = (message: MessageEvent<unknown>, eventName?: string) => {
      try {
        // MessageEvent.data 通常为字符串。为测试适配器与浏览器 polyfill 接受 object，但不弱化校验。
        const decoded = typeof message.data === 'string' ? JSON.parse(message.data) as unknown : message.data
        const inferredName = eventName ?? (typeof message.type === 'string' && message.type !== 'message' ? message.type : undefined)
        const event = parseScanEvent(decoded, inferredName)
        if (seenEventIds.has(event.eventId)) return
        seenEventIds.add(event.eventId)
        seenOrder.push(event.eventId)
        if (seenOrder.length > 512) {
          const expired = seenOrder.shift()
          if (expired) seenEventIds.delete(expired)
        }
        onEvent(event)
        reconcile()
        if (event.eventType === 'ScanCompleted' || event.eventType === 'TaskStopped') {
          // 服务端在终态事件后关闭有限重放流；浏览器侧也关闭，避免 EventSource 无限重连并重复拉取已不可变扫描。
          closed = true
          source.close()
        }
      } catch (error) {
        options.onError?.(error)
      }
    }
    source.onmessage = (message) => handle(message)
    source.onopen = () => reconcile()
    source.onerror = (error) => {
      if (closed) return
      // EventSource 在 OPEN/CONNECTING 时自动重试。每次 error 时对账，避免终态事件丢失后终态被隐藏。
      options.onError?.(error)
      reconcile()
    }
    const eventNames: ScanEventType[] = ['ScanCreated', 'TaskLeased', 'TraceCommitted', 'FindingUpdated', 'TaskStopped', 'ScanCompleted']
    const listeners: Array<{ name: string; listener: EventListener }> = []
    if (typeof source.addEventListener === 'function') {
      for (const name of eventNames) {
        const listener: EventListener = (event) => handle(event as MessageEvent<unknown>, name)
        source.addEventListener(name, listener)
        listeners.push({ name, listener })
      }
    }
    return () => {
      closed = true
      if (typeof source.removeEventListener === 'function') {
        for (const { name, listener } of listeners) source.removeEventListener(name, listener)
      }
      source.close()
    }
  }
}


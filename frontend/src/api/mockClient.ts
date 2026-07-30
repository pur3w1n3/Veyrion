import type {
  SentinelApi,
  ApiMode,
  DashboardSnapshot,
  RetryAuditStageResult,
  ProjectDto,
  CreateProjectRequest,
  ArtifactDto,
  RegisterArtifactRequest,
  UploadTask,
  ScanDto,
  CreateScanRequest,
  StartAuditRequest,
  AuditRunDto,
  DynamicTaskDto,
  FindingReplayDto,
  FocusEntryProbeDto,
  ProviderDto,
  ProviderModelInventoryDto,
  RoleAssignmentDto,
  AiJobDto,
  AiJobEventDto,
  EntryDto,
  CoverageMatrixDto,
  EvidenceGraphDto,
  ScanHypothesesDto,
  EvidenceDto,
  ScanEvent,
  SubscribeOptions,
} from './types'
import { ApiUnavailableError } from './types'

const demoSnapshot: DashboardSnapshot = {
  schemaVersion: 1,
  projectId: 'project-01',
  scanId: 'scan-07f2',
  dependencyMode: 'MOCK',
  entries: [
    { id: 'e-01', route: '/api/upload', method: 'POST', module: 'attachment', protocol: 'HTTP', precondition: '登录用户', status: 'DYNAMIC_SUSPECTED', coverage: 86 },
    { id: 'e-02', route: '/api/info', method: 'GET', module: 'diagnostics', protocol: 'HTTP', precondition: '同租户', status: 'VERIFIED', coverage: 94 },
    { id: 'e-03', route: '/api/run', method: 'POST', module: 'executor', protocol: 'HTTP', precondition: 'ROLE_ADMIN', status: 'STATIC_INFERRED', coverage: 61 },
    { id: 'e-04', route: '/ws/events', method: 'CONNECT', module: 'events', protocol: 'WebSocket', precondition: '未探索', status: 'UNREACHED', coverage: 0 }
  ],
  findings: [
    { id: 'f-01', title: '上传路径可控', severity: 'high', status: 'VERIFIED', entry: '/api/upload', sink: 'FileOutputStream', dependency: 'attachment.path', evidence: 12, hypothesisId: 'hyp-demo-df', securityProperty: 'DATAFLOW' },
    { id: 'f-02', title: '服务器路径信息泄露', severity: 'medium', status: 'VERIFIED', entry: '/api/info', sink: 'HTTP response', dependency: 'filesystem', evidence: 7 },
    { id: 'f-03', title: '文件内容进入执行器', severity: 'critical', status: 'DYNAMIC_SUSPECTED', entry: '/api/run', sink: 'ProcessBuilder', dependency: 'ROLE_ADMIN', evidence: 4 }
  ],
  hypotheses: [
    {
      schemaVersion: 1,
      hypothesisId: 'hyp-demo-df',
      scanId: 'scan-07f2',
      securityProperty: 'DATAFLOW',
      family: 'DATAFLOW',
      lifecycle: 'CANDIDATE',
      detectorVersion: 'demo/0.1',
      supportingEvidenceRefs: [],
      contradictingEvidenceRefs: [],
      coverageGapRefs: [],
      source: 'param:filename',
      effect: 'FileOutputStream'
    }
  ],
  paths: [],
  pathRuns: [],
  sqlExperimentCards: [],
  experimentPlans: [],
  experimentShapes: [],
  analysisPacks: [],
  probeBudget: { maxProbes: 0, plannedProbes: 0, unreachedEntries: 0, strategy: '', entryTrackPlans: [] },
  rankedSinks: [],
  ledgerDiff: { newlyMatched: [], regressions: [], unchangedCount: 0, coverageDelta: 0, summary: '' },
  verifiedFindings: [],
  path: [
    { label: 'POST /api/upload', detail: 'filename = ${safe-probe}', kind: 'entry', state: 'done' },
    { label: 'UploadService.save', detail: 'URLDecode → path concat', kind: 'transform', state: 'done' },
    { label: 'attachment.path', detail: 'table=attachment · mode=MOCK', kind: 'dependency', state: 'done' },
    { label: '路径限制分支', detail: 'synthetic user · branch covered', kind: 'branch', state: 'active' },
    { label: 'FileOutputStream', detail: '副作用已在临时工作区重放', kind: 'sink', state: 'active' }
  ]
}

const uploadTask = (promise: Promise<ArtifactDto>, controller: AbortController): UploadTask =>
  Object.assign(promise, { cancel: () => controller.abort() })
export class MockSentinelApi implements SentinelApi {
  readonly mode: ApiMode = 'demo'
  private unavailable(operation: string): never {
    throw new ApiUnavailableError(`${operation} (demo adapter)`)
  }

  async loadDashboard(_projectId?: string, _scanId?: string): Promise<DashboardSnapshot> {
    return structuredClone(demoSnapshot)
  }

  async retryAuditStage(): Promise<RetryAuditStageResult> {
    return this.unavailable('retry audit stage')
  }

  async listProjects(): Promise<ProjectDto[]> {
    return [{ schemaVersion: 1, projectId: 'project-01', name: 'Demo workspace', createdAt: new Date(0).toISOString() }]
  }

  async getProject(projectId: string): Promise<ProjectDto> {
    const project = (await this.listProjects()).find((item) => item.projectId === projectId)
    if (!project) return this.unavailable('get project')
    return project
  }

  async createProject(request: CreateProjectRequest | string): Promise<ProjectDto> {
    const name = typeof request === 'string' ? request : request.name
    return { schemaVersion: 1, projectId: 'demo-project', name, createdAt: new Date(0).toISOString() }
  }

  async updateProject(): Promise<ProjectDto> { return this.unavailable('update project') }
  async deleteProject(): Promise<void> { return this.unavailable('delete project') }
  async listArtifacts(): Promise<ArtifactDto[]> {
    return [{
      schemaVersion: 1,
      artifactId: 'demo-artifact',
      type: 'JAR',
      artifactDigest: '0'.repeat(64),
      sizeBytes: 1_048_576,
      staticOnly: true,
      verificationStatus: 'STATIC_INFERRED',
      registeredAt: new Date(0).toISOString(),
      projectId: 'project-01',
      originalFileName: 'demo-springblade-sample.jar',
      fileName: 'demo-springblade-sample.jar',
      displayName: 'demo-springblade-sample.jar'
    }]
  }

  async registerArtifact(request: RegisterArtifactRequest | string, _projectId?: string): Promise<ArtifactDto> {
    const path = typeof request === 'string' ? request : request.path
    const baseName = path.replace(/\\/g, '/').split('/').filter(Boolean).pop() || 'demo-sample.jar'
    return {
      schemaVersion: 1,
      artifactId: 'demo-artifact',
      type: 'JAR',
      artifactDigest: '0'.repeat(64),
      sizeBytes: 0,
      staticOnly: true,
      verificationStatus: 'STATIC_INFERRED',
      registeredAt: new Date(0).toISOString(),
      projectId: 'project-01',
      originalFileName: baseName,
      fileName: baseName,
      displayName: baseName
    }
  }

  uploadArtifact(): UploadTask {
    const controller = new AbortController()
    return uploadTask(Promise.reject(new ApiUnavailableError('artifact upload (demo adapter)')), controller)
  }

  async updateArtifact(): Promise<ArtifactDto> { return this.unavailable('update artifact') }
  async deleteArtifact(): Promise<void> { return this.unavailable('delete artifact') }
  async listScans(): Promise<ScanDto[]> { return [] }

  async createScan(_request: CreateScanRequest | string = {}, _projectId?: string): Promise<ScanDto> {
    return { schemaVersion: 1, scanId: 'scan-07f2', projectId: 'project-01', artifactDigest: '0'.repeat(64), status: 'COMPLETED', verificationStatus: 'STATIC_INFERRED', dependencyMode: 'MOCK', createdAt: new Date(0).toISOString(), updatedAt: new Date(0).toISOString(), evidenceRefs: [] }
  }

  async startAudit(projectId: string, _request: StartAuditRequest): Promise<AuditRunDto> {
    const scan = await this.createScan({}, projectId)
    return {
      schemaVersion: 1,
      auditRunId: 'audit-07f2',
      projectId,
      artifactDigest: scan.artifactDigest,
      scanId: scan.scanId,
      status: 'PRE_ANALYSIS_BLOCKED',
      scan,
      preAnalysisJob: {
        schemaVersion: 1,
        aiJobId: 'ai-job-demo',
        projectId,
        scanId: scan.scanId,
        artifactDigest: scan.artifactDigest,
        role: 'PRE_ANALYSIS',
        status: 'BLOCKED',
        createdAt: new Date(0).toISOString(),
        errorCode: 'DEMO_MODE_UNAVAILABLE'
      }
    }
  }

  async createDynamicTask(): Promise<DynamicTaskDto> { return this.unavailable('create dynamic artifact task') }
  async listDynamicTasks(): Promise<DynamicTaskDto[]> { return [] }
  async updateScan(): Promise<ScanDto> { return this.unavailable('update scan') }
  async deleteScan(_projectId?: string, _scanId?: string): Promise<void> { return this.unavailable('delete scan') }
  async listProviders(): Promise<ProviderDto[]> { return [] }
  async createProvider(): Promise<ProviderDto> { return this.unavailable('create provider') }
  async updateProvider(): Promise<ProviderDto> { return this.unavailable('update provider') }
  async deleteProvider(): Promise<void> { return this.unavailable('delete provider') }
  async refreshProviderModels(): Promise<ProviderModelInventoryDto> { return this.unavailable('refresh provider models') }
  async listRoleAssignments(): Promise<RoleAssignmentDto[]> { return [] }
  async saveRoleAssignment(): Promise<RoleAssignmentDto> { return this.unavailable('save role assignment') }
  async deleteRoleAssignment(): Promise<void> { return this.unavailable('delete role assignment') }
  async listAiJobs(): Promise<AiJobDto[]> {
    return [{
      schemaVersion: 1,
      aiJobId: 'ai-job-demo-report',
      projectId: 'project-01',
      scanId: 'scan-07f2',
      artifactDigest: '0'.repeat(64),
      role: 'REPORT_GENERATION',
      status: 'COMPLETED',
      providerId: 'demo-provider',
      model: 'demo-report',
      outputLanguage: 'ZH_CN',
      createdAt: new Date(0).toISOString()
    }]
  }
  async createAiJob(): Promise<AiJobDto> { return this.unavailable('create ai job') }
  async getAiJob(): Promise<AiJobDto> { return this.unavailable('get ai job') }
  async listAiJobEvents(aiJobId: string): Promise<AiJobEventDto[]> {
    if (aiJobId !== 'ai-job-demo-report') return []
    return [{
      schemaVersion: 1,
      aiJobId,
      sequence: 1,
      projectId: 'project-01',
      stage: 'MODEL_INFERENCE',
      status: 'COMPLETED',
      createdAt: new Date(0).toISOString(),
      modelInferenceSummary: [
        '# 安全审计报告',
        '',
        '## 报告元信息',
        '',
        '- **扫描 ID**: `scan-07f2`',
        '- **范围摘要**: 演示模式样本发现（关键发现 / 其他风险点）',
        '- **总体结论**: 演示数据，最高为静态推断信号，不等于已验证利用。',
        '',
        '## 执行摘要',
        '',
        '本页为**演示模式**最终报告主视图。结论均为受证据约束的模型推断，**不等于 VERIFIED**。',
        '',
        '- 演示扫描含上传路径与信息泄露等发现样本。',
        '- 动态确认若出现，仍为 MOCK SQL 证据，不得宣传为生产实库已证实。',
        '',
        '## 关键发现',
        '',
        '### 高危',
        '',
        '#### 1. 演示：后台任意文件上传信号',
        '',
        '- **风险等级**: 高危（high）',
        '- **验证状态**: 仅静态信号（STATIC_INFERRED）',
        '- **简述**: 演示模式样本；真实扫描由服务端 `findingBindings` 填充。',
        '- **技术路径**:',
        '  - **入口**: POST /ueditor/upload',
        '  - **中途代码逻辑**: 本轮证据不足以描述中间逻辑',
        '  - **底层触发位置**: `FileService#store`',
        '',
        '## 利用链',
        '',
        '本轮未识别可组合利用链',
        '',
        '## 附录：技术细节',
        '',
        'PathRun / Sink 排序 / 对照账本等请通过审计结果子页面查看。',
        '',
        '## 限制与下一步验证',
        '',
        '演示适配器不连接控制面；下载与重放能力可能不可用。'
      ].join('\n')
    }]
  }
  async updateAiJob(): Promise<AiJobDto> { return this.unavailable('update ai job') }
  async deleteAiJob(): Promise<void> { return this.unavailable('delete ai job') }

  async replayFinding(): Promise<FindingReplayDto> { return this.unavailable('replay finding') }

  async focusEntryProbe(): Promise<FocusEntryProbeDto> { return this.unavailable('focus entry probe') }
  async replaySqlExperimentCard(): Promise<FocusEntryProbeDto> { return this.unavailable('replay sql experiment card') }

  async getEntries(): Promise<EntryDto[]> {
    return (await this.loadDashboard()).entries
  }

  async getScan(_scanId: string): Promise<ScanDto> {
    return this.createScan()
  }

  async getScanCoverage(scanId: string): Promise<CoverageMatrixDto> {
    return {
      schemaVersion: 1,
      scanId,
      artifactUniverseSummary: {
        classCount: 0,
        methodCount: 0,
        fieldCount: 0,
        dependencyCount: 0,
        incomplete: true,
        note: 'DEMO_ONLY'
      },
      entryFamilies: [],
      callResolution: {
        DIRECT: 0,
        CHA: 0,
        UNRESOLVED: 0,
        unresolvedIsGap: true
      },
      detectors: [],
      dynamicExperiments: {
        pathRunCount: 0,
        effectiveAttemptCount: 0,
        unreachedCount: 0,
        stopReasonSamples: []
      },
      stopReasons: [],
      gaps: { unknown: 0, unresolved: 0, truncated: 0, unreached: 0, total: 0, countedAsCovered: false },
      honestyFlags: {
        neverTreatSuccessAsSafe: true,
        gapsNeverCountAsCovered: true,
        scanSuccessMeans: 'analysis_finished_not_safe'
      },
      checksum: '0'.repeat(64)
    }
  }

  async getEvidenceGraph(scanId: string): Promise<EvidenceGraphDto> {
    return {
      schemaVersion: 1,
      scanId,
      nodes: [{
        id: 'program:module:demo-lang:demo.mod',
        kind: 'PROGRAM',
        language: 'demo-lang',
        symbol: 'demo.mod',
        location: 'demo/mod.ts:1',
        evidenceRefs: ['ev-demo-1'],
        provenanceKind: 'FACT',
        extensions: { 'demo-lang': { note: 'unknown language extension sample' } }
      }],
      edges: [],
      truncated: false,
      maxNodes: 2000,
      maxEdges: 4000,
      nodeCount: 1,
      edgeCount: 0,
      compatibilityGap: {
        entryDtoCount: 0,
        entryNodeCount: 0,
        filteredEntryIds: [],
        notes: ['DEMO_ONLY']
      }
    }
  }

  async getScanHypotheses(scanId: string): Promise<ScanHypothesesDto> {
    const dashboard = await this.loadDashboard()
    const hypotheses = dashboard.hypotheses ?? []
    return { schemaVersion: 1, scanId, hypotheses, count: hypotheses.length }
  }

  async getScanAiMemory(scanId: string, section = 'FULL'): Promise<Record<string, unknown>> {
    return {
      schemaVersion: 1,
      section,
      memory: {
        scanId,
        counts: { entries: 0, sinks: 0, pathRuns: 0 },
        toolsCatalog: [],
        note: 'DEMO_ONLY'
      }
    }
  }

  async getEvidence(evidenceId: string): Promise<EvidenceDto> {
    return { schemaVersion: 1, evidenceId, kind: 'DEMO', source: 'demo', confidence: 0, summary: 'Demo evidence; not a real scan.', observedAt: new Date(0).toISOString(), toolVersion: 'demo', modelVersion: 'none', snapshotRef: 'demo://evidence' }
  }

  subscribe(_scanId: string, _onEvent: (event: ScanEvent) => void, _options?: SubscribeOptions): () => void {
    return () => undefined
  }
}

// 演示模式必须显式开启。未设置标志时现使用真实控制面适配器，防止生产构建静默展示 mock 结果。

package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.ai.conclusion.AiAuthConclusionBuilder;
import com.aq.jvmsentinel.ai.conclusion.AiAuthConclusionBuilder.AuthConclusionBuilt;
import com.aq.jvmsentinel.ai.conclusion.AiConclusionAnnotator;
import com.aq.jvmsentinel.ai.conclusion.AiConclusionJson;
import com.aq.jvmsentinel.ai.conclusion.AiDynamicProbeSupport;
import com.aq.jvmsentinel.ai.conclusion.AiReportEnforcer;
import com.aq.jvmsentinel.ai.conclusion.AiReportEnforcer.ReportBindingsEnforced;
import com.aq.jvmsentinel.ai.conclusion.AiReportEnforcer.ReportLedgerEnforced;
import com.aq.jvmsentinel.ai.context.AiPromptText;
import com.aq.jvmsentinel.ai.context.AiUserPromptBuilder;
import com.aq.jvmsentinel.ai.context.AuthContextBuilder;
import com.aq.jvmsentinel.ai.context.ContrastContextBuilder;
import com.aq.jvmsentinel.ai.context.FindingBindingsContextBuilder;
import com.aq.jvmsentinel.ai.context.PathRunContextBuilder;
import com.aq.jvmsentinel.ai.prompt.AiPromptLanguage;
import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.ai.prompt.AiRepairPrompts;
import com.aq.jvmsentinel.ai.prompt.AiSystemPrompt;
import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.DynamicProbeExecutor;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.aq.jvmsentinel.analysis.BranchConstraintHarvester;
import com.aq.jvmsentinel.analysis.CandidateRanker;
import com.aq.jvmsentinel.analysis.CoverageGapProjector;
import com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector;
import com.aq.jvmsentinel.analysis.TaintGraph;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.analysis.TaintGraphProjector;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.contrast.LedgerDiff;
import com.aq.jvmsentinel.analysis.experiment.TracePlanCompiler;
import com.aq.jvmsentinel.analysis.experiment.TracePlanObservationDiff;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapter;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.analysis.fuzz.FuzzStrategyRegistry;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ParameterSpec;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderProtocol;
import com.aq.jvmsentinel.provider.chat.AnthropicMessagesAdapter;
import com.aq.jvmsentinel.provider.chat.ChatTransport;
import com.aq.jvmsentinel.provider.chat.OpenAiChatCompletionsAdapter;
import com.aq.jvmsentinel.provider.chat.ProviderChatContracts;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * 有界 AI job 状态机。模型与制品内容仅为数据，不能改变 scope、策略、工具授权、传输或鉴权。
 */
public final class AiJobOrchestrator implements AutoCloseable {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_ROUNDS = 5;
    private static final int MAX_TOOL_CALLS = 16;
    private static final int PATH_TRIAGE_MAX_ROUNDS = 4;
    private static final int PATH_TRIAGE_MAX_TOOL_CALLS = 8;
    private static final int PATH_TRIAGE_MAX_PROBES = 4;
    private static final int FINALIZE_AFTER_TOOL_CALLS = 12;
    private static final int MAX_OUTPUT_TOKENS = 2_048;
    /** Provider 硬上限 2 分钟；大工具上下文下的完整审计报告需要上限内完成。 */
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(120);
    private static final Duration JOB_TIMEOUT = Duration.ofSeconds(600);
    @FunctionalInterface
    public interface TerminalListener {
        void onTerminal(SQLiteControlPlanePersistence.AiJobData job);
    }

    private final ControlPlaneStore store;
    private final ChatTransport transport;
    private final Clock clock;

    private final ControlPlaneToolDataSource.DynamicEvidenceSource dynamicEvidenceSource;
    private final DynamicProbeExecutor dynamicProbeExecutor;
    private final PathRunSource pathRunSource;
    private final ControlPlaneToolDataSource.ExperimentPlanAcceptor experimentPlanAcceptor;
    private final ExecutorService executor;
    private final Map<String, Running> running = new ConcurrentHashMap<>();
    private volatile TerminalListener terminalListener = job -> { };
    private final AiUserPromptBuilder userPromptBuilder;
    private final PathRunContextBuilder pathRunContext;
    private final AuthContextBuilder authContext;
    private final ContrastContextBuilder contrastContext;
    private final FindingBindingsContextBuilder findingBindingsContext;

    private final AiAuthConclusionBuilder authConclusion;
    private final AiDynamicProbeSupport dynamicProbeSupport;
    private final AiReportEnforcer reportEnforcer;
    private final AiConclusionAnnotator conclusionAnnotator;


    public AiJobOrchestrator(ControlPlaneStore store) {
        this(store, new ProviderChatTransport(), Clock.systemUTC());
    }

    public AiJobOrchestrator(ControlPlaneStore store, ChatTransport transport, Clock clock) {
        this(store, transport, clock, (projectId, artifactDigest, scanId) -> List.of(),
                (scanId, scope, principalId, jobId, toolCallId, entrypointRef, candidateInputs, maxRequests,
                        techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId)
                        -> java.util.Optional.empty(),
                (projectId, artifactDigest, scanId) -> List.of());
    }

    public AiJobOrchestrator(ControlPlaneStore store, ChatTransport transport, Clock clock,
                             ControlPlaneToolDataSource.DynamicEvidenceSource dynamicEvidenceSource) {
        this(store, transport, clock, dynamicEvidenceSource,
                (scanId, scope, principalId, jobId, toolCallId, entrypointRef, candidateInputs, maxRequests,
                        techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId)
                        -> java.util.Optional.empty(),
                (projectId, artifactDigest, scanId) -> List.of());
    }

    public AiJobOrchestrator(ControlPlaneStore store, ChatTransport transport, Clock clock,
                             ControlPlaneToolDataSource.DynamicEvidenceSource dynamicEvidenceSource,
                             DynamicProbeExecutor dynamicProbeExecutor) {
        this(store, transport, clock, dynamicEvidenceSource, dynamicProbeExecutor,
                (projectId, artifactDigest, scanId) -> List.of());
    }

    public AiJobOrchestrator(ControlPlaneStore store, ChatTransport transport, Clock clock,
                             ControlPlaneToolDataSource.DynamicEvidenceSource dynamicEvidenceSource,
                             DynamicProbeExecutor dynamicProbeExecutor,
                             PathRunSource pathRunSource) {
        this(store, transport, clock, dynamicEvidenceSource, dynamicProbeExecutor, pathRunSource,
                (scanId, plan) -> { });
    }

    public AiJobOrchestrator(ControlPlaneStore store, ChatTransport transport, Clock clock,
                             ControlPlaneToolDataSource.DynamicEvidenceSource dynamicEvidenceSource,
                             DynamicProbeExecutor dynamicProbeExecutor,
                             PathRunSource pathRunSource,
                             ControlPlaneToolDataSource.ExperimentPlanAcceptor experimentPlanAcceptor) {
        this.store = Objects.requireNonNull(store, "store");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.dynamicEvidenceSource = Objects.requireNonNull(dynamicEvidenceSource, "dynamicEvidenceSource");
        this.dynamicProbeExecutor = Objects.requireNonNull(dynamicProbeExecutor, "dynamicProbeExecutor");
        this.pathRunSource = Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.experimentPlanAcceptor = Objects.requireNonNull(experimentPlanAcceptor, "experimentPlanAcceptor");
        this.executor = Executors.newFixedThreadPool(4, runnable -> {
            Thread thread = new Thread(runnable, "bounded-ai-job");
            thread.setDaemon(true);
            return thread;
        });

        this.pathRunContext = new PathRunContextBuilder(store, pathRunSource);
        this.contrastContext = new ContrastContextBuilder(store, this.pathRunContext);
        this.authContext = new AuthContextBuilder(store, this.pathRunContext);
        this.findingBindingsContext = new FindingBindingsContextBuilder(
                store, pathRunSource, this.pathRunContext, this.contrastContext);
        this.userPromptBuilder = AiUserPromptBuilder.create(store, pathRunSource);
        this.authConclusion = new AiAuthConclusionBuilder(store, this.authContext, this.pathRunContext);
        this.dynamicProbeSupport = new AiDynamicProbeSupport(dynamicProbeExecutor);
        this.reportEnforcer = new AiReportEnforcer(this.contrastContext, this.findingBindingsContext);
        this.conclusionAnnotator = new AiConclusionAnnotator(store, this.pathRunContext, this.authConclusion);

        recoverInterruptedJobs();
    }

    public void setTerminalListener(TerminalListener listener) {
        this.terminalListener = listener == null ? job -> { } : listener;
    }

    public void submit(SQLiteControlPlanePersistence.AiJobData job, String actorId) {
        Objects.requireNonNull(job, "job");
        if (!"QUEUED".equals(job.status())) return;
        Running state = new Running();
        Running prior = running.putIfAbsent(job.aiJobId(), state);
        if (prior != null) return;
        state.future = executor.submit(() -> run(job.aiJobId(), actorId, state));
    }

    public void cancel(String jobId) {
        Running state = running.get(jobId);
        if (state == null) return;
        state.cancelled = true;
        ToolExecutionContext context = state.context;
        if (context != null) context.cancel();
        Future<?> future = state.future;
        if (future != null) future.cancel(true);
    }

    private void run(String jobId, String actorId, Running state) {
        long started = System.nanoTime();
        SQLiteControlPlanePersistence.AiJobData job = store.requireAiJob(jobId);
        try {
            if (state.cancelled || "CANCELLED".equals(job.status())) return;
            SQLiteControlPlanePersistence.ProviderData configured = validateExecutionSnapshot(job);
            job = transition(job, "RUNNING", "RUNNING", null, 0, 0,
                    "[]", null, actorId, "ai-job.start");
            appendEvent(job, "LIFECYCLE", "RUNNING", null, null, null,
                    null, null, null, null);
            ProviderDefinition provider = new ProviderDefinition(
                    ProviderContracts.SCHEMA_VERSION, job.workspaceId(), configured.providerId(),
                    configured.name(), configured.kind(), URI.create(configured.baseUrl()),
                    configured.enabled(), configured.hasCredential(),
                    Instant.parse(configured.createdAt()), Instant.parse(configured.updatedAt()));
            SQLiteControlPlanePersistence.AiJobData runningJob = job;
            store.withProviderCredential(job.providerId(), credential -> {
                executeLoop(runningJob, provider, credential, actorId, state, started);
                return null;
            });
        } catch (Throwable failure) {
            if (failure instanceof InterruptedException || Thread.currentThread().isInterrupted()
                    || state.cancelled) {
                persistCancelled(jobId, actorId, started);
            } else {
                String reason = failure instanceof ProviderChatTransport.TransportException transportFailure
                        ? transportFailure.code()
                        : failure instanceof JobFailure jobFailure ? jobFailure.code : "AI_JOB_FAILED";
                String diagnostic = failure instanceof ProviderChatTransport.TransportException transportFailure
                        ? transportFailure.diagnostic()
                        : failure instanceof JobFailure jobFailure
                        ? jobFailure.diagnostic : genericDiagnostic(failure);
                fail(jobId, reason, diagnostic, actorId, started);
            }
        } finally {
            running.remove(jobId, state);
            notifyTerminal(jobId);
        }
    }

    private void notifyTerminal(String jobId) {
        try {
            SQLiteControlPlanePersistence.AiJobData current = store.requireAiJob(jobId);
            if ("QUEUED".equals(current.status()) || "RUNNING".equals(current.status())) return;
            terminalListener.onTerminal(current);
        } catch (RuntimeException ignored) {
            // 监听器异常时流水线不得让已结束 job 卡住。
        }
    }

    private SQLiteControlPlanePersistence.ProviderData validateExecutionSnapshot(
            SQLiteControlPlanePersistence.AiJobData job) {
        if (!job.authorized() || job.providerId() == null || job.model() == null
                || job.scanId() == null || job.artifactDigest() == null) {
            throw new JobFailure("AI_JOB_SNAPSHOT_INVALID");
        }
        ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
        if (!job.projectId().equals(scan.dto().projectId())
                || !job.artifactDigest().equals(scan.dto().artifactDigest())
                || !"COMPLETED".equals(scan.dto().status())) {
            throw new JobFailure("SCAN_SNAPSHOT_CHANGED");
        }
        var binding = store.roleBindings(job.projectId()).stream()
                .filter(value -> value.role() == job.role()).findFirst()
                .orElseThrow(() -> new JobFailure("ROLE_BINDING_CHANGED"));
        if (!job.providerId().equals(binding.providerId()) || !job.model().equals(binding.model())) {
            throw new JobFailure("ROLE_BINDING_CHANGED");
        }
        SQLiteControlPlanePersistence.ProviderData provider = store.requireProvider(job.providerId());
        if (!provider.enabled() || !provider.hasCredential()) {
            throw new JobFailure("PROVIDER_NOT_READY");
        }
        if (provider.kind() != ProviderContracts.ProviderKind.OPENAI_CHAT
                && provider.kind() != ProviderContracts.ProviderKind.ANTHROPIC_MESSAGES
                && provider.kind() != ProviderContracts.ProviderKind.OPENAI_COMPATIBLE) {
            throw new JobFailure("PROVIDER_PROTOCOL_UNSUPPORTED");
        }
        try {
            JsonNode policy = JSON.readTree(job.policySnapshotJson());
            if (policy == null || !policy.isObject()
                    || !job.providerId().equals(policy.path("providerId").asText())
                    || !job.model().equals(policy.path("model").asText())
                    || !binding.updatedAt().equals(policy.path("roleBindingUpdatedAt").asText())
                    || !provider.kind().name().equals(policy.path("providerKind").asText())
                    || !provider.baseUrl().equals(policy.path("providerBaseUrl").asText())
                    || !provider.updatedAt().equals(
                            policy.path("providerConfigurationUpdatedAt").asText())) {
                throw new JobFailure("PROVIDER_CONFIGURATION_CHANGED");
            }
        } catch (JobFailure expected) {
            throw expected;
        } catch (Exception invalid) {
            throw new JobFailure("AI_JOB_SNAPSHOT_INVALID");
        }
        return provider;
    }

    private void executeLoop(SQLiteControlPlanePersistence.AiJobData initial, ProviderDefinition provider,
                             byte[] credential, String actorId, Running state, long started) {
        ProviderProtocol protocol = provider.kind().protocol();
        OpenAiChatCompletionsAdapter openAi = new OpenAiChatCompletionsAdapter();
        AnthropicMessagesAdapter anthropic = new AnthropicMessagesAdapter();
        AiToolRegistry registry = new AiToolRegistry(
                new ControlPlaneToolDataSource(store, initial.scanId(), dynamicEvidenceSource,
                        dynamicProbeExecutor, pathRunSource, experimentPlanAcceptor));
        boolean pathOrTriage = initial.role() == AgentRole.PATH_EXPLORATION
                || initial.role() == AgentRole.VULNERABILITY_TRIAGE;
        int maxRounds = pathOrTriage ? PATH_TRIAGE_MAX_ROUNDS : MAX_ROUNDS;
        int maxToolCalls = pathOrTriage ? PATH_TRIAGE_MAX_TOOL_CALLS : MAX_TOOL_CALLS;
        ToolExecutionContext context = ToolExecutionContext.bind(
                new ToolExecutionContext.Scope(initial.workspaceId(), initial.projectId()),
                actorId, initial.aiJobId(), initial.role(),
                new ToolExecutionContext.Budget(maxToolCalls, 65_536, 16, 65_536,
                        clock.instant().plus(JOB_TIMEOUT)));
        state.context = context;
        AiOutputLanguage outputLanguage = parseOutputLanguage(initial);
        // PATH/TRIAGE 等注入 TracePlan 差分、对照表后易超过 chat user 128KiB → UserTurn 抛 invalid。
        String userPrompt = AiPromptText.fitChatUserText(
                userPromptBuilder.buildUserPrompt(initial, outputLanguage));
        appendEvent(initial, "PROMPT_SYSTEM", "RUNNING", null, null, null, null, null,
                AiPromptSanitizer.sanitizeSummary(AiSystemPrompt.SYSTEM_PROMPT), null);
        appendEvent(initial, "PROMPT_USER", "RUNNING", null, null, null, null, null,
                AiPromptSanitizer.sanitizeSummary(userPrompt), null);
        List<ProviderChatContracts.ChatTurn> turns = new ArrayList<>();
        turns.add(new ProviderChatContracts.UserTurn(userPrompt));
        List<Map<String, Object>> toolSummary = new ArrayList<>();
        List<AuthBypassCandidate> toolBypassPoCs = new ArrayList<>();
        String requestId = null;
        int rounds = 0;
        int toolCallsUsed = 0;
        int sandboxProbeCount = 0;
        int pathTriageProbeAttempts = 0;
        int codeQuerySuccessCount = 0;
        boolean finalOnly = false;
        boolean authPocRepairAsked = false;
        boolean authCodeQueryRepairAsked = false;
        boolean authDiversityRepairAsked = false;
        boolean dynamicProbeRepairAsked = false;
        int dynamicAutoProbeCount = 0;
        for (; rounds < maxRounds; rounds++) {
            if (state.cancelled || context.isCancelled() || Thread.currentThread().isInterrupted()) {
                persistCancelled(initial.aiJobId(), actorId, started);
                return;
            }
            List<com.aq.jvmsentinel.ai.tool.AiToolRegistry.ToolDefinition> definitions =
                    finalOnly ? List.of() : registry.definitionsFor(initial.role());
            ObjectNode request = protocol == ProviderProtocol.OPENAI_CHAT
                    ? openAi.buildRequest(initial.model(), AiSystemPrompt.SYSTEM_PROMPT, turns,
                            definitions)
                    : anthropic.buildRequest(initial.model(), MAX_OUTPUT_TOKENS, AiSystemPrompt.SYSTEM_PROMPT, turns,
                            definitions);
            if (protocol == ProviderProtocol.OPENAI_CHAT) {
                request.put("max_completion_tokens", MAX_OUTPUT_TOKENS);
            }
            appendEvent(initial, "PROVIDER_REQUEST", "RUNNING",
                    AiConclusionJson.encode(Map.of("protocol", protocol.name(), "round", rounds + 1,
                            "maxOutputTokens", MAX_OUTPUT_TOKENS,
                            "outputLanguage", outputLanguage.name(),
                            "toolDefinitionCount", definitions.size())),
                    null, null, null, null, null, null);
            ProviderChatTransport.Response response = transport.send(provider, credential, request,
                    new ProviderChatTransport.Limits(REQUEST_TIMEOUT,
                            ProviderChatContracts.MAX_REQUEST_BYTES,
                            ProviderChatContracts.MAX_RESPONSE_BYTES));
            requestId = response.requestId() == null ? requestId : response.requestId();
            Map<String, Object> providerResult = new LinkedHashMap<>();
            providerResult.put("httpStatus", response.statusCode());
            providerResult.put("elapsedMillis", response.elapsedMillis());
            if (response.requestId() != null) providerResult.put("requestId", response.requestId());
            appendEvent(initial, "PROVIDER_RESPONSE", "RUNNING", null,
                    AiConclusionJson.encode(providerResult), null, null, null, null, null);
            byte[] responseBody = response.body();
            ProviderChatContracts.ParsedResponse parsed;
            try {
                parsed = protocol == ProviderProtocol.OPENAI_CHAT
                        ? openAi.parseResponse(responseBody) : anthropic.parseResponse(responseBody);
            } catch (RuntimeException malformed) {
                throw new JobFailure("MALFORMED_PROVIDER_RESPONSE",
                        protocol.name() + ": " + malformed.getMessage());
            } finally {
                Arrays.fill(responseBody, (byte) 0);
                response.clear();
            }
            appendEvent(initial, "PROVIDER_RESULT", "RUNNING", null,
                    AiConclusionJson.encode(Map.of("stopReason", parsed.stopReason().name(),
                            "toolCallCount", parsed.executableCalls().size())),
                    null, null, null, null, null);
            String thinking = AiPromptSanitizer.sanitizeSummary(extractThinking(parsed.assistant()));
            if (!thinking.isBlank()) {
                appendEvent(initial, "MODEL_THINKING", "RUNNING", null, null, null, null, null,
                        thinking, null);
            }
            String roundText = AiPromptSanitizer.sanitizeSummary(extractText(parsed.assistant()));
            if (!roundText.isBlank()
                    && parsed.stopReason() == ProviderChatContracts.StopReason.TOOL_USE) {
                appendEvent(initial, "MODEL_OUTPUT", "RUNNING", null, null, null, null, null,
                        roundText, null);
            }
            if (parsed.stopReason() == ProviderChatContracts.StopReason.TOOL_USE) {
                if (finalOnly) {
                    throw new JobFailure("TOOL_CALL_AFTER_BUDGET",
                            "provider returned tool calls after the server closed the tool phase");
                }
                List<ToolResult> results = new ArrayList<>();
                for (var call : parsed.executableCalls()) {
                    if (pathOrTriage && "sandbox_probe".equals(call.toolName())
                            && pathTriageProbeAttempts >= PATH_TRIAGE_MAX_PROBES) {
                        ToolResult denied = new ToolResult(CanonicalToolContracts.SCHEMA_VERSION,
                                call.callId(), call.toolName(), ToolStatus.DENIED, List.of(),
                                "PATH_TRIAGE_PROBE_BUDGET", false);
                        results.add(denied);
                        toolSummary.add(Map.of("tool", call.toolName(), "status", denied.status().name(),
                                "errorCode", "PATH_TRIAGE_PROBE_BUDGET"));
                        continue;
                    }
                    ToolResult result = registry.execute(call, context);
                    if (pathOrTriage && "sandbox_probe".equals(call.toolName())) {
                        // PATH/TRIAGE 后续轮次仅可消费已投影 PathRun fact（P0-05）。
                        result = AiDynamicProbeSupport.gatePathTriageProbeResult(result);
                    }
                    results.add(result);
                    Map<String, Object> summary = new LinkedHashMap<>();
                    summary.put("tool", call.toolName());
                    summary.put("status", result.status().name());
                    if (result.errorCode() != null) summary.put("errorCode", result.errorCode());
                    summary.put("truncated", result.truncated());
                    toolSummary.add(summary);
                    if ("sandbox_probe".equals(call.toolName())) {
                        pathTriageProbeAttempts++;
                        if (AiDynamicProbeSupport.isEffectiveSandboxProbeAttempt(result)) {
                            sandboxProbeCount++;
                        }
                    }
                    if (initial.role() == AgentRole.AUTH_ANALYSIS
                            && "code_query".equals(call.toolName())
                            && result.status() == ToolStatus.SUCCESS
                            && authConclusion.authCodeQueryCountsTowardGate(initial.scanId(), result)) {
                        codeQuerySuccessCount++;
                    }
                    if (initial.role() == AgentRole.AUTH_ANALYSIS
                            && "plan_propose".equals(call.toolName())
                            && result.status() == ToolStatus.SUCCESS) {
                        AiAuthConclusionBuilder.collectBypassPoCFromTool(toolBypassPoCs, result);
                    }
                    appendEvent(initial, "TOOL_CALL", "RUNNING", null, null,
                            safeToolName(call.toolName()), argumentSummary(call.toolName(), call.arguments()),
                            result.status().name(), null, null);
                    store.auditChange(initial.projectId(), actorId, "ai-job.tool-decision", "ai-job",
                            initial.aiJobId(), AiConclusionJson.encode(summary), clock.instant().toString());
                }
                turns.add(parsed.assistant());
                turns.add(protocol == ProviderProtocol.OPENAI_CHAT
                        ? openAi.toolResults(parsed.assistant(), results)
                        : anthropic.toolResults(parsed.assistant(), results));
                toolCallsUsed += parsed.executableCalls().size();
                if (toolCallsUsed >= FINALIZE_AFTER_TOOL_CALLS
                        || rounds + 1 >= maxRounds - 1
                        || toolCallsUsed >= maxToolCalls) {
                    finalOnly = true;
                    turns.add(new ProviderChatContracts.UserTurn(
                            AiPromptLanguage.finalInstruction(outputLanguage)));
                }
                continue;
            }
            if (parsed.stopReason() == ProviderChatContracts.StopReason.FILTERED
                    || parsed.stopReason() == ProviderChatContracts.StopReason.REFUSED) {
                throw new JobFailure(parsed.stopReason().name());
            }
            String summary = roundText;
            if (summary.isBlank()) throw new JobFailure("EMPTY_MODEL_SUMMARY");
            AuthConclusionBuilt built = authConclusion.buildAuthAwareConclusion(
                    initial, summary, toolBypassPoCs, authPocRepairAsked,
                    codeQuerySuccessCount, authCodeQueryRepairAsked, authDiversityRepairAsked);
            if (built.needsCodeQuery() && !authCodeQueryRepairAsked && rounds + 1 < MAX_ROUNDS) {
                authCodeQueryRepairAsked = true;
                finalOnly = false; // 重新开放工具以便 AUTH 调用 code_query
                turns.add(parsed.assistant());
                turns.add(new ProviderChatContracts.UserTurn(
                        AiRepairPrompts.authCodeQueryRepairInstruction(outputLanguage, built.authSurface())));
                appendEvent(initial, "AUTH_CODE_QUERY_REQUIRED", "RUNNING", null, null,
                        null, null, null,
                        AuthBypassFeasibility.CODE_QUERY_REQUIRED
                                + " authPass=" + built.authPass()
                                + " codeQuerySuccessCount=0",
                        null);
                continue;
            }
            if (built.needsDiversity() && !authDiversityRepairAsked && rounds + 1 < MAX_ROUNDS) {
                authDiversityRepairAsked = true;
                finalOnly = true;
                turns.add(parsed.assistant());
                turns.add(new ProviderChatContracts.UserTurn(
                        AiRepairPrompts.authPocDiversityRepairInstruction(outputLanguage, built.authSurface(),
                                built.candidateCount())));
                appendEvent(initial, "AUTH_POC_DIVERSITY_REQUIRED", "RUNNING", null, null,
                        null, null, null,
                        AuthBypassFeasibility.POC_DIVERSITY_REQUIRED
                                + " distinctMechanisms=" + built.candidateCount()
                                + " min=" + AuthBypassFeasibility.AUTH_POC_MECHANISM_MIN,
                        null);
                continue;
            }
            if (built.needsRepair() && !authPocRepairAsked && rounds + 1 < MAX_ROUNDS) {
                authPocRepairAsked = true;
                finalOnly = true;
                turns.add(parsed.assistant());
                turns.add(new ProviderChatContracts.UserTurn(
                        AiRepairPrompts.authBypassPocRepairInstruction(outputLanguage, built.authSurface())));
                appendEvent(initial, "AUTH_BYPASS_POC_REQUIRED", "RUNNING", null, null,
                        null, null, null,
                        AuthBypassFeasibility.ENFORCEMENT_REQUIRED
                                + " jwtSinks=" + built.authSurface().jwtSinkCount()
                                + " authGapSinks=" + built.authSurface().authGapSinkCount()
                                + " authAnnotatedEntries=" + built.authSurface().authAnnotatedEntryCount(),
                        null);
                continue;
            }
            if (built.needsRepair() || built.needsCodeQuery() || built.needsDiversity()) {
                // 无剩余轮次或已消耗 re-ask — 降级/种子填充。
                built = authConclusion.buildAuthAwareConclusion(initial, summary, toolBypassPoCs, true,
                        codeQuerySuccessCount, true, true);
            }
            List<AuthBypassCandidate> feasibilityPoCs = List.of();
            if (initial.role() == AgentRole.DYNAMIC_VERIFICATION) {
                feasibilityPoCs = authContext.loadFeasibilityPoCs(initial);
                int requiredProbes = AiDynamicProbeSupport.requiredEffectiveProbeCount(feasibilityPoCs);
                boolean needsProbeAttempt = sandboxProbeCount < requiredProbes;
                boolean canReAsk = needsProbeAttempt && !dynamicProbeRepairAsked
                        && rounds + 1 < MAX_ROUNDS && toolCallsUsed < MAX_TOOL_CALLS;
                if (canReAsk) {
                    dynamicProbeRepairAsked = true;
                    finalOnly = false; // 重新开放工具以便调用 sandbox_probe
                    List<AuthBypassCandidate> top = AuthBypassFeasibility.selectTopProbeTargets(
                            feasibilityPoCs, AuthBypassFeasibility.DYNAMIC_POC_PROBE_MAX);
                    turns.add(parsed.assistant());
                    turns.add(new ProviderChatContracts.UserTurn(
                            AiRepairPrompts.dynamicPocAttemptRepairInstruction(outputLanguage, top)));
                    appendEvent(initial, "DYNAMIC_POC_ATTEMPT_REQUIRED", "RUNNING", null, null,
                            null, null, null,
                            AuthBypassFeasibility.DYNAMIC_ATTEMPT_REQUIRED
                                    + " feasibilityPoCs=" + feasibilityPoCs.size()
                                    + " topN=" + top.size()
                                    + " sandboxProbeCount=" + sandboxProbeCount
                                    + " requiredProbes=" + requiredProbes,
                            null);
                    continue;
                }
                if (needsProbeAttempt) {
                    // re-ask 已用 / 无轮次 / 工具预算耗尽 — 服务端自动入队。
                    dynamicAutoProbeCount = dynamicProbeSupport.autoEnqueueFocusedPocProbes(
                            initial, actorId, feasibilityPoCs);
                    appendEvent(initial, "DYNAMIC_POC_ATTEMPT_SEEDED", "COMPLETED", null, null,
                            null, null, null,
                            AuthBypassFeasibility.DYNAMIC_ATTEMPT_SEEDED
                                    + " autoEnqueued=" + dynamicAutoProbeCount
                                    + " feasibilityPoCs=" + feasibilityPoCs.size()
                                    + " reAskTriggered=" + dynamicProbeRepairAsked,
                            null);
                }
            }
            String conclusion = initial.role() == AgentRole.DYNAMIC_VERIFICATION
                    ? AiDynamicProbeSupport.buildDynamicConclusion(summary, feasibilityPoCs, sandboxProbeCount,
                    dynamicProbeRepairAsked, dynamicAutoProbeCount)
                    : built.conclusionJson();
            if (initial.role() == AgentRole.PATH_EXPLORATION
                    || initial.role() == AgentRole.VULNERABILITY_TRIAGE) {
                conclusion = conclusionAnnotator.annotateNextExperiments(initial, summary, conclusion);
                conclusion = AiConclusionAnnotator.annotateEffectiveProbeCount(conclusion, sandboxProbeCount);
            }
            if (initial.role() == AgentRole.PATH_EXPLORATION) {
                conclusion = reportEnforcer.annotateFindingBindings(initial, summary, conclusion, outputLanguage);
            }
            if (initial.role() == AgentRole.VULNERABILITY_TRIAGE) {
                conclusionAnnotator.attachTriageFindingIfPresent(initial, conclusion, actorId,
                        (job, detail) -> appendEvent(job, "TRIAGE_FINDING_ATTACHED", "COMPLETED",
                                null, null, null, null, null, detail, null));
            }
            if (initial.role() == AgentRole.REPORT_GENERATION) {
                ReportBindingsEnforced bindingsEnforced = reportEnforcer.enforceReportFindingBindings(
                        initial, summary, conclusion, outputLanguage);
                summary = bindingsEnforced.summary();
                conclusion = bindingsEnforced.conclusionJson();
                ReportLedgerEnforced enforced = reportEnforcer.enforceReportContrastLedger(
                        initial, summary, conclusion, outputLanguage);
                summary = enforced.summary();
                conclusion = enforced.conclusionJson();
                if (enforced.incomplete()) {
                    appendEvent(initial, ContrastLedger.EVENT_INCOMPLETE, "COMPLETED", null, null,
                            null, null, null,
                            ContrastLedger.EVENT_INCOMPLETE
                                    + " missingRows=" + enforced.missingRowIds().size()
                                    + " appendedByServer=true",
                            null);
                }
                if (bindingsEnforced.appendedByServer()) {
                    appendEvent(initial, "FINDING_BINDINGS_ENFORCED", "COMPLETED", null, null,
                            null, null, null,
                            "FINDING_BINDINGS_ENFORCED appendedByServer=true localeRepaired="
                                    + bindingsEnforced.localeRepaired(),
                            null);
                }
            }
            appendEvent(initial, "MODEL_INFERENCE", "COMPLETED", null, null,
                    null, null, null, summary, null);
            if (built.seeded()) {
                appendEvent(initial, "AUTH_BYPASS_POC_SEEDED", "COMPLETED", null, null,
                        null, null, null,
                        AuthBypassFeasibility.ENFORCEMENT_SEEDED
                                + " pocDraftSource=" + AuthBypassFeasibility.DRAFT_RULE_GENERATED
                                + " seededCount=" + built.candidateCount(),
                        null);
            }
            SQLiteControlPlanePersistence.AiJobData current = store.requireAiJob(initial.aiJobId());
            if ("CANCELLED".equals(current.status())) return;
            transition(current, "COMPLETED", parsed.stopReason().name(), requestId,
                    elapsed(started), rounds + 1, AiConclusionJson.encode(toolSummary), conclusion,
                    actorId, "ai-job.complete");
            return;
        }
        SQLiteControlPlanePersistence.AiJobData current = store.requireAiJob(initial.aiJobId());
        appendEvent(current, "FAILURE", "FAILED", null, null, null,
                null, null, null, "ROUND_BUDGET_EXHAUSTED");
        transition(current, "FAILED", "ROUND_BUDGET_EXHAUSTED", requestId,
                elapsed(started), rounds, AiConclusionJson.encode(toolSummary), null, actorId, "ai-job.fail");
    }



    private static AiOutputLanguage parseOutputLanguage(SQLiteControlPlanePersistence.AiJobData job) {
        try {
            return AiPromptLanguage.parseOutputLanguage(job.policySnapshotJson());
        } catch (IllegalArgumentException invalid) {
            throw new JobFailure("AI_JOB_SNAPSHOT_INVALID", "invalid output language snapshot");
        }
    }

    private SQLiteControlPlanePersistence.AiJobData transition(
            SQLiteControlPlanePersistence.AiJobData job, String status, String reason,
            String requestId, long elapsedMillis, int rounds, String toolSummary,
            String conclusion, String actorId, String action) {
        SQLiteControlPlanePersistence.AiJobData current = store.requireAiJob(job.aiJobId());
        // 取消优先：不得将 CANCELLED job 复活为 RUNNING/COMPLETED/FAILED。
        if ("CANCELLED".equals(current.status()) && !"CANCELLED".equals(status)) {
            return current;
        }
        String stage = AiConclusionJson.encode(List.of(Map.of(
                "schemaVersion", 1, "role", current.role().name(), "status", status,
                "providerId", current.providerId() == null ? "" : current.providerId(),
                "model", current.model() == null ? "" : current.model())));
        return store.updateAiJob(current, status, reason, stage, requestId, elapsedMillis,
                rounds, toolSummary, conclusion, actorId, action, clock.instant().toString());
    }

    private void fail(String jobId, String reason, String diagnostic, String actorId, long started) {
        SQLiteControlPlanePersistence.AiJobData current = store.requireAiJob(jobId);
        if ("CANCELLED".equals(current.status()) || "COMPLETED".equals(current.status())) return;
        appendEvent(current, "FAILURE", "FAILED", null, null, null,
                null, null, null, AiPromptSanitizer.sanitizeDiagnostic(diagnostic));
        transition(current, "FAILED", safeReason(reason), current.providerRequestId(),
                elapsed(started), current.rounds(), current.toolSummaryJson(), null,
                actorId, "ai-job.fail");
    }

    private static String genericDiagnostic(Throwable failure) {
        String message = failure.getMessage();
        String value = failure.getClass().getSimpleName()
                + (message == null || message.isBlank() ? "" : ": " + message);
        return AiPromptSanitizer.sanitizeDiagnostic(value);
    }

    private void persistCancelled(String jobId, String actorId, long started) {
        SQLiteControlPlanePersistence.AiJobData current = store.requireAiJob(jobId);
        if ("COMPLETED".equals(current.status()) || "FAILED".equals(current.status())) return;
        appendEvent(current, "LIFECYCLE", "CANCELLED", null, null, null,
                null, null, null, "USER_CANCELLED");
        store.updateAiJob(current, "CANCELLED", "USER_CANCELLED", current.stagesJson(),
                current.providerRequestId(), elapsed(started), current.rounds(),
                current.toolSummaryJson(), null, actorId, "ai-job.cancelled",
                clock.instant().toString());
    }

    private void recoverInterruptedJobs() {
        try {
            for (SQLiteControlPlanePersistence.AiJobData job : store.aiJobs(null)) {
                if ("QUEUED".equals(job.status()) || "RUNNING".equals(job.status())) {
                    appendEvent(job, "RECOVERY", "FAILED", null, null, null,
                            null, null, null, "PROCESS_RESTARTED");
                    store.updateAiJob(job, "FAILED", "PROCESS_RESTARTED", job.stagesJson(),
                            job.providerRequestId(), job.elapsedMillis(), job.rounds(),
                            job.toolSummaryJson(), null, "local-admin", "ai-job.recovered",
                            clock.instant().toString());
                }
            }
        } catch (RuntimeException inMemoryOrUninitialized) {
            // 内存兼容 store 不支持 AI 管理。
        }
    }






    static int requiredEffectiveProbeCount(List<AuthBypassCandidate> feasibilityPoCs) {
        return AiDynamicProbeSupport.requiredEffectiveProbeCount(feasibilityPoCs);
    }

    static boolean isEffectiveSandboxProbeAttempt(ToolResult result) {
        return AiDynamicProbeSupport.isEffectiveSandboxProbeAttempt(result);
    }

    static boolean isEffectiveSandboxProbeFact(JsonNode value) {
        return AiDynamicProbeSupport.isEffectiveSandboxProbeFact(value);
    }

    static ToolResult gatePathTriageProbeResult(ToolResult result) {
        return AiDynamicProbeSupport.gatePathTriageProbeResult(result);
    }

    private static String extractText(ProviderChatContracts.AssistantTurn assistant) {
        JsonNode wire = assistant.wireMessage();
        JsonNode content = wire.get("content");
        if (content == null || content.isNull()) return "";
        if (content.isTextual()) return content.textValue();
        StringBuilder result = new StringBuilder();
        if (content.isArray()) {
            for (JsonNode block : content) {
                if ("text".equals(block.path("type").asText()) && block.path("text").isTextual()) {
                    if (!result.isEmpty()) result.append('\n');
                    result.append(block.path("text").asText());
                }
            }
        }
        return result.toString();
    }

    private static String extractThinking(ProviderChatContracts.AssistantTurn assistant) {
        JsonNode wire = assistant.wireMessage();
        JsonNode reasoning = wire.get("reasoning_content");
        if (reasoning != null && reasoning.isTextual()) return reasoning.textValue();
        if (wire.path("content").isArray()) {
            StringBuilder thinking = new StringBuilder();
            for (JsonNode block : wire.path("content")) {
                String type = block.path("type").asText();
                if (("thinking".equals(type) || "reasoning".equals(type))
                        && block.path("thinking").isTextual()) {
                    if (!thinking.isEmpty()) thinking.append('\n');
                    thinking.append(block.path("thinking").asText());
                }
            }
            return thinking.toString();
        }
        return "";
    }

    private static String safeToolName(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{1,128}")
                ? value : "INVALID_TOOL_NAME";
    }

    private static String argumentSummary(String toolName, JsonNode arguments) {
        int bytes;
        try {
            bytes = JSON.writeValueAsBytes(arguments).length;
        } catch (Exception invalid) {
            bytes = -1;
        }
        int fields = arguments != null && arguments.isObject() ? arguments.size() : 0;
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("shape", arguments != null && arguments.isObject() ? "OBJECT" : "OTHER");
        summary.put("fieldCount", fields);
        summary.put("encodedBytes", bytes);
        if (arguments != null && arguments.isObject()) {
            if ("facts_search".equals(toolName)) {
                summary.put("kind", safeArgumentIdentifier(arguments.path("kind").asText("")));
                if (arguments.path("limit").canConvertToInt()) {
                    summary.put("limit", Math.max(1, Math.min(100, arguments.path("limit").asInt())));
                }
                String query = arguments.path("query").asText("");
                summary.put("queryPresent", !query.isEmpty());
                summary.put("queryBytes", query.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            } else if ("evidence_get".equals(toolName)) {
                summary.put("evidenceRef", safeArgumentReference(
                        arguments.path("evidenceRef").asText("")));
            } else if ("plan_propose".equals(toolName)) {
                summary.put("entrypointRef", safeArgumentReference(
                        arguments.path("entrypointRef").asText("")));
                summary.put("candidateCount", arguments.path("candidateInputs").isArray()
                        ? Math.min(16, arguments.path("candidateInputs").size()) : 0);
                summary.put("objectiveBytes", arguments.path("objective").asText("")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
                String techniqueId = arguments.path("techniqueId").asText("");
                if (!techniqueId.isBlank()) {
                    summary.put("techniqueId", safeArgumentIdentifier(techniqueId));
                }
                String auth = arguments.path("authorizationHeader").asText("");
                summary.put("authorizationHeaderPresent", !auth.isBlank());
                summary.put("authorizationHeaderBytes",
                        auth.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
                String blade = arguments.path("bladeAuthHeader").asText("");
                summary.put("bladeAuthHeaderPresent", !blade.isBlank());
                summary.put("bladeAuthHeaderBytes",
                        blade.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            } else if ("sandbox_probe".equals(toolName)) {
                summary.put("entrypointRef", safeArgumentReference(
                        arguments.path("entrypointRef").asText("")));
                String techniqueId = arguments.path("techniqueId").asText("");
                if (!techniqueId.isBlank()) {
                    summary.put("techniqueId", safeArgumentIdentifier(techniqueId));
                }
                String auth = arguments.path("authorizationHeader").asText("");
                summary.put("authorizationHeaderPresent", !auth.isBlank());
                summary.put("authorizationHeaderBytes",
                        auth.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
                String blade = arguments.path("bladeAuthHeader").asText("");
                summary.put("bladeAuthHeaderPresent", !blade.isBlank());
                summary.put("bladeAuthHeaderBytes",
                        blade.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            }
        }
        return AiConclusionJson.encode(summary);
    }

    private static String safeArgumentIdentifier(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{1,64}") ? value : "REDACTED";
    }

    private static String safeArgumentReference(String value) {
        return value != null && value.matches("[A-Za-z0-9._:-]{1,256}") ? value : "REDACTED";
    }

    private void appendEvent(SQLiteControlPlanePersistence.AiJobData job, String stage, String status,
                             String providerRequestSummary, String providerResultSummary,
                             String toolCallName, String toolArgumentsSummary,
                             String toolResultStatus, String modelInferenceSummary,
                             String failureDiagnostic) {
        store.appendAiJobEvent(new SQLiteControlPlanePersistence.AiJobEventData(
                job.aiJobId(), 0, job.workspaceId(), job.projectId(), stage, status,
                providerRequestSummary, providerResultSummary, toolCallName,
                toolArgumentsSummary, toolResultStatus, modelInferenceSummary,
                failureDiagnostic, clock.instant().toString()));
    }

    private static String safeReason(String reason) {
        if (reason == null || !reason.matches("[A-Z0-9_]{1,64}")) return "AI_JOB_FAILED";
        return reason;
    }

    private static long elapsed(long started) {
        return Math.max(0, Duration.ofNanos(System.nanoTime() - started).toMillis());
    }

    @Override
    public void close() {
        for (Running value : running.values()) {
            value.cancelled = true;
            if (value.context != null) value.context.cancel();
            if (value.future != null) value.future.cancel(true);
        }
        executor.shutdownNow();
    }

    private static final class Running {
        private volatile boolean cancelled;
        private volatile ToolExecutionContext context;
        private volatile Future<?> future;
    }

    private static final class JobFailure extends RuntimeException {
        private final String code;
        private final String diagnostic;
        private JobFailure(String code) {
            this(code, code);
        }
        private JobFailure(String code, String diagnostic) {
            super(code, null, false, false);
            this.code = code;
            this.diagnostic = AiPromptSanitizer.sanitizeDiagnostic(diagnostic);
        }
    }
}

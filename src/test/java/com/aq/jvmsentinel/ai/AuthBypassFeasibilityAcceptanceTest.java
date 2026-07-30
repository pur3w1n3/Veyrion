package com.aq.jvmsentinel.ai;
import com.aq.jvmsentinel.AcceptanceAssertions;

import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.chat.ChatTransport;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * AUTH 模型编写的 bypass PoC 经 schema 闸门、持久化并注入 DYNAMIC，
 * 无效候选被拒绝。鉴权面 scan 拒绝静默空 PoC
 * （re-ask / RULE_GENERATED 种子）。非空 feasibility 强制 DYNAMIC sandbox_probe
 * 尝试（re-ask / 服务端自动入队）。
 */
public final class AuthBypassFeasibilityAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        parseAcceptsAiAuthMaterial();
        parseRejectsInvalidCandidates();
        planProposeAcceptsAuthorizationHeader();
        authConclusionInjectedIntoDynamicPrompt();
        authSurfaceEmptyPocsTriggersReAskThenSeed();
        authSurfaceEmptyRejectedWithoutSeedWhenNoEntries();
        selectTopProbeTargetsPrefersAuthMaterial();
        dynamicNonEmptyFeasibilityRequiresProbeOrReAsk();
        dynamicZeroProbeAfterReAskAutoEnqueues();
        bypassConfirmRequiresDynamicEvidence();
        System.out.println("AuthBypassFeasibilityAcceptanceTest: PASS");
    }

    private static void parseAcceptsAiAuthMaterial() {
        String jwt = "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9.";
        String json = """
                {
                  "bypassPoCs": [{
                    "entryRef": "entry:entry-ai",
                    "techniqueId": "ALG_NONE",
                    "track": "BYPASS_CANDIDATE",
                    "rationale": "alg-none JWT hypothesis",
                    "confidence": 0.55,
                    "authorizationHeader": "Bearer %s",
                    "evidenceRefs": ["evidence-ai"]
                  }]
                }
                """.formatted(jwt);
        AuthBypassFeasibility.ParseResult parsed = AuthBypassFeasibility.parseAndValidate(
                json, Set.of("entry:entry-ai"));
        check(parsed.candidates().size() == 1, "AI PoC with Authorization accepted");
        AuthBypassCandidate candidate = parsed.candidates().get(0);
        check(candidate.hasAuthMaterial(), "auth material retained");
        check(candidate.probeAuthToken().equals(jwt), "Bearer prefix stripped for probe token");
        check(parsed.rejected().isEmpty(), "no false rejects for valid AI PoC");
    }

    private static void parseRejectsInvalidCandidates() {
        String json = """
                {
                  "bypassCandidates": [
                    {"entryRef":"/admin/secret","techniqueId":"CUSTOM_POC","authorizationHeader":"x"},
                    {"entryRef":"entry:entry-ai","techniqueId":"BAD ID","authorizationHeader":"x"},
                    {"entryRef":"entry:missing","techniqueId":"CUSTOM_POC","authorizationHeader":"x"},
                    {"entryRef":"entry:entry-ai","techniqueId":"CUSTOM_POC",
                     "authorizationHeader":"rm -rf / && drop table users"}
                  ]
                }
                """;
        AuthBypassFeasibility.ParseResult parsed = AuthBypassFeasibility.parseAndValidate(
                json, Set.of("entry:entry-ai"));
        check(parsed.candidates().isEmpty(), "invalid PoCs rejected");
        check(!parsed.rejected().isEmpty(), "reject reasons recorded");
    }

    private static void planProposeAcceptsAuthorizationHeader() {
        ToolDataSource source = new ToolDataSource() {
            @Override
            public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                                String query, int limit) {
                return List.of();
            }

            @Override
            public java.util.Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope,
                                                               String evidenceRef) {
                if ("entry:entry-a".equals(evidenceRef) || "entry-a".equals(evidenceRef)) {
                    ObjectNode value = JSON.createObjectNode();
                    value.put("id", "entry-a");
                    value.put("method", "GET");
                    value.put("route", "/api/admin");
                    return java.util.Optional.of(new FactRecord(scope, "entry:entry-a", value));
                }
                return java.util.Optional.empty();
            }

            @Override
            public java.util.Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope,
                                                                   String entrypointRef) {
                String ref = entrypointRef.startsWith("entry:") ? entrypointRef : "entry:" + entrypointRef;
                return findEvidence(scope, ref);
            }
        };
        AiToolRegistry registry = new AiToolRegistry(source);
        ObjectNode args = JSON.createObjectNode();
        args.put("entrypointRef", "entry:entry-a");
        args.put("objective", "forge alg-none admin JWT");
        args.put("techniqueId", "ALG_NONE");
        args.put("track", "BYPASS_CANDIDATE");
        args.put("authorizationHeader", "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.");
        args.put("confidence", 0.7);
        var result = registry.execute(
                new CanonicalToolContracts.ToolCall(1, "poc-1", "plan_propose", args),
                ToolExecutionContext.bind(
                        new ToolExecutionContext.Scope("local", "project-a"),
                        "local-admin", "job-a", AgentRole.AUTH_ANALYSIS,
                        new ToolExecutionContext.Budget(4, 16_384, 8, 16_384,
                                Instant.now().plusSeconds(60))));
        check(result.status() == ToolStatus.SUCCESS, "plan_propose accepts AI authorizationHeader");
        check(result.outputs().get(0).value().has("bypassPoC"), "bypassPoC attached to plan");
        check(result.outputs().get(0).value().path("bypassPoC").path("authorizationHeader")
                        .asText().contains("eyJ"),
                "AI JWT material preserved in plan output");

        ObjectNode missingAuth = JSON.createObjectNode();
        missingAuth.put("entrypointRef", "entry:entry-a");
        missingAuth.put("objective", "probe without Authorization");
        missingAuth.put("techniqueId", "MISSING_AUTH");
        missingAuth.put("track", "UNAUTH");
        missingAuth.put("authorizationHeader", "");
        missingAuth.put("confidence", 0.4);
        var missingResult = registry.execute(
                new CanonicalToolContracts.ToolCall(1, "poc-missing", "plan_propose", missingAuth),
                ToolExecutionContext.bind(
                        new ToolExecutionContext.Scope("local", "project-a"),
                        "local-admin", "job-missing", AgentRole.AUTH_ANALYSIS,
                        new ToolExecutionContext.Budget(4, 16_384, 8, 16_384,
                                Instant.now().plusSeconds(60))));
        check(missingResult.status() == ToolStatus.SUCCESS,
                "plan_propose accepts MISSING_AUTH with empty authorizationHeader");
        check("MISSING_AUTH".equals(missingResult.outputs().get(0).value().path("techniqueId").asText()),
                "MISSING_AUTH technique preserved");
        check("UNAUTH".equals(missingResult.outputs().get(0).value().path("track").asText()),
                "MISSING_AUTH track is UNAUTH");
        check(!missingResult.outputs().get(0).value().path("bypassPoC").path("hasAuthMaterial").asBoolean(true),
                "MISSING_AUTH PoC has no auth material");
    }

    private static void authConclusionInjectedIntoDynamicPrompt() throws Exception {
        Path root = Files.createTempDirectory("veyrion-auth-poc");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-poc", "PoC fixture", now, "local-admin");
        Path artifact = root.resolve("Fixture.class");
        Files.writeString(artifact, "fixture");
        String digest = "b".repeat(64);
        store.registerArtifact(project, new ArtifactDescriptor("artifact-poc", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"), "local-admin");
        var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, "scan-poc", "entry-ai",
                "HTTP", "GET", "/api/admin", "example.AdminController", "example",
                List.of(), List.of("auth=jwt"), "STATIC_INFERRED", 0.8, 0, List.of("evidence-ai"));
        var evidence = new ApiDtos.EvidenceDto(1, project.projectId(), digest, "scan-poc",
                "evidence-ai", "FACT", "classfile", 1.0, "jwt utility", now,
                "test", "none", "snapshot-poc", "MOCK", "STATIC_INFERRED");
        var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, "scan-poc",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of("evidence-ai"), List.of(entry), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan,
                Map.of(evidence.evidenceId(), evidence), List.of(), List.of()), "local-admin");

        store.saveProvider("openai", "OpenAI", ProviderKind.OPENAI_CHAT,
                "https://api.openai.example", "gpt-test", true, "sk-test-key",
                "local-admin", now);
        store.saveRoleBinding("project-poc", AgentRole.AUTH_ANALYSIS,
                "openai", "gpt-test", "local-admin", now);
        store.saveRoleBinding("project-poc", AgentRole.DYNAMIC_VERIFICATION,
                "openai", "gpt-test", "local-admin", now);

        String authFinal = """
                Auth model ready.
                ```json
                {"bypassPoCs":[{"entryRef":"entry:entry-ai","techniqueId":"ALG_NONE","track":"BYPASS_CANDIDATE",
                "rationale":"try alg-none","confidence":0.6,
                "authorizationHeader":"eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9."}]}
                ```
                """;
        String authResponseBody = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                + "\"content\":" + JSON.writeValueAsString(authFinal) + "}}]}";
        ChatTransport authTransport = (provider, credential, request, limits) ->
                new ProviderChatTransport.Response(200,
                        authResponseBody.getBytes(StandardCharsets.UTF_8), "auth-req", 1);
        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, authTransport, Clock.systemUTC())) {
            var authJob = store.createAiJob("project-poc", AgentRole.AUTH_ANALYSIS,
                    "scan-poc", AiOutputLanguage.ZH_CN, true, "local-admin", Instant.now().toString());
            orchestrator.submit(authJob, "local-admin");
            var done = awaitTerminal(store, authJob.aiJobId());
            check("COMPLETED".equals(done.status()), "AUTH job completed");
            check(done.conclusionJson() != null && done.conclusionJson().contains("bypassPoCs"),
                    "AUTH conclusion persists bypassPoCs");
            check(done.conclusionJson().contains("eyJhbGciOiJub25lIn0"),
                    "AI JWT material persisted under schema gate");
            check(!done.conclusionJson().contains("\"classification\":\"VERIFIED\""),
                    "PoCs remain INFERENCE");
        }

        AtomicReference<String> dynamicPrompt = new AtomicReference<>("");
        ChatTransport dynamicTransport = (provider, credential, request, limits) -> {
            dynamicPrompt.set(request.toString());
            return new ProviderChatTransport.Response(200,
                    "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                            .concat("\"content\":\"dynamic checked PoCs\"}}]}")
                            .getBytes(StandardCharsets.UTF_8), "dyn-req", 1);
        };
        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, dynamicTransport, Clock.systemUTC(),
                (projectId, artifactDigest, scanId) -> List.of(),
                (scanId, scope, principalId, jobId, toolCallId, entrypointRef, candidateInputs, maxRequests,
                        techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId)
                        -> java.util.Optional.empty(),
                (projectId, artifactDigest, scanId) -> List.of())) {
            var dyn = store.createAiJob("project-poc", AgentRole.DYNAMIC_VERIFICATION,
                    "scan-poc", AiOutputLanguage.ZH_CN, true, "local-admin", Instant.now().toString());
            orchestrator.submit(dyn, "local-admin");
            check("COMPLETED".equals(awaitTerminal(store, dyn.aiJobId()).status()),
                    "DYNAMIC job completed");
        }
        String prompt = dynamicPrompt.get();
        check(prompt.contains("AUTH_BYPASS_FEASIBILITY"),
                "DYNAMIC prompt injects AUTH_BYPASS_FEASIBILITY");
        check(prompt.contains("entry:entry-ai") && prompt.contains("ALG_NONE"),
                "DYNAMIC prompt carries validated PoC entry/technique");
        check(prompt.contains("eyJhbGciOiJub25lIn0"),
                "DYNAMIC prompt includes AI auth material for attempt");
    }

    /** JWT / AUTH_GAP 面 + 空 AUTH 结论 → re-ask 后 RULE_GENERATED 草稿。 */
    private static void authSurfaceEmptyPocsTriggersReAskThenSeed() throws Exception {
        Path root = Files.createTempDirectory("veyrion-auth-surface");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-surface", "Surface fixture", now, "local-admin");
        Path artifact = root.resolve("Fixture.class");
        Files.writeString(artifact, "fixture");
        String digest = "c".repeat(64);
        store.registerArtifact(project, new ArtifactDescriptor("artifact-surface", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"), "local-admin");
        var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, "scan-surface", "entry-jwt",
                "HTTP", "GET", "/api/admin", "example.AdminController", "example",
                List.of(), List.of("auth=jwt"), "STATIC_INFERRED", 0.8, 0, List.of("evidence-jwt"));
        var jwtSink = new ApiDtos.SinkDto(1, project.projectId(), digest, "scan-surface",
                "sink-jwt-1", "JWT", "io.jsonwebtoken.Jwts", "class-name rule",
                "STATIC_INFERRED", 0.6, List.of("evidence-jwt"));
        var authGap = new ApiDtos.SinkDto(1, project.projectId(), digest, "scan-surface",
                "sink-auth-gap-1", "AUTH_GAP", "example.AdminController", "missing check",
                "STATIC_INFERRED", 0.5, List.of("evidence-jwt"));
        var evidence = new ApiDtos.EvidenceDto(1, project.projectId(), digest, "scan-surface",
                "evidence-jwt", "FACT", "classfile", 1.0, "jwt utility", now,
                "test", "none", "snapshot-surface", "MOCK", "STATIC_INFERRED");
        var finding = new ApiDtos.FindingDto(1, project.projectId(), digest, "scan-surface",
                "finding-jwt", "JWT/令牌处理", "low", "STATIC_INFERRED",
                "entry-jwt", "GET /api/admin", "sink-jwt-1", "JWT", "none", List.of(),
                List.of("evidence-jwt"), 1, 0.6, "MOCK");
        var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, "scan-surface",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of("evidence-jwt"), List.of(entry), List.of(), List.of(jwtSink, authGap),
                List.of(finding), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan,
                Map.of(evidence.evidenceId(), evidence), List.of(), List.of()), "local-admin");

        AuthBypassFeasibility.AuthSurface surface = AuthBypassFeasibility.detectAuthSurface(scan);
        check(surface.present(), "JWT/AUTH_GAP/auth-annotated surface detected");
        check(AuthBypassFeasibility.isIncomplete(List.of(), surface),
                "empty PoCs incomplete when auth surface present");
        check(!AuthBypassFeasibility.seedRuleGeneratedDrafts(scan).isEmpty(),
                "server can seed RULE_GENERATED drafts from surface");

        store.saveProvider("openai", "OpenAI", ProviderKind.OPENAI_CHAT,
                "https://api.openai.example", "gpt-test", true, "sk-test-key",
                "local-admin", now);
        store.saveRoleBinding("project-surface", AgentRole.AUTH_ANALYSIS,
                "openai", "gpt-test", "local-admin", now);

        java.util.concurrent.atomic.AtomicInteger calls =
                new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicBoolean sawRepair =
                new java.util.concurrent.atomic.AtomicBoolean();
        AtomicInteger codeQueryCalls = new AtomicInteger();
        ChatTransport transport = (provider, credential, request, limits) -> {
            int n = calls.incrementAndGet();
            String requestText = request.toString();
            if (requestText.contains(AuthBypassFeasibility.ENFORCEMENT_REQUIRED)) {
                sawRepair.set(true);
            }
            // 满足 AUTH_CODE_QUERY_REQUIRED 一次，然后继续省略 bypassPoCs 以走种子路径。
            if (requestText.contains("\"code_query\"") && codeQueryCalls.get() == 0
                    && (requestText.contains(AuthBypassFeasibility.CODE_QUERY_REQUIRED)
                    || n == 1)) {
                codeQueryCalls.incrementAndGet();
                try {
                    ObjectNode args = JSON.createObjectNode();
                    args.put("query", "jwt filter interceptor skip-url");
                    args.put("limit", 10);
                    ObjectNode function = JSON.createObjectNode();
                    function.put("name", "code_query");
                    function.put("arguments", JSON.writeValueAsString(args));
                    ObjectNode call = JSON.createObjectNode();
                    call.put("id", "cq-1");
                    call.put("type", "function");
                    call.set("function", function);
                    ObjectNode message = JSON.createObjectNode();
                    message.put("role", "assistant");
                    message.putNull("content");
                    message.putArray("tool_calls").add(call);
                    ObjectNode choice = JSON.createObjectNode();
                    choice.put("finish_reason", "tool_calls");
                    choice.set("message", message);
                    ObjectNode rootNode = JSON.createObjectNode();
                    rootNode.putArray("choices").add(choice);
                    return new ProviderChatTransport.Response(200,
                            JSON.writeValueAsString(rootNode).getBytes(StandardCharsets.UTF_8),
                            "surface-cq-" + n, 1);
                } catch (Exception encodeFailure) {
                    throw new IllegalStateException(encodeFailure);
                }
            }
            // 始终省略结构化 bypassPoCs，迫使服务端 re-ask 后种子。
            String body = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                    + "\"content\":\"鉴权模型：疑似 JWT，但本次不输出 PoC JSON。\"}}]}";
            return new ProviderChatTransport.Response(200,
                    body.getBytes(StandardCharsets.UTF_8), "surface-req-" + n, 1);
        };
        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, transport, Clock.systemUTC())) {
            var authJob = store.createAiJob("project-surface", AgentRole.AUTH_ANALYSIS,
                    "scan-surface", AiOutputLanguage.ZH_CN, true, "local-admin", Instant.now().toString());
            orchestrator.submit(authJob, "local-admin");
            var done = awaitTerminal(store, authJob.aiJobId());
            if (!"COMPLETED".equals(done.status())) {
                StringBuilder events = new StringBuilder();
                for (var event : store.aiJobEvents(authJob.aiJobId())) {
                    events.append(event.stage()).append('/').append(event.status())
                            .append(':').append(event.failureDiagnostic()).append('|');
                }
                throw new AssertionError("AUTH job completed after enforcement; status="
                        + done.status() + " stopReason=" + done.stopReason()
                        + " calls=" + calls.get() + " events=" + events
                        + " conclusion=" + done.conclusionJson());
            }
            check(calls.get() >= 2, "AUTH_BYPASS_POC_REQUIRED triggered a re-ask round");
            check(sawRepair.get(), "repair turn carried AUTH_BYPASS_POC_REQUIRED");
            check(done.conclusionJson() != null, "conclusion persisted");
            var rootNode = JSON.readTree(done.conclusionJson());
            check(rootNode.path("bypassPoCs").isArray() && rootNode.path("bypassPoCs").size() > 0,
                    "empty AUTH PoCs on auth surface rejected; non-empty drafts persisted");
            check(AuthBypassFeasibility.DRAFT_RULE_GENERATED.equals(
                            rootNode.path("pocDraftSource").asText()),
                    "drafts marked RULE_GENERATED");
            check(AuthBypassFeasibility.ENFORCEMENT_SEEDED.equals(
                            rootNode.path("enforcement").asText()),
                    "enforcement code AUTH_BYPASS_POC_SEEDED");
            check(rootNode.toString().contains("ALG_NONE")
                            || rootNode.toString().contains("MISSING_AUTH"),
                    "seeded techniques include JWT/auth probes");
            check(rootNode.toString().contains("eyJ") || rootNode.toString().contains("MISSING_AUTH"),
                    "seeded material usable by DYNAMIC sandbox_probe");
            check(!"VERIFIED".equals(rootNode.path("verificationStatus").asText()),
                    "seeded drafts remain INFERENCE");
        }
    }

    /** JWT finding 但零 entry 时 surface 检测器仍报 incomplete（无静默 OK）。 */
    private static void authSurfaceEmptyRejectedWithoutSeedWhenNoEntries() {
        var finding = new ApiDtos.FindingDto(1, "p", "d".repeat(64), "scan-x",
                "finding-jwt", "JWT utility", "low", "STATIC_INFERRED",
                "none", "none", "sink-1", "JWT", "none", List.of(),
                List.of(), 0, 0.5, "MOCK");
        var jwtSink = new ApiDtos.SinkDto(1, "p", "d".repeat(64), "scan-x",
                "sink-1", "JWT", "io.jsonwebtoken.Jwts", "rule",
                "STATIC_INFERRED", 0.6, List.of());
        var scan = new ApiDtos.ScanDto(1, "p", "d".repeat(64), "scan-x",
                "COMPLETED", "STATIC_INFERRED", "MOCK", Instant.now().toString(), Instant.now().toString(),
                List.of(), List.of(), List.of(), List.of(jwtSink), List.of(finding), List.of());
        AuthBypassFeasibility.AuthSurface surface = AuthBypassFeasibility.detectAuthSurface(scan);
        check(surface.present(), "JWT sink alone is auth surface");
        check(AuthBypassFeasibility.isIncomplete(List.of(), surface),
                "empty PoCs incomplete for JWT-only surface");
        check(AuthBypassFeasibility.seedRuleGeneratedDrafts(scan).isEmpty(),
                "no entries → no seedable drafts (still incomplete, not silently OK)");
        var node = AuthBypassFeasibility.toConclusionNode(
                "no pocs", List.of(), "NO_STRUCTURED_BYPASS_BLOCK",
                List.of("NO_STRUCTURED_BYPASS_BLOCK"),
                new AuthBypassFeasibility.EnforcementMeta(
                        true, AuthBypassFeasibility.ENFORCEMENT_REQUIRED, "", true));
        check(AuthBypassFeasibility.ENFORCEMENT_REQUIRED.equals(node.path("enforcement").asText()),
                "conclusion records AUTH_BYPASS_POC_REQUIRED when surface present and empty");
        check(node.path("authSurfacePresent").asBoolean(false),
                "authSurfacePresent flag persisted");
    }

    private static void selectTopProbeTargetsPrefersAuthMaterial() {
        List<AuthBypassCandidate> input = List.of(
                AuthBypassCandidate.of("entry:e1", "MISSING_AUTH", null, "no header",
                        List.of(), 0.2, "", "", "", ""),
                AuthBypassCandidate.of("entry:e2", "ALG_NONE", null, "jwt",
                        List.of(), 0.6, "eyJhbGciOiJub25lIn0.e30.", "", "", ""),
                AuthBypassCandidate.of("entry:e3", "EMPTY_BEARER", null, "empty",
                        List.of(), 0.3, "", "", "", ""),
                AuthBypassCandidate.of("entry:e2", "ALG_NONE", null, "dup",
                        List.of(), 0.6, "eyJhbGciOiJub25lIn0.e30.", "", "", ""));
        List<AuthBypassCandidate> top = AuthBypassFeasibility.selectTopProbeTargets(input, 3);
        check(top.size() == 3, "selects up to limit");
        check(top.get(0).hasAuthMaterial(), "auth-material PoC ranked first");
        check("entry:e2".equals(top.get(0).entryRef()), "auth-material entry preferred");
    }

    /** 非空 AUTH feasibility + 叙事-only DYNAMIC → re-ask → sandbox_probe。 */
    private static void dynamicNonEmptyFeasibilityRequiresProbeOrReAsk() throws Exception {
        Path root = Files.createTempDirectory("veyrion-dyn-probe");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-dyn-probe", "Dyn probe fixture", now, "local-admin");
        Path artifact = root.resolve("Fixture.class");
        Files.writeString(artifact, "fixture");
        String digest = "d".repeat(64);
        store.registerArtifact(project, new ArtifactDescriptor("artifact-dyn", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"), "local-admin");
        var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, "scan-dyn", "entry-dyn",
                "HTTP", "GET", "/api/admin", "example.AdminController", "example",
                List.of(), List.of("auth=jwt"), "STATIC_INFERRED", 0.8, 0, List.of("evidence-dyn"));
        var evidence = new ApiDtos.EvidenceDto(1, project.projectId(), digest, "scan-dyn",
                "evidence-dyn", "FACT", "classfile", 1.0, "jwt utility", now,
                "test", "none", "snapshot-dyn", "MOCK", "STATIC_INFERRED");
        var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, "scan-dyn",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of("evidence-dyn"), List.of(entry), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan,
                Map.of(evidence.evidenceId(), evidence), List.of(), List.of()), "local-admin");
        store.saveProvider("openai", "OpenAI", ProviderKind.OPENAI_CHAT,
                "https://api.openai.example", "gpt-test", true, "sk-test-key",
                "local-admin", now);
        store.saveRoleBinding("project-dyn-probe", AgentRole.AUTH_ANALYSIS,
                "openai", "gpt-test", "local-admin", now);
        store.saveRoleBinding("project-dyn-probe", AgentRole.DYNAMIC_VERIFICATION,
                "openai", "gpt-test", "local-admin", now);

        String authFinal = """
                ```json
                {"bypassPoCs":[{"entryRef":"entry:entry-dyn","techniqueId":"ALG_NONE","track":"BYPASS_CANDIDATE",
                "rationale":"alg-none","confidence":0.5,"evidenceRefs":["code:jwt-filter"],
                "authorizationHeader":"eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."}],
                "infeasibleEntries":[
                  {"entryRef":"entry:entry-dyn","reason":"session cookie path not exposed","evidenceRef":"code:session"},
                  {"entryRef":"entry:entry-dyn","reason":"API key header unused on route","evidenceRef":"code:apikey"}
                ]}
                ```
                """;
        AtomicInteger authCalls = new AtomicInteger();
        ChatTransport authTransport = (provider, credential, request, limits) -> {
            int n = authCalls.incrementAndGet();
            String text = request.toString();
            try {
                if (text.contains("\"code_query\"") && n == 1) {
                    ObjectNode args = JSON.createObjectNode();
                    args.put("query", "jwt filter");
                    args.put("limit", 8);
                    ObjectNode function = JSON.createObjectNode();
                    function.put("name", "code_query");
                    function.put("arguments", JSON.writeValueAsString(args));
                    ObjectNode call = JSON.createObjectNode();
                    call.put("id", "auth-cq-1");
                    call.put("type", "function");
                    call.set("function", function);
                    ObjectNode message = JSON.createObjectNode();
                    message.put("role", "assistant");
                    message.putNull("content");
                    message.putArray("tool_calls").add(call);
                    ObjectNode choice = JSON.createObjectNode();
                    choice.put("finish_reason", "tool_calls");
                    choice.set("message", message);
                    ObjectNode rootNode = JSON.createObjectNode();
                    rootNode.putArray("choices").add(choice);
                    return new ProviderChatTransport.Response(200,
                            JSON.writeValueAsString(rootNode).getBytes(StandardCharsets.UTF_8),
                            "auth-dyn-cq", 1);
                }
            } catch (Exception encodeFailure) {
                throw new IllegalStateException(encodeFailure);
            }
            try {
                String authResponseBody = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                        + "\"content\":" + JSON.writeValueAsString(authFinal) + "}}]}";
                return new ProviderChatTransport.Response(200,
                        authResponseBody.getBytes(StandardCharsets.UTF_8), "auth-dyn", 1);
            } catch (Exception encodeFailure) {
                throw new IllegalStateException(encodeFailure);
            }
        };
        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, authTransport, Clock.systemUTC())) {
            var authJob = store.createAiJob("project-dyn-probe", AgentRole.AUTH_ANALYSIS,
                    "scan-dyn", AiOutputLanguage.ZH_CN, true, "local-admin", Instant.now().toString());
            orchestrator.submit(authJob, "local-admin");
            check("COMPLETED".equals(awaitTerminal(store, authJob.aiJobId()).status()),
                    "AUTH fixture completed");
        }

        AtomicInteger calls = new AtomicInteger();
        AtomicBoolean sawRepair = new AtomicBoolean();
        AtomicInteger modelProbeCalls = new AtomicInteger();
        AtomicInteger executorProbes = new AtomicInteger();
        ChatTransport dynTransport = (provider, credential, request, limits) -> {
            int n = calls.incrementAndGet();
            String text = request.toString();
            // repair 轮次与 role-prompt 提及同一 code 不同。
            boolean repairTurn = text.contains("工具阶段已重新打开")
                    || text.contains("Tool phase is re-opened");
            if (repairTurn) {
                sawRepair.set(true);
            }
            String body;
            try {
                if (repairTurn && modelProbeCalls.get() == 0) {
                    modelProbeCalls.incrementAndGet();
                    ObjectNode args = JSON.createObjectNode();
                    args.put("entrypointRef", "entry:entry-dyn");
                    args.put("techniqueId", "ALG_NONE");
                    args.put("authorizationHeader",
                            "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.");
                    ObjectNode function = JSON.createObjectNode();
                    function.put("name", "sandbox_probe");
                    function.put("arguments", JSON.writeValueAsString(args));
                    ObjectNode call = JSON.createObjectNode();
                    call.put("id", "probe-1");
                    call.put("type", "function");
                    call.set("function", function);
                    ObjectNode message = JSON.createObjectNode();
                    message.put("role", "assistant");
                    message.putNull("content");
                    message.putArray("tool_calls").add(call);
                    ObjectNode choice = JSON.createObjectNode();
                    choice.put("finish_reason", "tool_calls");
                    choice.set("message", message);
                    ObjectNode rootNode = JSON.createObjectNode();
                    rootNode.putArray("choices").add(choice);
                    body = JSON.writeValueAsString(rootNode);
                } else {
                    body = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                            + "\"content\":\"动态验证：已对照 PathRun，未升 VERIFIED。\"}}]}";
                }
            } catch (Exception encodeFailure) {
                throw new IllegalStateException(encodeFailure);
            }
            return new ProviderChatTransport.Response(200,
                    body.getBytes(StandardCharsets.UTF_8), "dyn-req-" + n, 1);
        };
        String dynJobId;
        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, dynTransport, Clock.systemUTC(),
                (projectId, artifactDigest, scanId) -> List.of(),
                (scanId, scope, principalId, jobId, toolCallId, entrypointRef, candidateInputs, maxRequests,
                        techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId) -> {
                    executorProbes.incrementAndGet();
                    ObjectNode fact = JSON.createObjectNode();
                    fact.put("schemaVersion", 1);
                    fact.put("state", "COMPLETED");
                    fact.put("lifecycle", "COMPLETED");
                    fact.put("entrypointRef", entrypointRef);
                    fact.put("httpStatus", 401);
                    fact.put("outcomeClass", "AUTH_CHALLENGE");
                    fact.put("pathRunCount", 1);
                    fact.put("probeAttemptId", "patt-test-" + toolCallId);
                    return Optional.of(new ToolDataSource.FactRecord(scope,
                            "sandbox-probe:attempt:test:" + toolCallId, fact));
                },
                (projectId, artifactDigest, scanId) -> List.of())) {
            var dyn = store.createAiJob("project-dyn-probe", AgentRole.DYNAMIC_VERIFICATION,
                    "scan-dyn", AiOutputLanguage.ZH_CN, true, "local-admin", Instant.now().toString());
            dynJobId = dyn.aiJobId();
            orchestrator.submit(dyn, "local-admin");
            var done = awaitTerminal(store, dynJobId);
            if (!"COMPLETED".equals(done.status())) {
                throw new AssertionError("DYNAMIC completed after probe enforcement; status="
                        + done.status() + " stopReason=" + done.stopReason()
                        + " calls=" + calls.get() + " conclusion=" + done.conclusionJson());
            }
            check(calls.get() >= 2, "DYNAMIC_POC_ATTEMPT_REQUIRED triggered a re-ask round");
            check(sawRepair.get(), "repair turn carried DYNAMIC_POC_ATTEMPT_REQUIRED");
            check(modelProbeCalls.get() >= 1, "model called sandbox_probe after re-ask");
            check(executorProbes.get() >= 1, "sandbox_probe reached server executor");
            check(done.conclusionJson() != null, "DYNAMIC conclusion persisted");
            var conclusion = JSON.readTree(done.conclusionJson());
            check(conclusion.path("sandboxProbeCount").asInt() >= 1,
                    "conclusion records sandboxProbeCount >= 1");
            check(AuthBypassFeasibility.DYNAMIC_ATTEMPT_SATISFIED.equals(
                            conclusion.path("enforcement").asText()),
                    "enforcement DYNAMIC_POC_ATTEMPT_SATISFIED after probe");
            check(conclusion.path("reAskTriggered").asBoolean(false),
                    "reAskTriggered recorded on DYNAMIC conclusion");
        }
        List<String> stages = new ArrayList<>();
        for (var event : store.aiJobEvents(dynJobId)) {
            stages.add(event.stage());
        }
        check(stages.contains("DYNAMIC_POC_ATTEMPT_REQUIRED"),
                "audit event DYNAMIC_POC_ATTEMPT_REQUIRED emitted");
    }

    /** re-ask 后仍叙事-only → 服务端自动入队聚焦探针（AUTH-seed 类比）。 */
    private static void dynamicZeroProbeAfterReAskAutoEnqueues() throws Exception {
        Path root = Files.createTempDirectory("veyrion-dyn-auto");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-dyn-auto", "Dyn auto fixture", now, "local-admin");
        Path artifact = root.resolve("Fixture.class");
        Files.writeString(artifact, "fixture");
        String digest = "e".repeat(64);
        store.registerArtifact(project, new ArtifactDescriptor("artifact-auto", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"), "local-admin");
        var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, "scan-auto", "entry-auto",
                "HTTP", "GET", "/api/admin", "example.AdminController", "example",
                List.of(), List.of("auth=jwt"), "STATIC_INFERRED", 0.8, 0, List.of("evidence-auto"));
        var evidence = new ApiDtos.EvidenceDto(1, project.projectId(), digest, "scan-auto",
                "evidence-auto", "FACT", "classfile", 1.0, "jwt utility", now,
                "test", "none", "snapshot-auto", "MOCK", "STATIC_INFERRED");
        var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, "scan-auto",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of("evidence-auto"), List.of(entry), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan,
                Map.of(evidence.evidenceId(), evidence), List.of(), List.of()), "local-admin");
        store.saveProvider("openai", "OpenAI", ProviderKind.OPENAI_CHAT,
                "https://api.openai.example", "gpt-test", true, "sk-test-key",
                "local-admin", now);
        store.saveRoleBinding("project-dyn-auto", AgentRole.AUTH_ANALYSIS,
                "openai", "gpt-test", "local-admin", now);
        store.saveRoleBinding("project-dyn-auto", AgentRole.DYNAMIC_VERIFICATION,
                "openai", "gpt-test", "local-admin", now);

        String authFinal = """
                ```json
                {"bypassPoCs":[{"entryRef":"entry:entry-auto","techniqueId":"MISSING_AUTH","track":"UNAUTH",
                "rationale":"probe without auth","confidence":0.4,"evidenceRefs":["code:auth-filter"]}],
                "infeasibleEntries":[
                  {"entryRef":"entry:entry-auto","reason":"no JWT alg-none path","evidenceRef":"code:jwt"},
                  {"entryRef":"entry:entry-auto","reason":"tenant branch unreachable","evidenceRef":"code:tenant"}
                ]}
                ```
                """;
        AtomicInteger authAutoCalls = new AtomicInteger();
        ChatTransport authTransport = (provider, credential, request, limits) -> {
            int n = authAutoCalls.incrementAndGet();
            String text = request.toString();
            try {
                if (text.contains("\"code_query\"") && n == 1) {
                    ObjectNode args = JSON.createObjectNode();
                    args.put("query", "auth filter");
                    args.put("limit", 8);
                    ObjectNode function = JSON.createObjectNode();
                    function.put("name", "code_query");
                    function.put("arguments", JSON.writeValueAsString(args));
                    ObjectNode call = JSON.createObjectNode();
                    call.put("id", "auth-auto-cq");
                    call.put("type", "function");
                    call.set("function", function);
                    ObjectNode message = JSON.createObjectNode();
                    message.put("role", "assistant");
                    message.putNull("content");
                    message.putArray("tool_calls").add(call);
                    ObjectNode choice = JSON.createObjectNode();
                    choice.put("finish_reason", "tool_calls");
                    choice.set("message", message);
                    ObjectNode rootNode = JSON.createObjectNode();
                    rootNode.putArray("choices").add(choice);
                    return new ProviderChatTransport.Response(200,
                            JSON.writeValueAsString(rootNode).getBytes(StandardCharsets.UTF_8),
                            "auth-auto-cq", 1);
                }
                String authResponseBody = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                        + "\"content\":" + JSON.writeValueAsString(authFinal) + "}}]}";
                return new ProviderChatTransport.Response(200,
                        authResponseBody.getBytes(StandardCharsets.UTF_8), "auth-auto", 1);
            } catch (Exception encodeFailure) {
                throw new IllegalStateException(encodeFailure);
            }
        };
        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, authTransport, Clock.systemUTC())) {
            var authJob = store.createAiJob("project-dyn-auto", AgentRole.AUTH_ANALYSIS,
                    "scan-auto", AiOutputLanguage.ZH_CN, true, "local-admin", Instant.now().toString());
            orchestrator.submit(authJob, "local-admin");
            check("COMPLETED".equals(awaitTerminal(store, authJob.aiJobId()).status()),
                    "AUTH fixture for auto-enqueue completed");
        }

        AtomicInteger calls = new AtomicInteger();
        AtomicInteger autoEnqueues = new AtomicInteger();
        ChatTransport dynTransport = (provider, credential, request, limits) -> {
            calls.incrementAndGet();
            // 始终叙事-only 以触发 re-ask 后服务端种子/自动入队。
            String body = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                    + "\"content\":\"仅叙事，不调用工具。\"}}]}";
            return new ProviderChatTransport.Response(200,
                    body.getBytes(StandardCharsets.UTF_8), "auto-req-" + calls.get(), 1);
        };
        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, dynTransport, Clock.systemUTC(),
                (projectId, artifactDigest, scanId) -> List.of(),
                (scanId, scope, principalId, jobId, toolCallId, entrypointRef, candidateInputs, maxRequests,
                        techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId) -> {
                    // 自动入队在真实 AI job id 下使用合成 toolCallId dyn-poc-N。
                    if (toolCallId != null && toolCallId.startsWith("dyn-poc-")) {
                        autoEnqueues.incrementAndGet();
                    }
                    ObjectNode fact = JSON.createObjectNode();
                    fact.put("schemaVersion", 1);
                    fact.put("state", "COMPLETED");
                    fact.put("lifecycle", "COMPLETED");
                    fact.put("entrypointRef", entrypointRef);
                    fact.put("pathRunCount", 1);
                    fact.put("probeAttemptId", "patt-auto-" + toolCallId);
                    return Optional.of(new ToolDataSource.FactRecord(scope,
                            "sandbox-probe:attempt:auto:" + toolCallId, fact));
                },
                (projectId, artifactDigest, scanId) -> List.of())) {
            var dyn = store.createAiJob("project-dyn-auto", AgentRole.DYNAMIC_VERIFICATION,
                    "scan-auto", AiOutputLanguage.ZH_CN, true, "local-admin", Instant.now().toString());
            orchestrator.submit(dyn, "local-admin");
            var done = awaitTerminal(store, dyn.aiJobId());
            check("COMPLETED".equals(done.status()), "DYNAMIC completed after auto-enqueue fallback");
            check(calls.get() >= 2, "re-ask consumed a round before auto-enqueue");
            check(autoEnqueues.get() >= 1, "server auto-enqueued focused PoC probe");
            var conclusion = JSON.readTree(done.conclusionJson());
            check(conclusion.path("sandboxProbeCount").asInt(0) == 0,
                    "model sandbox_probe count remained 0");
            check(conclusion.path("autoEnqueuedProbeCount").asInt(0) >= 1,
                    "conclusion records autoEnqueuedProbeCount");
            check(AuthBypassFeasibility.DYNAMIC_ATTEMPT_SEEDED.equals(
                            conclusion.path("enforcement").asText()),
                    "enforcement DYNAMIC_POC_ATTEMPT_SEEDED");
            check(conclusion.path("reAskTriggered").asBoolean(false),
                    "re-ask was attempted before auto-enqueue");
        }
    }

    /** P0-05：零动态 PathRun 证据不得产生 DYNAMIC_CONTRAST / confirmed。 */
    private static void bypassConfirmRequiresDynamicEvidence() throws Exception {
        List<AuthBypassCandidate> claimed = List.of(AuthBypassCandidate.of(
                "entry:entry-ai", "ALG_NONE",
                com.aq.jvmsentinel.model.IdentityTrack.BYPASS_CANDIDATE,
                "hypothesis only", List.of("evidence-ai"), 0.4,
                "Bearer x.y.", "", "", ""));

        String claimConfirmed = """
                {"bypassPoCs":[{"entryRef":"entry:entry-ai","techniqueId":"ALG_NONE",
                "track":"BYPASS_CANDIDATE","rationale":"bypass confirmed","confidence":0.9}],
                "bypassConfirmation":{"status":"DYNAMIC_CONTRAST","pathRunRefs":[]},
                "summary":"AUTH_BYPASS_CONFIRMED on entry-ai"}
                """;
        AuthBypassFeasibility.BypassConfirmation noEvidence =
                AuthBypassFeasibility.evaluateBypassConfirmation(claimConfirmed, List.of(), claimed);
        check(noEvidence.status() == AuthBypassFeasibility.BypassConfirmationStatus.INSUFFICIENT_EVIDENCE,
                "no PathRun evidence cannot confirm DYNAMIC_CONTRAST");
        check(noEvidence.pathRunRefs().isEmpty(), "insufficient evidence carries empty pathRunRefs");

        AuthBypassFeasibility.BypassConfirmation hypothesis =
                AuthBypassFeasibility.evaluateBypassConfirmation(
                        "{\"bypassPoCs\":[],\"summary\":\"feasibility hypothesis only\"}",
                        List.of(), claimed);
        check(hypothesis.status() == AuthBypassFeasibility.BypassConfirmationStatus.HYPOTHESIS,
                "non-claiming summary stays HYPOTHESIS without PathRuns");

        ApiDtos.PathRunDto challenge = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pathrun-auth-1", "scan-auth", "entry:GET:/api/admin",
                "BYPASS_CANDIDATE", "attempt-0", null, "GET", "application/json",
                "GET /api/admin track=BYPASS_CANDIDATE", "AUTH_CHALLENGE", 401,
                true, false, List.of(), "AUTH_CHALLENGE", "DYNAMIC_SUSPECTED",
                List.of("evidence-dyn"), "MOCK", "synthetic identity");
        AuthBypassFeasibility.BypassConfirmation withEvidence =
                AuthBypassFeasibility.evaluateBypassConfirmation(claimConfirmed, List.of(challenge), claimed);
        check(withEvidence.status() == AuthBypassFeasibility.BypassConfirmationStatus.DYNAMIC_CONTRAST,
                "AUTH_CHALLENGE PathRun allows DYNAMIC_CONTRAST when claimed");
        check(withEvidence.pathRunRefs().contains("pathrun-auth-1"),
                "pathRunRefs cite the AUTH_CHALLENGE PathRun");

        var node = AuthBypassFeasibility.toConclusionNode(
                "bypass confirmed without probes", claimed, "", List.of(), null,
                AuthBypassFeasibility.evaluateBypassConfirmation(
                        "bypass confirmed without probes", List.of(), claimed));
        check("INSUFFICIENT_EVIDENCE".equals(node.path("bypassConfirmation").path("status").asText()),
                "conclusion JSON carries bypassConfirmation.status=INSUFFICIENT_EVIDENCE");
        check(node.path("summary").asText().startsWith(
                        AuthBypassFeasibility.CONFIRMATION_INSUFFICIENT_PREFIX),
                "summary prefixed when confirmation evidence missing");
        check(!"DYNAMIC_CONTRAST".equals(node.path("bypassConfirmation").path("status").asText()),
                "server never persists DYNAMIC_CONTRAST without PathRun evidence");
    }

    private static SQLiteControlPlanePersistence.AiJobData awaitTerminal(
            ControlPlaneStore store, String jobId) throws InterruptedException {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(20);
        while (System.nanoTime() < deadline) {
            var job = store.requireAiJob(jobId);
            if ("COMPLETED".equals(job.status()) || "FAILED".equals(job.status())
                    || "CANCELLED".equals(job.status()) || "BLOCKED".equals(job.status())) {
                return job;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("AI job did not terminate: " + jobId);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        AcceptanceAssertions.record();
    }
}

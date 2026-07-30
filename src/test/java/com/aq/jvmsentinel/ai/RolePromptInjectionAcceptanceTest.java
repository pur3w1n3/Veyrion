package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.chat.ChatTransport;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Acceptance: §2.3 six-role prompt inject sections and default roleInstruction markers.
 * Captures first-round user prompts via mock ChatTransport; does not call a live LLM.
 */
public final class RolePromptInjectionAcceptanceTest {
    private static final String API_KEY = "sk-role-prompt-inject";

    public static void main(String[] args) throws Exception {
        toolAllowlistsAligned();
        promptInjectSectionsPresent();
        System.out.println("RolePromptInjectionAcceptanceTest: PASS");
    }

    private static void toolAllowlistsAligned() {
        ToolExecutionContext.Budget budget = new ToolExecutionContext.Budget(
                1, 2_048, 8, 4_096, Instant.MAX);
        ToolExecutionContext.Scope scope = new ToolExecutionContext.Scope("ws", "project");
        check(ToolExecutionContext.bind(scope, "p", "j", AgentRole.PRE_ANALYSIS, budget)
                        .allowedTools().contains("code_query"),
                "PRE allowlist includes code_query for TAINT_GRAPH");
        check(ToolExecutionContext.bind(scope, "p", "j", AgentRole.PATH_EXPLORATION, budget)
                        .allowedTools().contains("code_query"),
                "PATH allowlist includes code_query for TAINT_GRAPH");
        check(ToolExecutionContext.bind(scope, "p", "j", AgentRole.DYNAMIC_VERIFICATION, budget)
                        .allowedTools().contains("fuzz_strategy_get"),
                "DYNAMIC allowlist includes fuzz_strategy_get");
    }

    private static void promptInjectSectionsPresent() throws Exception {
        Path root = Files.createTempDirectory("veyrion-role-prompt");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-role-prompt", now);
        var project = store.createProject("project-role-prompt", "Role prompt fixture", now, "local-admin");
        Path artifact = root.resolve("Fixture.class");
        Files.writeString(artifact, "fixture");
        String digest = "d".repeat(64);
        store.registerArtifact(project, new ArtifactDescriptor("artifact-role", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"), "local-admin");

        var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, "scan-role", "entry-1",
                "HTTP", "GET", "/blade-auth/login", "org.springblade.AuthController", "blade",
                List.of("name=role, type=string, equals=ADMIN, maxLen=32"),
                List.of("auth=jwt", "if (role.equals(\"ADMIN\"))"),
                "STATIC_INFERRED", 0.8, 0, List.of("ev-1"));
        var sqlSink = new ApiDtos.SinkDto(1, project.projectId(), digest, "scan-role",
                "sink-sql-1", "SQL", "com.Example#query",
                "bytecode; taint-path=tp-001; bounded",
                "STATIC_INFERRED", 0.7, List.of("ev-1"));
        var evidence = new ApiDtos.EvidenceDto(1, project.projectId(), digest, "scan-role",
                "ev-1", "FACT", "classfile", 1.0, "fixture", now,
                "test", "none", "snap-role", "MOCK", "STATIC_INFERRED");
        var finding = new ApiDtos.FindingDto(1, project.projectId(), digest, "scan-role",
                "finding-1", "SQL", "medium", "STATIC_INFERRED",
                "entry-1", "GET /blade-auth/login", "sink-sql-1", "SQL", "none", List.of(),
                List.of("ev-1"), 1, 0.6, "MOCK",
                Map.of("rootCauseStatement", "concat", "cweId", "CWE-89",
                        "fixSuggestion", "use PreparedStatement",
                        "attackPath", List.of(Map.of(
                                "layer", "sink", "label", "SQL", "evidenceRefs", List.of("ev-1")))));
        var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, "scan-role",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of("ev-1"), List.of(entry), List.of(), List.of(sqlSink),
                List.of(finding), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan,
                Map.of(evidence.evidenceId(), evidence), List.of(), List.of()), "local-admin");

        store.saveProvider("openai", "OpenAI", ProviderKind.OPENAI_CHAT,
                "https://api.openai.example", "gpt-test", true, API_KEY,
                "local-admin", now);
        for (AgentRole role : AgentRole.values()) {
            store.saveRoleBinding(project.projectId(), role, "openai", "gpt-test", "local-admin", now);
        }

        // Seed TRIAGE conclusion so REPORT can inject fixSuggestion from prior rootCause.
        var triageSeed = store.createAiJob(project.projectId(), AgentRole.VULNERABILITY_TRIAGE,
                "scan-role", AiOutputLanguage.ZH_CN, true, "local-admin", now);
        store.updateAiJob(triageSeed, "COMPLETED", "OK", triageSeed.stagesJson(),
                "seed", 1L, 1, "[]",
                "{\"summary\":\"triage seed\",\"rootCause\":{\"attackPath\":[{\"layer\":\"sink\","
                        + "\"label\":\"SQL\",\"evidenceRefs\":[\"ev-1\"]}],"
                        + "\"rootCauseStatement\":\"concat\",\"affectedComponent\":\"Example#query\","
                        + "\"cweId\":\"CWE-89\",\"fixSuggestion\":\"use PreparedStatement\"}}",
                "local-admin", "seed-triage", Instant.now().toString());

        assertPrompt(store, AgentRole.PRE_ANALYSIS, AiOutputLanguage.ZH_CN,
                List.of("RANKED_SINK_CATALOG", "TAINT_GRAPH_SUMMARY", "BRANCH_CONSTRAINT_FACTS",
                        "code_query kind=TAINT_GRAPH", "RANKED_SINK"));
        assertPrompt(store, AgentRole.AUTH_ANALYSIS, AiOutputLanguage.ZH_CN,
                List.of("FRAMEWORK_ADAPTER_CONTEXT", "PARAMETER_CONSTRAINT_HINTS",
                        "adapterId=spring-mvc", "adapterId=spring-blade",
                        "preferSecondaryAuthHeaderHint=true", "HINT", "code_query",
                        "wellKnownKeyHint"));
        assertPrompt(store, AgentRole.DYNAMIC_VERIFICATION, AiOutputLanguage.ZH_CN,
                List.of("FUZZ_STRATEGY_CONTEXT", "BRANCH_CONSTRAINT_FACTS", "fuzz_strategy_get",
                        "selectedProbes"));
        assertPrompt(store, AgentRole.PATH_EXPLORATION, AiOutputLanguage.ZH_CN,
                List.of("COVERAGE_GAP_FACTS", "code_query kind=TAINT_GRAPH", "findingBindings",
                        "api:{method,route,entryRef}"));
        assertPrompt(store, AgentRole.VULNERABILITY_TRIAGE, AiOutputLanguage.ZH_CN,
                List.of("ROOT_CAUSE_TEMPLATE", "CWE_MAPPING_HINTS", "rootCause"));
        assertPrompt(store, AgentRole.REPORT_GENERATION, AiOutputLanguage.ZH_CN,
                List.of("## 漏洞相关", "findingBindings", "## 修复建议", "FIX_SUGGESTION_CONTEXT",
                        "use PreparedStatement"));
        assertPrompt(store, AgentRole.REPORT_GENERATION, AiOutputLanguage.EN,
                List.of("## Vulnerabilities", "findingBindings",
                        "Remediation / Fix Suggestions", "FIX_SUGGESTION_CONTEXT"));
        assertPrompt(store, AgentRole.PRE_ANALYSIS, AiOutputLanguage.EN,
                List.of("RANKED_SINK_CATALOG", "TAINT_GRAPH_SUMMARY", "BRANCH_CONSTRAINT_FACTS",
                        "code_query kind=TAINT_GRAPH"));
        assertPrompt(store, AgentRole.DYNAMIC_VERIFICATION, AiOutputLanguage.EN,
                List.of("FUZZ_STRATEGY_CONTEXT", "selectedProbes", "fuzz_strategy_get"));
    }

    private static void assertPrompt(
            ControlPlaneStore store, AgentRole role, AiOutputLanguage language,
            List<String> required) throws Exception {
        AtomicReference<String> captured = new AtomicReference<>("");
        ChatTransport transport = (provider, credential, request, limits) -> {
            if (captured.get().isBlank()) {
                captured.set(request.toString());
            }
            return new ProviderChatTransport.Response(200,
                    "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                            .concat("\"content\":\"ok\"}}]}")
                            .getBytes(StandardCharsets.UTF_8),
                    "role-prompt-" + role.name(), 1);
        };
        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, transport, Clock.systemUTC())) {
            var job = store.createAiJob("project-role-prompt", role, "scan-role",
                    language, true, "local-admin", Instant.now().toString());
            orchestrator.submit(job, "local-admin");
            var done = awaitTerminal(store, job.aiJobId());
            check("COMPLETED".equals(done.status()) || "FAILED".equals(done.status()),
                    role + " job reached terminal status");
        }
        String prompt = captured.get();
        check(!prompt.isBlank(), role + " prompt captured");
        for (String needle : required) {
            check(prompt.contains(needle), role + "/" + language + " prompt contains " + needle);
        }
    }

    private static com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData
    awaitTerminal(ControlPlaneStore store, String jobId) throws InterruptedException {
        long deadline = System.nanoTime() + 30_000_000_000L;
        while (System.nanoTime() < deadline) {
            var job = store.requireAiJob(jobId);
            if ("COMPLETED".equals(job.status()) || "FAILED".equals(job.status())
                    || "CANCELLED".equals(job.status()) || "BLOCKED".equals(job.status())) {
                return job;
            }
            Thread.sleep(20);
        }
        throw new AssertionError("AI job did not terminate: " + jobId);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.chat.ChatTransport;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-07: VULNERABILITY_TRIAGE conclusionJson retains structured rootCause and non-empty
 * evidenceRefs; AUTH PoC serialization must not empty those fields.
 */
public final class TriageConclusionFidelityAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        parseRetainsRootCauseAndEvidenceRefs();
        parseMarksInsufficientWhenRequiredMissing();
        copyRootCauseWhitelistsCounterevidence();
        triageJobConclusionRetainsRootCause();
        System.out.println("TriageConclusionFidelityAcceptanceTest: PASS ("
                + ASSERTIONS.get() + " assertions)");
    }

    private static void parseRetainsRootCauseAndEvidenceRefs() throws Exception {
        String summary = """
                Triage complete.
                ```json
                {
                  "evidenceRefs": ["pathrun:pr-1", "evidence:e-1"],
                  "counterevidence": ["pathrun:pr-neg"],
                  "rootCause": {
                    "attackPath": [
                      {"layer":"HTTP","label":"POST /api/user/query","evidenceRefs":["entry:entry-1"]},
                      {"layer":"sink","label":"SQL concat","evidenceRefs":["sink:sink-1","pathrun:pr-1"]}
                    ],
                    "rootCauseStatement":"missing parameterized query",
                    "affectedComponent":"UserRepository#findByUsername",
                    "cweId":"CWE-89",
                    "fixSuggestion":"use PreparedStatement placeholders"
                  }
                }
                ```
                """;
        TriageConclusion.ParseResult parsed = TriageConclusion.parseAndValidate(summary);
        check(!parsed.insufficientEvidence(), "valid TRIAGE is not INSUFFICIENT_EVIDENCE");
        check(parsed.rootCause() != null, "rootCause parsed");
        check("missing parameterized query".equals(parsed.rootCause().rootCauseStatement()),
                "rootCauseStatement retained");
        check("CWE-89".equals(parsed.rootCause().cweId()), "cweId retained");
        check("UserRepository#findByUsername".equals(parsed.rootCause().affectedComponent()),
                "affectedComponent retained");
        check(!parsed.rootCause().attackPath().isEmpty(), "attackPath retained");
        check(!parsed.evidenceRefs().isEmpty(), "top-level evidenceRefs non-empty");
        check(parsed.counterevidence().contains("pathrun:pr-neg"), "counterevidence retained");

        JsonNode node = TriageConclusion.toConclusionNode(summary, parsed);
        check(node.path("rootCause").isObject(), "serialized rootCause object present");
        check(node.path("rootCause").path("rootCauseStatement").asText().contains("parameterized"),
                "serialized rootCauseStatement retained");
        check(node.path("evidenceRefs").isArray() && node.path("evidenceRefs").size() > 0,
                "serialized evidenceRefs non-empty");
        check(!"AuthBypass".equals(node.path("conclusionKind").asText()),
                "conclusionKind is TRIAGE not AUTH");
        check("VULNERABILITY_TRIAGE".equals(node.path("conclusionKind").asText()),
                "conclusionKind=VULNERABILITY_TRIAGE");
        check(!node.has("bypassPoCs"),
                "TRIAGE node does not use AUTH bypassPoCs shape");
        check(!node.path("rootCause").isMissingNode() && !node.path("rootCause").isEmpty(),
                "rootCause not emptied by serialization");
    }

    private static void parseMarksInsufficientWhenRequiredMissing() {
        TriageConclusion.ParseResult empty = TriageConclusion.parseAndValidate("no structured json");
        check(empty.insufficientEvidence(), "missing rootCause → insufficient");
        JsonNode node = TriageConclusion.toConclusionNode("no structured json", empty);
        check(TriageConclusion.INSUFFICIENT_EVIDENCE.equals(node.path("classification").asText()),
                "classification fail-closed to INSUFFICIENT_EVIDENCE");
        check(node.path("rootCause").isObject(), "rootCause object still present when insufficient");
    }

    private static void copyRootCauseWhitelistsCounterevidence() {
        Map<String, Object> rootCause = Map.of(
                "attackPath", List.of(Map.of(
                        "layer", "HTTP",
                        "label", "GET /admin",
                        "evidenceRefs", List.of("entry:e1"))),
                "rootCauseStatement", "auth gap",
                "cweId", "CWE-862",
                "counterevidence", List.of("pathrun:deny-1"));
        var finding = new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, "project-a", "a".repeat(64), "scan-a",
                "finding-a", "Auth gap", "medium", "STATIC_INFERRED",
                "e1", "GET /admin", "sink-a", "AUTH_GAP", "none", List.of(),
                List.of("entry:e1"), 1, 0.5, "MOCK", rootCause);
        check(finding.rootCause() != null, "FindingDto keeps rootCause");
        check("auth gap".equals(finding.rootCause().get("rootCauseStatement")),
                "rootCauseStatement copied");
        Object counter = finding.rootCause().get("counterevidence");
        check(counter instanceof List<?> list && list.contains("pathrun:deny-1"),
                "copyRootCause whitelists counterevidence");
    }

    private static void triageJobConclusionRetainsRootCause() throws Exception {
        Path root = Files.createTempDirectory("veyrion-triage-fidelity");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-triage", "Triage fidelity", now, "local-admin");
        Path artifact = root.resolve("Fixture.class");
        Files.writeString(artifact, "fixture");
        String digest = "d".repeat(64);
        store.registerArtifact(project, new ArtifactDescriptor("artifact-triage", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"),
                "local-admin");
        var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, "scan-triage", "entry-1",
                "HTTP", "POST", "/api/user/query", "example.UserController", "example",
                List.of(), List.of(), "STATIC_INFERRED", 0.8, 0, List.of("evidence-1"));
        var sink = new ApiDtos.SinkDto(1, project.projectId(), digest, "scan-triage",
                "sink-1", "SQL", "example.UserRepository", "concat",
                "STATIC_INFERRED", 0.7, List.of("evidence-1"));
        var evidence = new ApiDtos.EvidenceDto(1, project.projectId(), digest, "scan-triage",
                "evidence-1", "FACT", "classfile", 1.0, "sql concat", now,
                "test", "none", "snapshot-triage", "MOCK", "STATIC_INFERRED");
        var finding = new ApiDtos.FindingDto(1, project.projectId(), digest, "scan-triage",
                "finding-1", "SQL injection candidate", "high", "STATIC_INFERRED",
                "entry-1", "POST /api/user/query", "sink-1", "SQL", "none", List.of(),
                List.of("evidence-1"), 1, 0.7, "MOCK");
        var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, "scan-triage",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of("evidence-1"), List.of(entry), List.of(), List.of(sink),
                List.of(finding), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan,
                Map.of(evidence.evidenceId(), evidence), List.of(finding), List.of()), "local-admin");

        store.saveProvider("openai", "OpenAI", ProviderKind.OPENAI_CHAT,
                "https://api.openai.example", "gpt-test", true, "sk-test-key",
                "local-admin", now);
        store.saveRoleBinding("project-triage", AgentRole.VULNERABILITY_TRIAGE,
                "openai", "gpt-test", "local-admin", now);

        String triageFinal = """
                Structured triage.
                ```json
                {
                  "evidenceRefs":["pathrun:pr-1","evidence-1","entry:entry-1"],
                  "counterevidence":["pathrun:pr-safe"],
                  "rootCause":{
                    "attackPath":[
                      {"layer":"HTTP","label":"POST /api/user/query","evidenceRefs":["entry:entry-1"]},
                      {"layer":"sink","label":"SQL concat","evidenceRefs":["sink:sink-1","pathrun:pr-1"]}
                    ],
                    "rootCauseStatement":"missing parameterized query",
                    "affectedComponent":"UserRepository#findByUsername",
                    "cweId":"CWE-89",
                    "fixSuggestion":"use PreparedStatement placeholders"
                  }
                }
                ```
                """;
        String responseBody = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                + "\"content\":" + JSON.writeValueAsString(triageFinal) + "}}]}";
        ChatTransport transport = (provider, credential, request, limits) ->
                new ProviderChatTransport.Response(200,
                        responseBody.getBytes(StandardCharsets.UTF_8), "triage-req", 1);

        try (AiJobOrchestrator orchestrator = new AiJobOrchestrator(store, transport, Clock.systemUTC())) {
            var job = store.createAiJob("project-triage", AgentRole.VULNERABILITY_TRIAGE,
                    "scan-triage", AiOutputLanguage.ZH_CN, true, "local-admin", Instant.now().toString());
            orchestrator.submit(job, "local-admin");
            var done = awaitTerminal(store, job.aiJobId());
            check("COMPLETED".equals(done.status()), "TRIAGE job completed");
            check(done.conclusionJson() != null && !done.conclusionJson().isBlank(),
                    "TRIAGE conclusionJson persisted");
            JsonNode conclusion = JSON.readTree(done.conclusionJson());
            check(conclusion.path("rootCause").isObject(),
                    "TRIAGE conclusionJson retains rootCause object");
            check("missing parameterized query".equals(
                            conclusion.path("rootCause").path("rootCauseStatement").asText()),
                    "TRIAGE conclusionJson retains rootCauseStatement");
            check("CWE-89".equals(conclusion.path("rootCause").path("cweId").asText()),
                    "TRIAGE conclusionJson retains cweId");
            check(conclusion.path("rootCause").path("attackPath").isArray()
                            && conclusion.path("rootCause").path("attackPath").size() >= 2,
                    "TRIAGE conclusionJson retains attackPath");
            check(conclusion.path("evidenceRefs").isArray()
                            && conclusion.path("evidenceRefs").size() > 0,
                    "TRIAGE conclusionJson retains non-empty evidenceRefs");
            check(conclusion.path("counterevidence").isArray()
                            && conclusion.path("counterevidence").size() > 0,
                    "TRIAGE conclusionJson retains counterevidence");
            check(!"INSUFFICIENT_EVIDENCE".equals(conclusion.path("classification").asText())
                            || conclusion.path("evidenceRefs").size() > 0,
                    "valid TRIAGE not fail-closed incorrectly");
            check("INFERENCE".equals(conclusion.path("classification").asText()),
                    "valid TRIAGE classification=INFERENCE");
            check(!conclusion.has("bypassPoCs")
                            || (conclusion.path("bypassPoCs").isArray()
                            && conclusion.path("bypassPoCs").isEmpty()),
                    "TRIAGE did not replace conclusion with AUTH bypassPoCs payload");
            check(conclusion.path("evidenceRefs").size() > 0
                            || !conclusion.path("rootCause").path("attackPath").isEmpty(),
                    "AUTH empty evidenceRefs array did not wipe TRIAGE refs");
            String expectedFindingId = "finding-triage-" + done.aiJobId();
            ApiDtos.FindingDto attached = store.finding(expectedFindingId);
            check(attached != null, "TRIAGE attaches finding for dashboard/REPORT");
            check(attached.rootCause() != null
                            && "CWE-89".equals(String.valueOf(attached.rootCause().get("cweId"))),
                    "attached finding retains structured cweId");
            check(store.requireScan("scan-triage").dto().findings().stream()
                            .anyMatch(item -> expectedFindingId.equals(item.findingId())),
                    "scan dto lists TRIAGE-attached finding");
        }
    }

    private static com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData awaitTerminal(
            ControlPlaneStore store, String jobId) throws InterruptedException {
        long deadline = System.nanoTime() + 30_000_000_000L;
        while (System.nanoTime() < deadline) {
            var job = store.requireAiJob(jobId);
            if ("COMPLETED".equals(job.status())
                    || "FAILED".equals(job.status())
                    || "CANCELLED".equals(job.status())
                    || "BLOCKED".equals(job.status())) {
                return job;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("AI job did not reach terminal state: " + jobId);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
    }
}

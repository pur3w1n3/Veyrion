package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-07 residual: ControlPlaneStore.attachTriageFinding keeps structured rootCause for dashboard.
 */
public final class TriageFindingAttachAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        attachStoresStructuredRootCause();
        System.out.println("TriageFindingAttachAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void attachStoresStructuredRootCause() throws Exception {
        Path root = Files.createTempDirectory("veyrion-triage-attach");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-attach", "Triage attach", now, "local-admin");
        Path artifact = root.resolve("Fixture.class");
        Files.writeString(artifact, "fixture");
        String digest = "e".repeat(64);
        store.registerArtifact(project, new ArtifactDescriptor("artifact-attach", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"),
                "local-admin");
        var entry = new ApiDtos.EntryDto(1, project.projectId(), digest, "scan-attach", "entry-1",
                "HTTP", "GET", "/api/user", "example.UserController", "example",
                List.of(), List.of(), "STATIC_INFERRED", 0.8, 0, List.of());
        var scan = new ApiDtos.ScanDto(1, project.projectId(), digest, "scan-attach",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of(), List.of(entry), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");

        String summary = """
                {
                  "evidenceRefs": ["entry:entry-1", "pathrun:pr-1"],
                  "rootCause": {
                    "attackPath": [
                      {"layer":"HTTP","label":"GET /api/user","evidenceRefs":["entry:entry-1"]},
                      {"layer":"sink","label":"SQL concat","evidenceRefs":["pathrun:pr-1"]}
                    ],
                    "rootCauseStatement":"missing parameterized query",
                    "affectedComponent":"UserRepository",
                    "cweId":"CWE-89",
                    "fixSuggestion":"use PreparedStatement"
                  }
                }
                """;
        TriageConclusion.ParseResult parsed = TriageConclusion.parseAndValidate(summary);
        check(!parsed.insufficientEvidence(), "triage parse sufficient");
        ApiDtos.FindingDto finding = new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, "scan-attach",
                "finding-triage-job-attach", "TRIAGE CWE-89", "medium",
                TriageConclusion.CLASSIFICATION_INFERENCE, "entry-1", "/api/user",
                "sink-triage", "SQL concat", "none", List.of("none"),
                parsed.evidenceRefs(), parsed.evidenceRefs().size(), 0.55d, ApiDtos.MOCK,
                TriageConclusion.toRootCauseMap(parsed));
        store.attachTriageFinding("scan-attach", finding);

        ApiDtos.FindingDto attached = store.finding("finding-triage-job-attach");
        check(attached != null, "finding indexed");
        check("CWE-89".equals(String.valueOf(attached.rootCause().get("cweId"))), "cweId preserved");
        check("use PreparedStatement".equals(String.valueOf(attached.rootCause().get("fixSuggestion"))),
                "fixSuggestion preserved");
        check(store.requireScan("scan-attach").dto().findings().stream()
                        .anyMatch(item -> "finding-triage-job-attach".equals(item.findingId())),
                "scan dto includes attached finding");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

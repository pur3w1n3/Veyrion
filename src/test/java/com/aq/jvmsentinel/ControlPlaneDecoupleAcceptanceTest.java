package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.ir.ProgramNode;

import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P1-08: Control Plane query/write ports accept Test Analyzer-style unknown-language nodes
 * and expose findings / PathRuns / providers / createScan projection via application.port
 * without JVM-only required fields.
 * Declared scope = incremental port decoupling, not a ControlPlaneServer big-bang rewrite.
 */
public final class ControlPlaneDecoupleAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = Files.createTempDirectory("cp-decouple");
        Path database = root.resolve("state/control-plane.db");
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, "decouple-token", database).start()) {
            String scanId = seedScan(server);
            verifyUnknownLanguageNodeViaPorts(server, scanId);
            verifyNeutralHttpProjection(server, scanId);
            verifyHypothesesRoute(server, scanId);
            verifyFindingAndPathRunQueryPorts(server, scanId);
            verifyProviderQueryPort(server);
            verifyCreateScanProjectionPort(server, scanId);
            System.out.println("ControlPlaneDecoupleAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            deleteTree(root);
        }
    }

    private static String seedScan(ControlPlaneServer server) throws Exception {
        String now = Instant.now().toString();
        ControlPlaneStore store = server.store();
        ControlPlaneStore.ProjectRecord project = store.createProject(
                "proj-decouple", "Decouple", now, "local-admin");
        String digest = "d".repeat(64);
        String scanId = "scan-decouple-1";
        Path jar = Files.createTempFile("decouple-artifact", ".jar").toAbsolutePath();
        Files.write(jar, new byte[]{0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        ArtifactDescriptor descriptor = new ArtifactDescriptor(
                "art-decouple-1", ArtifactType.JAR, jar, Files.size(jar),
                digest, true, Instant.now(), "decouple.jar");
        store.registerArtifact(project, descriptor, "local-admin");
        ApiDtos.FindingDto finding = new ApiDtos.FindingDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "finding-decouple-1", "Unknown-lang config hypothesis", "MEDIUM",
                ApiDtos.STATIC_INFERRED, "entry-decouple-1", "GET /api/x",
                "sink-config-1", "dangerous-config", "none", List.of(),
                List.of("ev-seed-1"), 1, 0.4, ApiDtos.MOCK, Map.of(),
                "hyp-unknown-lang-1", "CONFIG");
        ApiDtos.ScanDto scan = new ApiDtos.ScanDto(
                ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of("ev-seed-1"), List.of(), List.of(), List.of(), List.of(finding), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(
                scan, Map.of(), List.of(finding), List.of()), "local-admin");
        store.saveHypotheses(scanId, List.of(
                new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION, "hyp-unknown-lang-1", scanId,
                        "CONFIG", HypothesisFamily.CONFIG,
                        HypothesisLifecycle.CANDIDATE, "test-analyzer/0.1",
                        List.of("ev-seed-1"), List.of(), List.of(), "", "")), "local-admin");
        ApiDtos.PathRunDto pathRun = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-decouple-1", scanId, "entry:entry-decouple-1",
                "UNAUTH", "attempt-corr-1", "plan:decouple-1",
                "GET", "application/json",
                "GET /api/x correlationId=corr-decouple-1",
                "HTTP_OBSERVED", 200, true, true,
                List.of(new ApiDtos.SqlEventDto(
                        "SELECT 1", "benign", "READ", true, false, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-pr-decouple-1"), "MOCK", "");
        store.replacePathRunsForTask(project.projectId(), digest, scanId, "task-decouple-seed",
                List.of(pathRun), now);
        check(server.scanQueryPort().exists(scanId), "scanQueryPort sees seeded scan");
        return scanId;
    }

    @SuppressWarnings("unchecked")
    private static void verifyFindingAndPathRunQueryPorts(ControlPlaneServer server, String scanId)
            throws Exception {
        check(server.findingQueryPort().scanExists(scanId), "findingQueryPort sees scan");
        List<Map<String, Object>> findings = server.findingQueryPort().findingsForScan(scanId)
                .orElseThrow();
        check(findings.size() == 1, "findingQueryPort returns seeded finding");
        check("finding-decouple-1".equals(String.valueOf(findings.get(0).get("findingId"))),
                "findingId preserved via port");
        check("MOCK".equals(String.valueOf(findings.get(0).get("dependencyMode"))),
                "MOCK provenance visible on finding port (not elevated)");
        Optional<Map<String, Object>> one = server.findingQueryPort().findingView("finding-decouple-1");
        check(one.isPresent(), "findingView by id");
        check("CONFIG".equals(String.valueOf(one.get().get("securityProperty"))),
                "securityProperty readable without JVM sink fields");

        check(server.pathRunQueryPort().scanExists(scanId), "pathRunQueryPort sees scan");
        List<Map<String, Object>> pathRuns = server.pathRunQueryPort().pathRunsForScan(scanId)
                .orElseThrow();
        check(pathRuns.size() == 1, "pathRunQueryPort returns seeded PathRun");
        check("MOCK".equals(String.valueOf(pathRuns.get(0).get("identityProvenance"))),
                "PathRun MOCK provenance annotated via port");
        check("corr-decouple-1".equals(String.valueOf(pathRuns.get(0).get("correlationId"))),
                "PathRun correlation retained via port");

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> findingsHttp = client.send(
                HttpRequest.newBuilder(uri(server, "/scans/" + scanId + "/findings"))
                        .header("Authorization", "Bearer decouple-token")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        check(findingsHttp.statusCode() == 200, "findings HTTP 200 via FindingQueryPort path");
        Map<String, Object> body = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(findingsHttp.body(), Map.class);
        check(body.get("findings") instanceof List<?> list && list.size() == 1,
                "findings HTTP projects port data");

        HttpResponse<String> findingHttp = client.send(
                HttpRequest.newBuilder(uri(server, "/findings/finding-decouple-1"))
                        .header("Authorization", "Bearer decouple-token")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        check(findingHttp.statusCode() == 200, "single finding HTTP via FindingQueryPort");
    }

    private static void verifyUnknownLanguageNodeViaPorts(ControlPlaneServer server, String scanId) {
        ProgramNode unknown = new ProgramNode(
                "program:module:pythonish:app.handlers",
                "MODULE",
                "pythonish",
                "app.handlers",
                "app/handlers.py:42",
                List.of("ev-analyzer-py-1"),
                "FACT",
                Map.of(
                        "typescript", Map.of("note", "wrong-namespace-ignored-by-core"),
                        "pythonish", Map.of("astKind", "FunctionDef", "decorators", List.of("route"))));
        server.analyzerIrIngestPort().ingestProgramNodes(scanId, List.of(unknown));

        List<ProgramNode> stored = server.analyzerIrIngestPort().supplementalProgramNodes(scanId);
        check(stored.size() == 1, "supplemental node saved");
        check("pythonish".equals(stored.get(0).language()), "unknown language preserved");
        check(stored.get(0).extensions().containsKey("pythonish"), "namespaced extension preserved");

        Optional<EvidenceGraph> graph = server.evidenceGraphQueryPort().evidenceGraph(scanId);
        check(graph.isPresent(), "evidenceGraphQueryPort returns graph");
        Optional<IrNode> found = graph.get().findById(unknown.id());
        check(found.isPresent(), "unknown language node queryable in graph");
        check(found.get() instanceof ProgramNode program
                        && "pythonish".equals(program.language())
                        && "app.handlers".equals(program.symbol())
                        && "app/handlers.py:42".equals(program.location()),
                "general ProgramNode fields readable without JVM fields");
        check(server.hypothesisQueryPort().hypotheses(scanId).size() == 1,
                "hypothesisQueryPort returns family-scoped hypothesis");
        check(server.coverageQueryPort().coverage(scanId).isPresent(),
                "coverageQueryPort projects for scan");
    }

    @SuppressWarnings("unchecked")
    private static void verifyNeutralHttpProjection(ControlPlaneServer server, String scanId)
            throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(uri(server, "/scans/" + scanId + "/evidence-graph"))
                        .header("Authorization", "Bearer decouple-token")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200, "evidence-graph HTTP 200");
        Object parsed = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(response.body(), Object.class);
        check(parsed instanceof Map<?, ?>, "evidence-graph body is object");
        Map<String, Object> body = (Map<String, Object>) parsed;
        check(body.get("nodes") instanceof List<?>, "evidence-graph nodes list");
        boolean seen = false;
        for (Object node : (List<?>) body.get("nodes")) {
            if (!(node instanceof Map<?, ?> map)) continue;
            if ("program:module:pythonish:app.handlers".equals(String.valueOf(map.get("id")))) {
                seen = true;
                check("PROGRAM".equals(String.valueOf(map.get("kind"))), "wire kind PROGRAM");
                check("pythonish".equals(String.valueOf(map.get("language"))), "wire language");
                check(map.get("extensions") instanceof Map<?, ?>, "wire extensions present");
            }
        }
        check(seen, "unknown language node present on neutral evidence-graph API");
    }

    @SuppressWarnings("unchecked")
    private static void verifyHypothesesRoute(ControlPlaneServer server, String scanId) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(uri(server, "/scans/" + scanId + "/hypotheses"))
                        .header("Authorization", "Bearer decouple-token")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200, "hypotheses HTTP 200");
        Map<String, Object> body = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(response.body(), Map.class);
        check(body.get("hypotheses") instanceof List<?>, "hypotheses list");
        check(Integer.valueOf(1).equals(body.get("count"))
                        || ((List<?>) body.get("hypotheses")).size() == 1,
                "hypotheses count");
    }

    @SuppressWarnings("unchecked")
    private static void verifyProviderQueryPort(ControlPlaneServer server) throws Exception {
        check(server.providerQueryPort() != null, "providerQueryPort wired");
        List<Map<String, Object>> viaPort = server.providerQueryPort().listProviders();
        check(viaPort != null, "providerQueryPort returns list");

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(uri(server, "/providers"))
                        .header("Authorization", "Bearer decouple-token")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200, "providers HTTP 200 via ProviderQueryPort");
        Map<String, Object> body = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(response.body(), Map.class);
        check(body.get("providers") instanceof List<?>, "providers envelope list");
        int httpCount = ((List<?>) body.get("providers")).size();
        check(httpCount == viaPort.size(), "providers HTTP count matches ProviderQueryPort");
        for (Map<String, Object> item : viaPort) {
            check(!item.containsKey("apiKey"), "provider port never exposes apiKey");
            check(item.containsKey("providerId") || item.containsKey("hasCredential"),
                    "provider projection has identity or credential flag");
        }
    }

    @SuppressWarnings("unchecked")
    private static void verifyCreateScanProjectionPort(ControlPlaneServer server, String scanId)
            throws Exception {
        Map<String, Object> view = server.scanQueryPort().scanView(scanId)
                .orElseThrow(() -> new AssertionError("scanView missing for seeded scan"));
        check(view.containsKey("hypotheses"), "createScan projection includes hypotheses");
        check(view.containsKey("coverage"), "createScan projection includes coverage");
        check(scanId.equals(String.valueOf(view.get("scanId"))), "scanView scanId matches");
        Object hypotheses = view.get("hypotheses");
        check(hypotheses instanceof List<?> list && !list.isEmpty(),
                "scanView hypotheses non-empty for seeded scan");
    }

    private static URI uri(ControlPlaneServer server, String path) {
        // baseUri is /api/v1 without trailing slash — must concatenate, not URI.resolve.
        return URI.create(server.baseUri() + path);
    }

    private static void deleteTree(Path root) throws Exception {
        if (root == null || !Files.exists(root)) return;
        try (var stream = Files.walk(root)) {
            stream.sorted((a, b) -> b.compareTo(a)).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                    // best-effort cleanup
                }
            });
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

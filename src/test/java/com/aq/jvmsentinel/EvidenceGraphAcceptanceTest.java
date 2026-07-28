package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.ir.EvidenceGraphProjector;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EdgeKind;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P1-02: Evidence Graph projection, finding evidence-ref join, AUTH EntryDto gap, API bound.
 */
public final class EvidenceGraphAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        verifySyntheticProjection();
        verifyTruncationBudget();
        Path root = Files.createTempDirectory("evidence-graph");
        try {
            Path jar = buildFixture(root);
            verifyLiveApi(root, jar);
            System.out.println("EvidenceGraphAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            deleteTree(root);
        }
    }

    private static void verifySyntheticProjection() {
        List<ApiDtos.EntryDto> entries = List.of(
                new ApiDtos.EntryDto(
                        ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-eg",
                        "entry-http-1", "HTTP", "GET", "/search", "com/example/A", "A",
                        List.of("q"), List.of("ROLE=USER"), ApiDtos.STATIC_INFERRED, 0.8, 0,
                        List.of("ev-entry-1")),
                new ApiDtos.EntryDto(
                        ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-eg",
                        "entry-auth-1", "AUTH", "FILTER", "/security", "com/example/AuthFilter", "AuthFilter",
                        List.of(), List.of("AUTH"), ApiDtos.STATIC_INFERRED, 0.7, 0,
                        List.of("ev-auth-1")));
        List<ApiDtos.SinkDto> sinks = List.of(
                new ApiDtos.SinkDto(
                        ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-eg",
                        "sink-sql-1", "SQL", "Statement.executeQuery", "/search",
                        ApiDtos.STATIC_INFERRED, 0.9, List.of("ev-sink-1", "ev-entry-1")));
        List<ApiDtos.FindingDto> findings = List.of(
                new ApiDtos.FindingDto(
                        ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-eg",
                        "finding-1", "SQL signal", "high", ApiDtos.STATIC_INFERRED,
                        "entry-http-1", "GET /search", "sink-sql-1", "Statement.executeQuery",
                        "none", List.of(), List.of("ev-entry-1", "ev-sink-1"), 2, 0.9, ApiDtos.MOCK));
        List<SecurityHypothesis> hypotheses = List.of(
                new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION, "hyp-df-1", "scan-eg",
                        "SQL", HypothesisFamily.DATAFLOW, HypothesisLifecycle.CANDIDATE,
                        "static-sink-compat/0.1", List.of("ev-sink-1"), List.of(), List.of(),
                        "param:q", "jdbc:execute"));
        List<ApiDtos.PathRunDto> pathRuns = List.of(
                new ApiDtos.PathRunDto(
                        ApiDtos.SCHEMA_VERSION, "pr-1", "scan-eg", "entry-http-1", "ANON", "att-1",
                        "plan-1", "GET", "application/json", "q=1", "STOP", 0,
                        true, true, List.of(), "BUDGET", ApiDtos.UNREACHED, List.of("ev-run-1"),
                        ApiDtos.MOCK, ""));

        StaticFactSnapshot facts = syntheticFacts();
        EvidenceGraph graph = EvidenceGraphProjector.fromScan(
                "scan-eg", Optional.of(facts), entries, sinks, List.of(),
                hypotheses, findings, pathRuns);

        check(graph.schemaVersion() == EvidenceGraph.SCHEMA_VERSION, "schemaVersion");
        check(graph.findById(StableNodeIds.entry("entry-http-1")).isPresent(), "HTTP entry node present");
        check(graph.findById(StableNodeIds.entry("entry-auth-1")).isEmpty(),
                "AUTH entry not projected as EntryNode");
        check(graph.findById(StableNodeIds.guard("auth-entry:entry-auth-1")).isPresent(),
                "AUTH entry projected as GuardNode");
        check(graph.findById(StableNodeIds.effect("sink-sql-1")).isPresent(), "effect node present");
        check(graph.findById(StableNodeIds.trust("entry-http-1", "q")).isPresent(), "trust boundary present");
        check(graph.findById(StableNodeIds.runtime("pr-1")).isPresent(), "runtime observation present");

        long entryNodes = graph.nodes().stream().filter(node -> node instanceof EntryNode).count();
        check(entryNodes == 1, "EntryNode count excludes AUTH");
        check(graph.compatibilityGap().entryDtoCount() == 2, "entryDtoCount=2");
        check(graph.compatibilityGap().entryNodeCount() == 1, "entryNodeCount=1");
        check(graph.compatibilityGap().filteredEntryIds().contains("entry-auth-1"),
                "filtered AUTH id recorded");
        check(!graph.compatibilityGap().notes().isEmpty(), "gap notes present");

        for (String ref : findings.get(0).evidenceRefs()) {
            List<IrNode> carriers = graph.nodesForEvidenceRef(ref);
            check(!carriers.isEmpty(), "finding evidence ref resolvable: " + ref);
        }
        check(graph.findById(StableNodeIds.entry("entry-http-1")).orElseThrow()
                        .evidenceRefs().contains("ev-entry-1"),
                "entry carries finding evidence");
        // Bidirectional: node → findingIds via shared evidence refs.
        List<Map<String, Object>> findingMaps = List.of(Map.of(
                "findingId", "finding-1",
                "evidenceRefs", findings.get(0).evidenceRefs()));
        List<String> reverse = graph.findingIdsForNode(
                StableNodeIds.entry("entry-http-1"), findingMaps);
        check(reverse.contains("finding-1"), "node→finding reverse join via evidence refs");
        List<String> effectReverse = graph.findingIdsForNode(
                StableNodeIds.effect("sink-sql-1"), findingMaps);
        check(effectReverse.contains("finding-1"), "effect node→finding reverse join");

        check(graph.edges().stream().anyMatch(edge -> edge.kind() == EdgeKind.DATA),
                "DATA edge projected");
        check(graph.edges().stream().anyMatch(edge -> edge.kind() == EdgeKind.CALL),
                "CALL edge from static facts");
        check(graph.edges().stream().anyMatch(edge -> edge.kind() == EdgeKind.OBSERVED),
                "OBSERVED edge from PathRun");

        Map<String, Object> wire = graph.toMap();
        check(Boolean.FALSE.equals(wire.get("truncated")), "synthetic not truncated");
        check(wire.get("nodes") instanceof List<?>, "wire nodes array");
        check(wire.get("edges") instanceof List<?>, "wire edges array");
        check(wire.get("compatibilityGap") instanceof Map<?, ?>, "wire compatibilityGap");
        EvidenceGraph restored = EvidenceGraph.fromMap(wire);
        check(restored.nodes().size() == graph.nodes().size(), "wire round-trip node count");
        check(restored.findById(StableNodeIds.entry("entry-http-1")).isPresent(),
                "wire round-trip restores entry node");
        check(restored.nodesForEvidenceRef("ev-sink-1").stream()
                        .anyMatch(n -> n.id().equals(StableNodeIds.effect("sink-sql-1"))),
                "wire round-trip preserves finding↔node join");
    }

    private static void verifyTruncationBudget() {
        List<ApiDtos.EntryDto> entries = List.of(
                new ApiDtos.EntryDto(
                        ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-trunc",
                        "e1", "HTTP", "GET", "/a", "com/A", "A",
                        List.of("p"), List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of("ev-a")),
                new ApiDtos.EntryDto(
                        ApiDtos.SCHEMA_VERSION, "p1", "digest", "scan-trunc",
                        "e2", "HTTP", "GET", "/b", "com/B", "B",
                        List.of("p"), List.of(), ApiDtos.STATIC_INFERRED, 0.5, 0, List.of("ev-b")));
        EvidenceGraph tiny = EvidenceGraphProjector.fromScan(
                "scan-trunc", Optional.empty(), entries, List.of(), List.of(),
                List.of(), List.of(), List.of(), 2, 2);
        check(tiny.truncated(), "low budget sets truncated");
        check("NODE_OR_EDGE_BUDGET".equals(tiny.stopReason()), "stopReason budget");
        check(tiny.nodes().size() <= 2, "node cap honored");
        check(tiny.edges().size() <= 2, "edge cap honored");
        check(Boolean.TRUE.equals(tiny.toMap().get("truncated")), "wire truncated flag");
    }

    private static StaticFactSnapshot syntheticFacts() {
        BytecodeFactIndex.InstructionEvidence evidence = new BytecodeFactIndex.InstructionEvidence(
                "com/example/A", "m", "()V", 0, 0);
        List<BytecodeFactIndex.ResolvedCallEdge> graph = List.of(
                new BytecodeFactIndex.ResolvedCallEdge(
                        "com/example/A", "m", "()V", "com/example/B", "com/example/B", "n", "()V",
                        BytecodeFactIndex.EdgeKind.DIRECT, "", evidence));
        return new StaticFactSnapshot(
                StaticFactSnapshot.COMPLETE,
                List.of(),
                BytecodeFactIndex.AnalysisCoverage.empty(),
                List.of(),
                List.of(),
                List.of(new BytecodeFactIndex.MethodFact("com/example/A", "m", "()V", 1, "ev")),
                List.of(),
                List.of(),
                List.of(),
                graph,
                List.of());
    }

    private static void verifyLiveApi(Path root, Path jar) throws Exception {
        String token = "evidence-graph-token";
        Path database = root.resolve("state/control-plane.db");
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, token, database).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"evidence graph slice\"}", token));
            String projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            String scanId = text(scan, "scanId");

            Map<String, Object> graph = ok(send(client,
                    uri(server, "/scans/" + scanId + "/evidence-graph"), "GET", "", token));
            check(scanId.equals(String.valueOf(graph.get("scanId"))), "evidence-graph scanId");
            check(graph.get("schemaVersion") instanceof Number, "evidence-graph schemaVersion");
            check(graph.get("nodes") instanceof List<?>, "evidence-graph nodes");
            check(graph.get("edges") instanceof List<?>, "evidence-graph edges");
            check(graph.get("truncated") instanceof Boolean, "evidence-graph truncated flag");
            check(graph.get("maxNodes") instanceof Number, "maxNodes present");
            check(graph.get("maxEdges") instanceof Number, "maxEdges present");
            check(graph.get("compatibilityGap") instanceof Map<?, ?>, "compatibilityGap present");

            @SuppressWarnings("unchecked")
            Map<String, Object> gap = (Map<String, Object>) graph.get("compatibilityGap");
            int entryDtoCount = gap.get("entryDtoCount") instanceof Number n ? n.intValue() : -1;
            int entryNodeCount = gap.get("entryNodeCount") instanceof Number n ? n.intValue() : -1;
            check(entryDtoCount >= 0 && entryNodeCount >= 0, "entry counts present");
            check(entryNodeCount <= entryDtoCount, "EntryNode count <= EntryDto count");

            Map<String, Object> findingsBody = ok(send(client,
                    uri(server, "/scans/" + scanId + "/findings"), "GET", "", token));
            Object findingsObj = findingsBody.get("findings");
            List<?> findings;
            if (findingsObj instanceof List<?> list && !list.isEmpty()) {
                findings = list;
            } else {
                Object scanFindings = scan.get("findings");
                check(scanFindings instanceof List<?> && !((List<?>) scanFindings).isEmpty(),
                        "scan has findings for evidence join");
                findings = (List<?>) scanFindings;
            }
            @SuppressWarnings("unchecked")
            List<?> nodeList = (List<?>) graph.get("nodes");
            boolean joined = false;
            for (Object findingObj : findings) {
                if (!(findingObj instanceof Map<?, ?> finding)) continue;
                Object refsObj = finding.get("evidenceRefs");
                if (!(refsObj instanceof List<?> refs) || refs.isEmpty()) continue;
                for (Object refObj : refs) {
                    String ref = String.valueOf(refObj);
                    for (Object nodeObj : nodeList) {
                        if (!(nodeObj instanceof Map<?, ?> node)) continue;
                        Object nodeRefs = node.get("evidenceRefs");
                        if (nodeRefs instanceof List<?> list && list.stream()
                                .map(String::valueOf).anyMatch(ref::equals)) {
                            joined = true;
                            break;
                        }
                    }
                    if (joined) break;
                }
                if (joined) break;
            }
            check(joined, "at least one finding evidence ref joins a graph node");

            // P1-02: authoritative graph persisted in StaticFactSnapshot (schema v4).
            Optional<StaticFactSnapshot> facts = server.store().staticFacts(scanId);
            check(facts.isPresent(), "static facts persisted");
            check(facts.get().hasPersistedEvidenceGraph(), "evidence graph persisted on snapshot");
            EvidenceGraph persisted = facts.get().evidenceGraph().orElseThrow();
            check(persisted.scanId().equals(scanId), "persisted graph scanId");
            check(!persisted.nodes().isEmpty(), "persisted graph has nodes");
            int apiNodes = graph.get("nodeCount") instanceof Number n
                    ? n.intValue() : -1;
            check(apiNodes >= persisted.nodes().size(),
                    "API graph includes persisted authoritative nodes");

            // Bidirectional live: finding → node and node → findingId.
            List<Map<String, Object>> findingWire = new ArrayList<>();
            for (Object findingObj : findings) {
                if (findingObj instanceof Map<?, ?> finding) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> cast = (Map<String, Object>) finding;
                    findingWire.add(cast);
                }
            }
            boolean reverseJoined = false;
            for (IrNode node : persisted.nodes()) {
                List<String> findingIds = persisted.findingIdsForNode(node.id(), findingWire);
                if (!findingIds.isEmpty()) {
                    for (String findingId : findingIds) {
                        for (Map<String, Object> finding : findingWire) {
                            if (!findingId.equals(String.valueOf(finding.get("findingId")))) continue;
                            Object refsObj = finding.get("evidenceRefs");
                            if (!(refsObj instanceof List<?> refs)) continue;
                            boolean overlap = refs.stream().map(String::valueOf)
                                    .anyMatch(node.evidenceRefs()::contains);
                            check(overlap, "reverse join finding shares evidence with node");
                            reverseJoined = true;
                        }
                    }
                }
                if (reverseJoined) break;
            }
            check(reverseJoined, "at least one node→finding reverse join on live scan");
        }
    }

    private static Path buildFixture(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeFixtures(sources);
        compile(sources, classes);
        Path jar = root.resolve("evidence-graph-fixture.jar");
        archive(classes, jar);
        return jar;
    }

    private static void writeFixtures(Path sources) throws Exception {
        Path pkg = Files.createDirectories(sources.resolve("com/example/eg"));
        Files.writeString(pkg.resolve("UserController.java"), """
                package com.example.eg;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RequestParam;
                import org.springframework.web.bind.annotation.RestController;
                @RestController
                public class UserController {
                    private final UserRepository repository = new UserRepository();
                    @GetMapping("/search")
                    public String search(@RequestParam("q") String q) {
                        return repository.find(q);
                    }
                }
                """);
        Files.writeString(pkg.resolve("UserRepository.java"), """
                package com.example.eg;
                import java.sql.Connection;
                import java.sql.DriverManager;
                import java.sql.Statement;
                public class UserRepository {
                    public String find(String q) {
                        try {
                            Connection c = DriverManager.getConnection("jdbc:h2:mem:test");
                            Statement s = c.createStatement();
                            s.execute("SELECT * FROM users WHERE name='" + q + "'");
                            return "ok";
                        } catch (Exception e) {
                            return "err";
                        }
                    }
                }
                """);
        Path spring = Files.createDirectories(sources.resolve("org/springframework/web/bind/annotation"));
        Files.writeString(spring.resolve("RestController.java"), """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        Files.writeString(spring.resolve("GetMapping.java"), """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String value() default ""; }
                """);
        Files.writeString(spring.resolve("RequestParam.java"), """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.PARAMETER)
                public @interface RequestParam { String value() default ""; }
                """);
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "JDK compiler available");
        List<Path> sourceFiles;
        try (Stream<Path> stream = Files.walk(sources)) {
            sourceFiles = stream.filter(path -> path.toString().endsWith(".java")).toList();
        }
        try (StandardJavaFileManager manager =
                     compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean success = compiler.getTask(null, manager, null,
                    List.of("--release", "17", "-parameters", "-d", classes.toString()), null,
                    manager.getJavaFileObjectsFromPaths(sourceFiles)).call();
            check(success, "fixture compilation");
        }
    }

    private static void archive(Path classes, Path jar) throws Exception {
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                output.putNextEntry(new ZipEntry(
                        "BOOT-INF/classes/" + classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, output);
                output.closeEntry();
            }
        }
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method,
                                             String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("X-Sentinel-Authorization", token);
        HttpRequest request = "POST".equals(method)
                ? builder.POST(HttpRequest.BodyPublishers.ofString(body)).build()
                : builder.GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ok(HttpResponse<String> response) throws Exception {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "HTTP " + response.statusCode() + " body=" + response.body());
        return com.aq.jvmsentinel.control.JsonCodec.parseObject(response.body());
    }

    private static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        check(value != null && !String.valueOf(value).isBlank(), key + " present");
        return String.valueOf(value);
    }

    private static String escape(String path) {
        return path.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> stream = Files.walk(root)) {
            List<Path> paths = stream.sorted((a, b) -> b.getNameCount() - a.getNameCount()).toList();
            for (Path path : paths) {
                Files.deleteIfExists(path);
            }
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

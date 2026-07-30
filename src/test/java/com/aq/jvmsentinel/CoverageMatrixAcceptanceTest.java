package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.coverage.CoverageBaselineMetrics;
import com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P0-13：Coverage Matrix 投影诚实、checksum 稳定与 recall-gate 骨架。
 */
public final class CoverageMatrixAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        JsonNode baseline = loadBaseline("baselines/p0-13-source-sink-auth-gap.json");
        verifySyntheticProjection(baseline);
        verifyMutationAndHoldoutBaselines();
        Path root = Files.createTempDirectory("coverage-matrix");
        try {
            Path jar = buildFixture(root);
            verifyLiveApi(root, jar, baseline);
            System.out.println("CoverageMatrixAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            deleteTree(root);
        }
    }

    private static JsonNode loadBaseline(String resource) throws Exception {
        try (InputStream in = CoverageMatrixAcceptanceTest.class.getClassLoader()
                .getResourceAsStream(resource)) {
            check(in != null, "baseline fixture present: " + resource);
            return JSON.readTree(in);
        }
    }

    /**
     * P0-13 mutation/holdout：从 CoverageMatrix 对 baseline groundTruth 计算真实 TP/FP/FN。
     * Suppress 必需 detector 须使 recall gate 失败（FN &gt; 0）。
     */
    private static void verifyMutationAndHoldoutBaselines() throws Exception {
        JsonNode mutation = loadBaseline("baselines/p0-13-mutation-sql-variant.json");
        JsonNode holdout = loadBaseline("baselines/p0-13-holdout-framework.json");
        check("mutation".equals(mutation.path("kind").asText()), "mutation baseline kind");
        check("holdout".equals(holdout.path("kind").asText()), "holdout baseline kind");
        check(!mutation.path("metrics").path("stub").asBoolean(true), "mutation.metrics.stub=false");
        check(!holdout.path("metrics").path("stub").asBoolean(true), "holdout.metrics.stub=false");
        check(mutation.path("metrics").path("computedAtGate").asBoolean(), "mutation computedAtGate");
        check(holdout.path("metrics").path("computedAtGate").asBoolean(), "holdout computedAtGate");

        CoverageMatrix mutationMatrix = projectWithFamilies(
                List.of(hypothesis("hyp-df-m", "SQL", HypothesisFamily.DATAFLOW)));
        assertComputedGate(mutation, mutationMatrix, "mutation", true);
        CoverageMatrix mutationSuppressed = CoverageMatrixProjector.project(
                "scan-mutation", Optional.of(syntheticFacts()), List.of(), List.of(), List.of(),
                List.of(hypothesis("hyp-df-m", "SQL", HypothesisFamily.DATAFLOW)), List.of(),
                CoverageMatrixProjector.SuppressMode.SUPPRESS_DATAFLOW);
        assertComputedGate(mutation, mutationSuppressed, "mutation-suppressed", false);

        CoverageMatrix holdoutMatrix = projectWithFamilies(
                List.of(hypothesis("hyp-gc-h", "AUTH_GAP", HypothesisFamily.GUARD_COVERAGE)));
        assertComputedGate(holdout, holdoutMatrix, "holdout", true);
        CoverageMatrix holdoutSuppressed = CoverageMatrixProjector.project(
                "scan-holdout", Optional.of(syntheticFacts()), List.of(), List.of(), List.of(),
                List.of(hypothesis("hyp-gc-h", "AUTH_GAP", HypothesisFamily.GUARD_COVERAGE)), List.of(),
                CoverageMatrixProjector.SuppressMode.SUPPRESS_GUARD_COVERAGE);
        assertComputedGate(holdout, holdoutSuppressed, "holdout-suppressed", false);
    }

    private static CoverageMatrix projectWithFamilies(List<SecurityHypothesis> hypotheses) {
        return CoverageMatrixProjector.project(
                "scan-baseline", Optional.of(syntheticFacts()), List.of(), List.of(), List.of(),
                hypotheses, List.of());
    }

    private static SecurityHypothesis hypothesis(String id, String property, HypothesisFamily family) {
        return new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION, id, "scan-baseline",
                property, family, HypothesisLifecycle.CANDIDATE,
                "static-sink-compat/0.1", List.of("ev-1"), List.of(), List.of(),
                "param:q", "jdbc:execute");
    }

    private static void assertComputedGate(
            JsonNode baseline, CoverageMatrix matrix, String label, boolean expectPass) {
        CoverageBaselineMetrics.GroundTruth truth = groundTruthFrom(baseline);
        CoverageBaselineMetrics.GateResult gate =
                CoverageBaselineMetrics.evaluateGate(matrix, truth);
        CoverageBaselineMetrics.Metrics metrics = gate.metrics();
        check(!metrics.stub(), label + " metrics.stub=false (computed)");
        check(metrics.truePositives() >= 0 && metrics.falsePositives() >= 0
                        && metrics.falseNegatives() >= 0 && metrics.trueNegatives() >= 0,
                label + " TP/FP/FN/TN non-negative");
        check(Double.isFinite(metrics.recall()) && metrics.recall() >= 0.0 && metrics.recall() <= 1.0,
                label + " recall in [0,1] (" + metrics.recall() + ")");
        check(Double.isFinite(metrics.precision()) && metrics.precision() >= 0.0
                        && metrics.precision() <= 1.0,
                label + " precision in [0,1] (" + metrics.precision() + ")");
        if (expectPass) {
            check(gate.passed(), label + " gate passes with detectors present");
            check(metrics.falseNegatives() == 0, label + " FN=0 when detectors fire");
            check(metrics.truePositives() >= 1, label + " TP>=1 from real projection");
        } else {
            check(!gate.passed(), label + " gate fails when detector suppressed");
            check(metrics.falseNegatives() >= 1, label + " FN>=1 after suppress");
            check(metrics.recall() < 1.0, label + " recall drops below 1.0 after suppress");
        }
    }

    private static CoverageBaselineMetrics.GroundTruth groundTruthFrom(JsonNode baseline) {
        Set<String> positives = new java.util.LinkedHashSet<>();
        Set<String> negatives = new java.util.LinkedHashSet<>();
        JsonNode gt = baseline.path("groundTruth");
        if (gt.path("positiveFamilies").isArray()) {
            for (JsonNode node : gt.path("positiveFamilies")) {
                positives.add(node.asText());
            }
        } else {
            for (JsonNode node : baseline.path("expectedCoveredDetectorFamilies")) {
                positives.add(node.asText());
            }
        }
        if (gt.path("negativeFamilies").isArray()) {
            for (JsonNode node : gt.path("negativeFamilies")) {
                negatives.add(node.asText());
            }
        }
        return CoverageBaselineMetrics.GroundTruth.of(positives, negatives);
    }

    private static void verifySyntheticProjection(JsonNode baseline) {
        StaticFactSnapshot facts = syntheticFacts();
        List<SecurityHypothesis> hypotheses = List.of(
                new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION, "hyp-df-1", "scan-synth",
                        "SQL", HypothesisFamily.DATAFLOW, HypothesisLifecycle.CANDIDATE,
                        "static-sink-compat/0.1", List.of("ev-1"), List.of(), List.of(),
                        "param:q", "jdbc:execute"),
                new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION, "hyp-gc-1", "scan-synth",
                        "AUTH_GAP", HypothesisFamily.GUARD_COVERAGE, HypothesisLifecycle.CANDIDATE,
                        "static-sink-compat/0.1", List.of("ev-2"), List.of(), List.of(),
                        "/search", "missing-auth-guard"));
        List<ApiDtos.PathRunDto> pathRuns = List.of(
                new ApiDtos.PathRunDto(
                        ApiDtos.SCHEMA_VERSION, "pr-1", "scan-synth", "entry-1", "ANON", "att-1",
                        "plan-1", "GET", "application/json", "q=1", "STOP", 0,
                        false, false, List.of(), "BUDGET", ApiDtos.UNREACHED, List.of(),
                        ApiDtos.MOCK, ""));

        CoverageMatrix first = CoverageMatrixProjector.project(
                "scan-synth", Optional.of(facts), List.of(), List.of(), List.of(),
                hypotheses, pathRuns);
        CoverageMatrix second = CoverageMatrixProjector.project(
                "scan-synth", Optional.of(facts), List.of(), List.of(), List.of(),
                hypotheses, pathRuns);

        check(first.gaps().unresolved() > 0, "unresolved counted in gaps");
        check(first.gaps().truncated() > 0, "truncated counted in gaps");
        check(first.gaps().unreached() > 0, "unreached counted in gaps");
        check(first.gaps().unknown() > 0, "unknown counted in gaps");
        check(!Boolean.TRUE.equals(first.gaps().toMap().get("countedAsCovered")),
                "gaps never counted as covered");
        check(first.callResolution().unresolved() > 0, "callResolution UNRESOLVED present");
        check(Boolean.TRUE.equals(first.callResolution().toMap().get("unresolvedIsGap")),
                "UNRESOLVED flagged as gap");
        check(first.honestyFlags().neverTreatSuccessAsSafe(), "neverTreatSuccessAsSafe");
        check("analysis_finished_not_safe".equals(first.honestyFlags().toMap().get("scanSuccessMeans")),
                "SUCCESS not mapped to safe/secure");
        check(first.checksum().equals(second.checksum()), "projection checksum stable across runs");
        check(first.toMap().equals(second.toMap()), "projection map stable across runs");

        Set<String> expected = Set.of("DATAFLOW", "GUARD_COVERAGE");
        CoverageMatrixProjector.RecallGateResult gate =
                CoverageMatrixProjector.evaluateRecallGate(first, expected);
        check(gate.passed(), "baseline recall gate passes with detectors present");

        CoverageMatrix suppressed = CoverageMatrixProjector.project(
                "scan-synth", Optional.of(facts), List.of(), List.of(), List.of(),
                hypotheses, pathRuns, CoverageMatrixProjector.SuppressMode.SUPPRESS_DATAFLOW);
        CoverageMatrixProjector.RecallGateResult failed =
                CoverageMatrixProjector.evaluateRecallGate(suppressed, expected);
        check(!failed.passed(), "recall gate fails when DATAFLOW detector cleared");
        check(failed.missingFamilies().contains("DATAFLOW"), "missing family is DATAFLOW");

        String summary = first.gapsSummaryText(false);
        check(summary.contains("not safe") || summary.contains("SUCCESS"),
                "REPORT summary refuses SUCCESS-as-safe wording");
        check(baseline.path("expectedCoveredDetectorFamilies").isArray(),
                "baseline lists expected covered families");
    }

    private static StaticFactSnapshot syntheticFacts() {
        BytecodeFactIndex.InstructionEvidence evidence = new BytecodeFactIndex.InstructionEvidence(
                "com/example/A", "m", "()V", 0, 0);
        List<BytecodeFactIndex.ResolvedCallEdge> graph = List.of(
                new BytecodeFactIndex.ResolvedCallEdge(
                        "com/example/A", "m", "()V", "com/example/B", "com/example/B", "n", "()V",
                        BytecodeFactIndex.EdgeKind.DIRECT, "", evidence),
                new BytecodeFactIndex.ResolvedCallEdge(
                        "com/example/A", "m", "()V", "com/example/C", "com/example/C", "n", "()V",
                        BytecodeFactIndex.EdgeKind.CHA, "", evidence),
                new BytecodeFactIndex.ResolvedCallEdge(
                        "com/example/A", "m", "()V", "java/lang/Object", "java/lang/Object", "x", "()V",
                        BytecodeFactIndex.EdgeKind.UNRESOLVED, "missing target", evidence));
        List<BytecodeFactIndex.UnresolvedDynamicFact> unresolved = List.of(
                new BytecodeFactIndex.UnresolvedDynamicFact("INVOKE_DYNAMIC", "bootstrap", evidence));
        BytecodeFactIndex.AnalysisCoverage coverage = new BytecodeFactIndex.AnalysisCoverage(
                10, 10, 3, 2, false, List.of("BUDGET_EXCEEDED", "UNKNOWN_TARGET"));
        return new StaticFactSnapshot(
                StaticFactSnapshot.TRUNCATED,
                List.of(),
                coverage,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                unresolved,
                graph,
                List.of("classes capped at 500"));
    }

    private static void verifyLiveApi(Path root, Path jar, JsonNode baseline) throws Exception {
        String token = "coverage-token";
        Path database = root.resolve("state/control-plane.db");
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, token, database).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"coverage slice\"}", token));
            String projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            String scanId = text(scan, "scanId");
            check("COMPLETED".equals(String.valueOf(scan.get("status")))
                            || "SUCCESS".equals(String.valueOf(scan.get("status")))
                            || scan.get("status") != null,
                    "scan finished with a status");
            Object coverageObj = scan.get("coverage");
            check(coverageObj instanceof Map<?, ?>, "scan response embeds coverage matrix");
            @SuppressWarnings("unchecked")
            Map<String, Object> coverage = (Map<String, Object>) coverageObj;
            assertCoverageHonesty(coverage);

            Map<String, Object> endpoint = ok(send(client,
                    uri(server, "/scans/" + scanId + "/coverage"), "GET", "", token));
            assertCoverageHonesty(endpoint);
            check(scanId.equals(String.valueOf(endpoint.get("scanId"))), "coverage endpoint scanId");
            check(endpoint.get("checksum") != null
                            && !String.valueOf(endpoint.get("checksum")).isBlank(),
                    "coverage checksum present");

            Map<String, Object> detail = ok(send(client,
                    uri(server, "/scans/" + scanId), "GET", "", token));
            check(detail.get("coverage") instanceof Map<?, ?>, "GET scan includes coverage");

            // Live fixture 存在时应 surface SQL + AUTH_GAP detector family。
            Object detectors = endpoint.get("detectors");
            check(detectors instanceof List<?>, "detectors array present");
            boolean hasDataflow = false;
            boolean hasGuard = false;
            for (Object item : (List<?>) detectors) {
                if (!(item instanceof Map<?, ?> map)) continue;
                String family = String.valueOf(map.get("family"));
                int signals = map.get("signals") instanceof Number n ? n.intValue() : 0;
                boolean covered = Boolean.TRUE.equals(map.get("countedAsCovered"));
                if ("DATAFLOW".equals(family) && signals > 0 && covered) hasDataflow = true;
                if ("GUARD_COVERAGE".equals(family) && signals > 0 && covered) hasGuard = true;
            }
            check(hasDataflow, "live fixture projects DATAFLOW covered signals");
            check(hasGuard, "live fixture projects GUARD_COVERAGE covered signals");

            CoverageMatrixProjector.RecallGateResult liveGate =
                    CoverageMatrixProjector.evaluateRecallGate(
                            CoverageMatrixProjector.project(
                                    scanId,
                                    server.store().staticFacts(scanId),
                                    server.store().requireScan(scanId).dto().entries(),
                                    server.store().requireScan(scanId).dto().dependencies(),
                                    server.store().requireScan(scanId).dto().sinks(),
                                    server.store().hypotheses(scanId),
                                    List.of()),
                            Set.of("DATAFLOW", "GUARD_COVERAGE"));
            check(liveGate.passed(), "live recall gate passes for baseline families");
            check(baseline.path("recallGate").path("failWhenDetectorCleared").asText()
                            .equals("DATAFLOW"),
                    "baseline documents DATAFLOW clear failure");
        }
    }

    private static void assertCoverageHonesty(Map<String, Object> coverage) {
        check(coverage.get("schemaVersion") instanceof Number, "coverage schemaVersion");
        Object honesty = coverage.get("honestyFlags");
        check(honesty instanceof Map<?, ?>, "honestyFlags present");
        Map<?, ?> flags = (Map<?, ?>) honesty;
        check(Boolean.TRUE.equals(flags.get("neverTreatSuccessAsSafe")),
                "neverTreatSuccessAsSafe=true");
        check(Boolean.TRUE.equals(flags.get("gapsNeverCountAsCovered")),
                "gapsNeverCountAsCovered=true");
        check("analysis_finished_not_safe".equals(String.valueOf(flags.get("scanSuccessMeans"))),
                "scanSuccessMeans is not safe/secure");
        String blob = JsonCodec.stringify(coverage).toLowerCase();
        check(!blob.contains("\"safe\":true") && !blob.contains("\"secure\":true"),
                "coverage payload does not claim safe/secure");
        Object gaps = coverage.get("gaps");
        check(gaps instanceof Map<?, ?>, "gaps object present");
        check(Boolean.FALSE.equals(((Map<?, ?>) gaps).get("countedAsCovered")),
                "gaps.countedAsCovered=false");
    }

    private static Path buildFixture(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeFixtures(sources);
        compile(sources, classes);
        Path jar = root.resolve("coverage-fixture.jar");
        archive(classes, jar);
        return jar;
    }

    private static void writeFixtures(Path sources) throws Exception {
        Path pkg = Files.createDirectories(sources.resolve("com/example/cov"));
        Files.writeString(pkg.resolve("UserController.java"), """
                package com.example.cov;
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
                package com.example.cov;
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

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "request succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static String text(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof String text) || text.isBlank()) {
            throw new AssertionError("missing " + field);
        }
        return text;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

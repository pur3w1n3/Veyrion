package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

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
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * 说明：P0-12：SQL sink+AUTH_GAP 投影为 DATAFLOW+GUARD_COVERAGE hypothesis，无 sink-none。
 */
public final class SecurityHypothesisAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = Files.createTempDirectory("security-hypothesis");
        try {
            Path jar = buildFixture(root);
            verifyProjection(root, jar);
            System.out.println("SecurityHypothesisAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            deleteTree(root);
        }
    }

    private static void verifyProjection(Path root, Path jar) throws Exception {
        String token = "hypothesis-token";
        Path database = root.resolve("state/control-plane.db");
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, token, database).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"hypothesis slice\"}", token));
            String projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            String scanId = text(scan, "scanId");

            check(array(scan, "sinks").stream().anyMatch(value -> value instanceof Map<?, ?> item
                            && "SQL".equals(item.get("category"))),
                    "fixture emits SQL sink");
            check(array(scan, "sinks").stream().anyMatch(value -> value instanceof Map<?, ?> item
                            && "AUTH_GAP".equals(item.get("category"))),
                    "fixture emits AUTH_GAP sink");

            List<Object> hypotheses = array(scan, "hypotheses");
            check(!hypotheses.isEmpty(), "scan response includes hypotheses");
            boolean hasDataflow = hypotheses.stream().anyMatch(value -> value instanceof Map<?, ?> item
                    && "DATAFLOW".equals(String.valueOf(item.get("family"))));
            boolean hasGuard = hypotheses.stream().anyMatch(value -> value instanceof Map<?, ?> item
                    && "GUARD_COVERAGE".equals(String.valueOf(item.get("family")))
                    && ("AUTH_GAP".equals(String.valueOf(item.get("securityProperty")))
                    || "GUARD_COVERAGE".equals(String.valueOf(item.get("securityProperty")))));
            check(hasDataflow, "DATAFLOW hypothesis projected from SQL sink");
            check(hasGuard, "GUARD_COVERAGE hypothesis projected from AUTH_GAP");

            for (Object value : hypotheses) {
                if (!(value instanceof Map<?, ?> item)) continue;
                String effect = String.valueOf(item.get("effect"));
                String source = String.valueOf(item.get("source"));
                check(!"sink-none".equals(effect) && !"sink-none".equals(source),
                        "hypothesis does not use sink-none as AUTH representation");
            }

            ControlPlaneStore store = server.store();
            List<SecurityHypothesis> stored = store.hypotheses(scanId);
            check(stored.stream().anyMatch(h -> h.family() == HypothesisFamily.DATAFLOW),
                    "store has DATAFLOW hypothesis");
            check(stored.stream().anyMatch(h -> h.family() == HypothesisFamily.GUARD_COVERAGE),
                    "store has GUARD_COVERAGE hypothesis");

            ApiDtos.FindingDto sqlFinding = store.requireScan(scanId).findings().stream()
                    .filter(f -> "SQL".equalsIgnoreCase(f.securityProperty())
                            || (f.sink() != null && f.sink().toLowerCase().contains("sql")))
                    .findFirst()
                    .orElse(null);
            check(sqlFinding != null, "SQL finding present");
            check(sqlFinding.hypothesisId() != null && !sqlFinding.hypothesisId().isBlank(),
                    "SQL finding binds hypothesisId");
            SecurityHypothesis sqlHyp = store.hypothesis(sqlFinding.hypothesisId());
            check(sqlHyp != null && sqlHyp.family() == HypothesisFamily.DATAFLOW,
                    "finding.hypothesisId reverse-looks up DATAFLOW hypothesis");

            ApiDtos.FindingDto authFinding = store.requireScan(scanId).findings().stream()
                    .filter(f -> "AUTH_GAP".equalsIgnoreCase(f.securityProperty())
                            || SecurityHypothesisProjector.GUARD_COVERAGE_SINK_LABEL.equalsIgnoreCase(f.sink()))
                    .findFirst()
                    .orElse(null);
            check(authFinding != null, "AUTH_GAP / guard-coverage finding present");
            check(!"sink-none".equalsIgnoreCase(authFinding.sinkId()),
                    "AUTH finding sinkId is not sink-none");
            check(!"sink-none".equalsIgnoreCase(authFinding.sink()),
                    "AUTH finding sink label is not sink-none");
            check(authFinding.sinkId().startsWith("guard:") || authFinding.sinkId().startsWith("hypothesis:"),
                    "AUTH finding uses guard:/hypothesis: sinkId");
            check(SecurityHypothesisProjector.GUARD_COVERAGE_SINK_LABEL.equals(authFinding.sink()),
                    "AUTH finding sink label is guard-coverage");
            SecurityHypothesis authHyp = store.hypothesis(authFinding.hypothesisId());
            check(authHyp != null && authHyp.family() == HypothesisFamily.GUARD_COVERAGE,
                    "finding.hypothesisId reverse-looks up GUARD_COVERAGE hypothesis");

            Map<String, Object> findingsBody = ok(send(client,
                    uri(server, "/scans/" + scanId + "/findings"), "GET", "", token));
            List<Object> findingMaps = array(findingsBody, "findings");
            check(findingMaps.stream().anyMatch(value -> value instanceof Map<?, ?> item
                            && item.get("hypothesisId") != null
                            && String.valueOf(item.get("hypothesisId")).equals(sqlFinding.hypothesisId())),
                    "findings API exposes hypothesisId");
            check(findingMaps.stream().anyMatch(value -> value instanceof Map<?, ?> item
                            && "AUTH_GAP".equals(String.valueOf(item.get("securityProperty")))),
                    "findings API exposes AUTH_GAP securityProperty");

            ControlPlaneStore reloaded = ControlPlaneStore.sqlite(database, root);
            check(reloaded.hypotheses(scanId).stream()
                            .anyMatch(h -> h.family() == HypothesisFamily.GUARD_COVERAGE),
                    "hypotheses reload from SQLite V024");
            ApiDtos.FindingDto reloadedAuth = reloaded.finding(authFinding.findingId());
            check(reloadedAuth != null
                            && authFinding.hypothesisId().equals(reloadedAuth.hypothesisId()),
                    "finding hypothesisId survives SQLite reload");

            Map<String, Object> projectTwo = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"hypothesis scope two\"}", token));
            String projectTwoId = text(projectTwo, "projectId");
            Map<String, Object> artifactTwo = ok(send(client,
                    uri(server, "/projects/" + projectTwoId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scanTwo = ok(send(client,
                    uri(server, "/projects/" + projectTwoId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifactTwo, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            String scanTwoId = text(scanTwo, "scanId");
            String sharedId = "hypothesis:shared-scope-regression";
            SecurityHypothesis firstShared = new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION, sharedId, scanId, "AUTH_GAP",
                    HypothesisFamily.GUARD_COVERAGE, HypothesisLifecycle.CANDIDATE,
                    "scope-regression", List.of(), List.of(), List.of(), "", "");
            SecurityHypothesis secondShared = new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION, sharedId, scanTwoId, "AUTH_GAP",
                    HypothesisFamily.GUARD_COVERAGE, HypothesisLifecycle.CANDIDATE,
                    "scope-regression", List.of(), List.of(), List.of(), "", "");
            List<SecurityHypothesis> firstHypotheses = new java.util.ArrayList<>(store.hypotheses(scanId));
            firstHypotheses.add(firstShared);
            store.saveHypotheses(scanId, firstHypotheses, "local-admin");
            List<SecurityHypothesis> secondHypotheses = new java.util.ArrayList<>(store.hypotheses(scanTwoId));
            secondHypotheses.add(secondShared);
            store.saveHypotheses(scanTwoId, secondHypotheses, "local-admin");
            check(store.hypothesis(scanId, sharedId) == firstShared,
                    "same hypothesisId resolves inside first scan");
            check(store.hypothesis(scanTwoId, sharedId) == secondShared,
                    "same hypothesisId resolves inside second scan");
            check(store.hypothesis(sharedId) == null,
                    "ambiguous global hypothesisId fails closed");

            ControlPlaneStore scopedReload = ControlPlaneStore.sqlite(database, root);
            check(scopedReload.hypothesis(scanId, sharedId) != null
                            && scopedReload.hypothesis(scanTwoId, sharedId) != null,
                    "V024 reload preserves both scan-scoped hypothesis rows");
            check(scopedReload.hypothesis(sharedId) == null,
                    "V024 reload keeps ambiguous global lookup fail-closed");
        }
    }

    private static Path buildFixture(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeFixtures(sources);
        compile(sources, classes);
        Path jar = root.resolve("hypothesis-fixture.jar");
        archive(classes, jar);
        return jar;
    }

    private static void writeFixtures(Path sources) throws Exception {
        Path pkg = Files.createDirectories(sources.resolve("com/example/hyp"));
        Files.writeString(pkg.resolve("UserController.java"), """
                package com.example.hyp;
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
                package com.example.hyp;
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

    @SuppressWarnings("unchecked")
    private static List<Object> array(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof List<?> list)) throw new AssertionError("missing array " + field);
        return (List<Object>) list;
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

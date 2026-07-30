package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

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
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P1-03：实验计划绑定执行；超预算以 PROBE_BUDGET 拒绝。
 */
public final class ExperimentPlanExecutionAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ToolExecutionContext.Scope SCOPE =
            new ToolExecutionContext.Scope("local", "project-a");

    public static void main(String[] args) throws Exception {
        validatorRejectsOverBudget();
        planProposeBindsForExecution();
        focusProbeConsumesAcceptedPlan();
        System.out.println("ExperimentPlanExecutionAcceptanceTest: PASS");
    }

    private static void validatorRejectsOverBudget() {
        ExperimentPlan plan = new ExperimentPlan(
                "plan-budget", "entry:e1", IdentityTrack.UNAUTH, "GET",
                "application/json", List.of(), false, "2xx", "", 2);
        try {
            ExperimentPlanValidator.validate(plan, 0);
            throw new AssertionError("remainingBudget=0 must fail");
        } catch (IllegalArgumentException failure) {
            check("PROBE_BUDGET".equals(failure.getMessage()), "PROBE_BUDGET when no remaining budget");
        }
        try {
            ExperimentPlanValidator.validate(new ExperimentPlan(
                    "plan-budget-2", "entry:e1", IdentityTrack.UNAUTH, "GET",
                    "application/json", List.of(), false, "2xx", "", 4), 2);
            throw new AssertionError("maxAttempts>remaining must fail");
        } catch (IllegalArgumentException failure) {
            check("PROBE_BUDGET".equals(failure.getMessage()), "PROBE_BUDGET when maxAttempts exceeds");
        }
        ExperimentPlanValidator.validate(plan, 8);
    }

    private static void planProposeBindsForExecution() {
        AtomicReference<ExperimentPlan> accepted = new AtomicReference<>();
        ApiDtos.EntryDto entry = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "project-a", "a".repeat(64), "scan-a",
                "entry-plan-1", "HTTP", "GET", "/api/admin", "app.Admin", "Admin",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
        ToolDataSource source = new ToolDataSource() {
            @Override
            public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                                String query, int limit) {
                return List.of();
            }

            @Override
            public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
                return Optional.empty();
            }

            @Override
            public Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope,
                                                          String entrypointRef) {
                EntryRefResolver.Resolution resolution =
                        EntryRefResolver.resolve(List.of(entry), entrypointRef);
                if (!resolution.resolved()) return Optional.empty();
                ObjectNode value = JSON.createObjectNode();
                value.put("entrypoint", entry.declaringClass());
                return Optional.of(new FactRecord(scope, resolution.canonicalRef(), value));
            }

            @Override
            public void acceptExperimentPlan(ToolExecutionContext.Scope scope, ExperimentPlan plan) {
                accepted.set(plan);
            }
        };
        AiToolRegistry registry = new AiToolRegistry(source);
        ObjectNode args = JSON.createObjectNode();
        args.put("objective", "probe admin with bounded inputs");
        args.put("entrypointRef", "entry:entry-plan-1");
        args.put("track", "ADMIN");
        args.put("method", "GET");
        args.put("contentType", "application/json");
        args.put("maxAttempts", 2);
        args.putArray("candidateInputs").add("q=1").add("q=2");
        ToolExecutionContext context = ToolExecutionContext.bind(
                SCOPE, "principal-1", "job-1", AgentRole.PATH_EXPLORATION,
                new ToolExecutionContext.Budget(16, 64_000, 4, 256_000,
                        Instant.now().plus(Duration.ofMinutes(5))));
        ToolResult result = registry.execute(
                new ToolCall(1, "call-plan-1", "plan_propose", args), context);
        check(result.status() == ToolStatus.SUCCESS, "plan_propose completes: " + result.errorCode());
        check(accepted.get() != null, "acceptExperimentPlan invoked");
        check(accepted.get().planId().startsWith("plan:"), "planId assigned");
        check(accepted.get().track() == IdentityTrack.ADMIN, "track ADMIN");
        check(!result.outputs().isEmpty(), "plan_propose returns outputs");
        check(result.outputs().get(0).value().path("boundForExecution").asBoolean(false),
                "boundForExecution true");
        check(result.outputs().get(0).value().path("serverGated").asBoolean(false),
                "serverGated true");
    }

    private static void focusProbeConsumesAcceptedPlan() throws Exception {
        Path root = Files.createTempDirectory("exp-plan-bind");
        try {
            Path jar = buildFixtureJar(root);
            String token = "plan-bind-token";
            HttpClient client = HttpClient.newHttpClient();
            try (ControlPlaneServer server = new ControlPlaneServer(
                    root, 0, token, root.resolve("state/control-plane.db")).start()) {
                URI base = server.baseUri();
                String projectId = text(request(client, URI.create(base + "/projects"), "POST",
                        "{\"name\":\"plan-bind\"}", token, "plan-project"), "projectId");
                String digest = text(request(client,
                        URI.create(base + "/projects/" + projectId + "/artifacts"), "POST",
                        "{\"path\":\"" + escape(jar.toString()) + "\"}", token, "plan-artifact"),
                        "artifactDigest");
                Map<String, Object> scan = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/scans"), "POST",
                        "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                        token, "plan-scan"));
                String scanId = text(scan, "scanId");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> entries = (List<Map<String, Object>>) scan.get("entries");
                String entryId = text(entries.get(0), "id");
                String planId = "plan:manual-bind-1";
                ExperimentPlan plan = new ExperimentPlan(
                        planId, "entry:" + entryId, IdentityTrack.UNAUTH, "GET",
                        "application/json", List.of(), false, "2xx", "", 2,
                        List.of("q=from-plan"), "COMPLETED", "");
                server.acceptExperimentPlan(scanId, plan);

                Map<String, Object> dashboard = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/dashboard?scanId=" + scanId),
                        "GET", null, token, null));
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> plans =
                        (List<Map<String, Object>>) dashboard.get("experimentPlans");
                check(plans != null && plans.stream().anyMatch(row -> planId.equals(row.get("planId"))),
                        "dashboard lists accepted experimentPlans");
                check(dashboard.get("probeBudget") instanceof Map<?, ?>, "dashboard exposes probeBudget");

                URI focusUri = URI.create(base + "/scans/" + scanId + "/entries/" + entryId + "/focus-probe");
                HttpResponse<String> missing = request(client, focusUri, "POST",
                        "{\"authorized\":true,\"experimentPlanId\":\"plan:missing\"}",
                        token, "focus-missing-plan");
                check(missing.statusCode() == 404, "unknown plan → 404");

                HttpResponse<String> accepted = request(client, focusUri, "POST",
                        "{\"authorized\":true,\"experimentPlanId\":\"" + planId + "\"}",
                        token, "focus-with-plan");
                check(accepted.statusCode() == 202, "focus with bound plan accepted: " + accepted.body());
                Map<String, Object> body = json(accepted);
                check("DYNAMIC_SUSPECTED".equals(body.get("verificationStatus")),
                        "bound focus stays DYNAMIC_SUSPECTED");
                check(!"VERIFIED".equals(body.get("verificationStatus")), "never VERIFIED");
            }
        } finally {
            deleteTree(root);
        }
    }

    private static Path buildFixtureJar(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        source(sources, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        source(sources, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String[] value() default {}; String[] path() default {}; }
                """);
        source(sources, "app/PlanController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class PlanController {
                    @GetMapping("/focus")
                    public String focus(String q) { return q == null ? "ok" : q; }
                }
                """);
        compile(sources, classes);
        Path jar = root.resolve("plan-fixture.jar");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                output.putNextEntry(new ZipEntry(
                        "BOOT-INF/classes/" + classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, output);
                output.closeEntry();
            }
        }
        return jar;
    }

    private static void source(Path root, String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "tests require a JDK compiler");
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

    private static HttpResponse<String> request(HttpClient client, URI uri, String method, String body,
                                                String token, String idempotencyKey) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Authorization", token);
        if (idempotencyKey != null) builder.header("Idempotency-Key", idempotencyKey);
        HttpRequest request = "GET".equals(method)
                ? builder.GET().build()
                : builder.method(method, HttpRequest.BodyPublishers.ofString(body == null ? "" : body)).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> json(HttpResponse<String> response) {
        return JsonCodec.parseObject(response.body());
    }

    private static String text(HttpResponse<String> response, String key) {
        return text(json(response), key);
    }

    private static String text(Map<String, Object> body, String key) {
        Object value = body.get(key);
        check(value instanceof String text && !text.isBlank(), key + " present");
        return (String) value;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> walk = Files.walk(root)) {
            List<Path> paths = walk.sorted((left, right) -> right.compareTo(left)).toList();
            for (Path path : paths) Files.deleteIfExists(path);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.model.ProvenanceKind;
import com.aq.jvmsentinel.model.VerificationStatus;

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
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Load-free, owner-qualified JVM sink detection and entry-flow acceptance checks. */
public final class BytecodeSinkAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("bytecode-sink-test");
        try {
            Path sources = Files.createDirectories(root.resolve("sources"));
            Path classes = Files.createDirectories(root.resolve("classes"));
            writeFixtures(sources);
            compile(sources, classes);
            Path jar = root.resolve("sink-fixture.jar");
            archive(classes, jar);

            ArtifactRegistry registry = new ArtifactRegistry(root);
            PreAnalysisInput input = ArtifactMetadataReader.read(registry.register(jar));
            PreAnalysisResult result = new PreAnalysisService().analyze(input);
            Set<String> categories = result.sinkCatalog().sinks().stream()
                    .map(sink -> sink.category()).collect(java.util.stream.Collectors.toSet());
            Set<String> expected = Set.of("COMMAND", "NATIVE_CODE", "DESERIALIZATION", "EXPRESSION",
                    "JNDI", "CLASS_LOADING", "SQL", "XPATH", "XML", "FILE_READ", "FILE_WRITE", "SSRF");
            check(categories.containsAll(expected),
                    "owner-qualified checklist coverage missing " + difference(expected, categories));
            check(result.sinkCatalog().sinks().stream()
                            .filter(sink -> sink.source().startsWith("bytecode-invoke:"))
                            .allMatch(sink ->
                            sink.status() == VerificationStatus.STATIC_INFERRED
                                    && sink.source().startsWith("bytecode-invoke:")
                                    && sink.symbol().startsWith("app.SinkController#danger")),
                    "invocations remain static candidates bound to their actual caller method");
            check(result.entryCatalog().evidence().stream().filter(item ->
                            item.source().startsWith("classfile-call:"))
                    .allMatch(item -> item.kind() == ProvenanceKind.FACT
                            && item.summary().contains("runtime reachability and input control not established")),
                    "call evidence is factual while exploitability remains explicitly unproven");
            check(result.sinkCatalog().sinks().stream().noneMatch(sink ->
                            sink.symbol().contains("java.lang.String#trim")),
                    "generic method names are not treated as sinks without an owner-qualified rule");

            verifyProjectedFlow(root, jar);
            System.out.println("BytecodeSinkAcceptanceTest: PASS");
        } finally {
            deleteTree(root);
        }
    }

    private static void verifyProjectedFlow(Path root, Path jar) throws Exception {
        String token = "sink-test-token";
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(
                root, 0, token, root.resolve("state/control-plane.db")).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"sink flow\"}", token));
            String projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            String scanId = text(scan, "scanId");
            String dangerousEntryId = text(byRoute(array(scan, "entries"), "/danger"), "id");
            String safeEntryId = text(byRoute(array(scan, "entries"), "/safe"), "id");

            Map<String, Object> paths = ok(send(client,
                    uri(server, "/scans/" + scanId + "/paths"), "GET", "", token));
            Map<String, Object> dangerous = byField(
                    array(paths, "paths"), "entrypointId", dangerousEntryId);
            Map<String, Object> safe = byField(array(paths, "paths"), "entrypointId", safeEntryId);
            check(stepKinds(dangerous).contains("sink"),
                    "danger handler path contains its own direct classfile sink candidates");
            check(!stepKinds(safe).contains("sink"),
                    "safe handler path does not inherit sinks from another method in the same controller");

            Map<String, Object> findings = ok(send(client,
                    uri(server, "/scans/" + scanId + "/findings"), "GET", "", token));
            check(array(findings, "findings").stream()
                            .filter(value -> value instanceof Map<?, ?> item
                                    && !String.valueOf(item.get("title")).contains("鉴权缺口"))
                            .allMatch(value -> value instanceof Map<?, ?> item
                                    && "/danger".equals(item.get("entry"))),
                    "sensitive findings bind to the exact annotated handler method rather than every class route");
            Map<String, Object> chains = ok(send(client,
                    uri(server, "/attack-chains?projectId=" + projectId), "GET", "", token));
            check(array(chains, "attackChains").stream().allMatch(value ->
                            value instanceof Map<?, ?> item
                                    && String.valueOf(item.get("title")).contains("尚未验证")),
                    "combined static candidates never claim a verified cross-sink flow");
        }
    }

    private static void writeFixtures(Path root) throws Exception {
        source(root, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        source(root, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String[] value() default {}; String[] path() default {}; }
                """);
        source(root, "org/springframework/boot/loader/NoisyLauncher.java", """
                package org.springframework.boot.loader;
                public class NoisyLauncher {
                    public void frameworkMechanic(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """);
        source(root, "app/SinkController.java", """
                package app;
                import java.beans.XMLDecoder;
                import java.io.*;
                import java.net.*;
                import java.nio.file.*;
                import java.sql.DriverManager;
                import javax.naming.InitialContext;
                import javax.script.ScriptEngine;
                import javax.script.ScriptEngineManager;
                import javax.xml.parsers.DocumentBuilderFactory;
                import javax.xml.xpath.XPathFactory;
                import org.xml.sax.InputSource;
                import org.springframework.web.bind.annotation.*;

                @RestController
                public class SinkController {
                    @GetMapping("/danger")
                    public void danger(String command, String path, String url, String expression) throws Exception {
                        Runtime.getRuntime().exec(command);
                        System.load(path);
                        new ObjectInputStream(InputStream.nullInputStream()).readObject();
                        new XMLDecoder(InputStream.nullInputStream()).readObject();
                        new InitialContext().lookup(url);
                        Class.forName(command);
                        DriverManager.getConnection(url);
                        XPathFactory.newInstance().newXPath().evaluate(expression, new InputSource(new StringReader("")));
                        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(InputStream.nullInputStream());
                        Files.readString(Path.of(path));
                        Files.writeString(Path.of(path), command);
                        new URL(url).openConnection();
                        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
                        engine.eval(expression);
                    }

                    @GetMapping("/safe")
                    public String safe(String value) {
                        return value.trim();
                    }
                }
                """);
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

    @SuppressWarnings("unchecked")
    private static Map<String, Object> byRoute(List<Object> values, String route) {
        return values.stream().filter(value -> value instanceof Map<?, ?> item
                        && route.equals(item.get("route")))
                .map(value -> (Map<String, Object>) value).findFirst()
                .orElseThrow(() -> new AssertionError("missing path for " + route));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> byField(List<Object> values, String field, String expected) {
        return values.stream().filter(value -> value instanceof Map<?, ?> item
                        && expected.equals(item.get(field)))
                .map(value -> (Map<String, Object>) value).findFirst()
                .orElseThrow(() -> new AssertionError("missing " + field + "=" + expected));
    }

    private static Set<String> stepKinds(Map<String, Object> path) {
        return array(path, "steps").stream().filter(Map.class::isInstance)
                .map(Map.class::cast).map(step -> String.valueOf(step.get("kind")))
                .collect(java.util.stream.Collectors.toSet());
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

    private static Set<String> difference(Set<String> expected, Set<String> actual) {
        java.util.LinkedHashSet<String> result = new java.util.LinkedHashSet<>(expected);
        result.removeAll(actual);
        return result;
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}

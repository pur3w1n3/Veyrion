package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.ClassMetadata;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.artifact.ArtifactValidationException;
import com.aq.jvmsentinel.model.Entrypoint;
import com.aq.jvmsentinel.model.ProvenanceKind;
import com.aq.jvmsentinel.model.VerificationStatus;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Executable acceptance checks for bounded, load-free classfile annotation analysis. */
public final class ClassfileAnnotationAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("classfile-annotation-test");
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeAnnotationFixtures(sources);
        writeApplicationFixtures(sources);
        compile(sources, classes);

        Path jar = root.resolve("fixture.jar");
        createArchive(classes, jar, "BOOT-INF/classes/");
        ArtifactRegistry registry = new ArtifactRegistry(root);
        PreAnalysisInput input = ArtifactMetadataReader.read(registry.register(jar));
        check(input.classNames().contains("app.OrderController"), "BOOT-INF class name normalization");
        ClassMetadata plain = input.classMetadata().stream()
                .filter(metadata -> metadata.className().equals("app.PlainController")).findFirst().orElseThrow();
        check(plain.annotationMetadataValid(), "plain class metadata should parse");

        PreAnalysisResult result = new PreAnalysisService().analyze(input);
        Set<String> routes = result.entryCatalog().entries().stream()
                .map(entry -> entry.method() + " " + entry.route()).collect(java.util.stream.Collectors.toSet());
        Set<String> expectedRoutes = Set.of(
                "GET /api/orders",
                "GET /api/orders-alt",
                "POST /api/orders",
                "PUT /api/item/{id}",
                "DELETE /api/item/{id}");
        check(routes.equals(expectedRoutes),
                "synthetic Spring MVC recall/precision baseline: expected " + expectedRoutes + " but got " + routes);
        check(result.entryCatalog().entries().stream().noneMatch(
                entry -> entry.declaringClass().equals("app.PlainController")), "annotated plain class must not be guessed");
        check(result.entryCatalog().entries().stream().allMatch(
                entry -> entry.status() == VerificationStatus.STATIC_INFERRED), "routes remain static inferred");
        check(result.entryCatalog().evidence().stream().anyMatch(
                item -> item.kind() == ProvenanceKind.FACT && item.source().startsWith("classfile-annotation:")),
                "annotation evidence must be factual");
        check(result.entryCatalog().evidence().stream().noneMatch(
                item -> item.summary().contains("hasRole") || item.summary().contains("fixture-secret")),
                "evidence summaries must not expose annotation/config values");
        Entrypoint get = result.entryCatalog().entries().stream()
                .filter(entry -> entry.method().equals("GET") && entry.route().equals("/api/orders")).findFirst().orElseThrow();
        check(get.parameters().stream().anyMatch(value -> value.contains("position=0")
                && value.contains("RequestParam") && value.contains("name=q")), "request parameter metadata");
        check(get.parameters().stream().anyMatch(value -> value.contains("position=1")
                && value.contains("RequestHeader") && value.contains("X-Tenant")), "header parameter metadata");
        check(get.preconditions().stream().anyMatch(value -> value.startsWith("PreAuthorize(")),
                "class permission precondition");
        check(result.permissionMatrix().requirements().stream().anyMatch(
                requirement -> requirement.entrypointId().equals(get.id())
                        && requirement.roles().contains("ROLE_READER")
                        && requirement.states().stream().anyMatch(value -> value.startsWith("EXPR:"))),
                "permission matrix");
        check(result.dependencyMap().accesses().stream().anyMatch(value -> value.kind().equals("DATABASE")),
                "class-name/config dependency inference regression");
        check(result.sinkCatalog().sinks().isEmpty(),
                "valid classfiles must not become sinks from framework/application class names alone");
        check(result.entryCatalog().evidence().stream().noneMatch(
                item -> item.summary().contains("fixture-secret")), "configuration redaction regression");

        Path directClass = classes.resolve("app/OrderController.class");
        PreAnalysisInput directInput = ArtifactMetadataReader.read(registry.register(directClass));
        check(directInput.classNames().equals(List.of("app.OrderController")), "direct CLASS internal name");
        check(new PreAnalysisService().analyze(directInput).entryCatalog().entries().stream().anyMatch(
                entry -> entry.method().equals("POST") && entry.route().equals("/api/orders")),
                "direct CLASS annotation parsing");

        Path war = root.resolve("fixture.war");
        createArchive(classes, war, "WEB-INF/classes/");
        PreAnalysisInput warInput = ArtifactMetadataReader.read(registry.register(war));
        check(warInput.classNames().contains("app.OrderController"), "WEB-INF class name normalization");

        Path malformed = root.resolve("Corrupt.class");
        Files.write(malformed, new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0});
        PreAnalysisInput malformedInput = ArtifactMetadataReader.read(registry.register(malformed));
        check(!malformedInput.classMetadata().get(0).annotationMetadataValid(), "truncated class must safely degrade");
        new PreAnalysisService().analyze(malformedInput);

        Path oversized = root.resolve("Oversized.class");
        Files.write(oversized, new byte[4 * 1024 * 1024 + 1]);
        expect(ArtifactValidationException.class,
                () -> ArtifactMetadataReader.read(registry.register(oversized)));
        System.out.println("ClassfileAnnotationAcceptanceTest: PASS");
    }

    private static void writeAnnotationFixtures(Path root) throws Exception {
        annotation(root, "org.springframework.stereotype.Controller", "TYPE", "");
        annotation(root, "org.springframework.web.bind.annotation.RestController", "TYPE", "");
        source(root, "org/springframework/web/bind/annotation/RequestMethod.java",
                "package org.springframework.web.bind.annotation;\n"
                        + "public enum RequestMethod { GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE }\n");
        annotation(root, "org.springframework.web.bind.annotation.RequestMapping", "TYPE,METHOD",
                "String[] value() default {}; String[] path() default {}; "
                        + "RequestMethod[] method() default {};");
        for (String name : List.of("GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping")) {
            annotation(root, "org.springframework.web.bind.annotation." + name, "METHOD",
                    "String[] value() default {}; String[] path() default {};");
        }
        for (String name : List.of("RequestParam", "PathVariable", "RequestHeader", "CookieValue", "RequestPart")) {
            annotation(root, "org.springframework.web.bind.annotation." + name, "PARAMETER",
                    "String value() default \"\"; String name() default \"\";");
        }
        for (String name : List.of("RequestBody", "ModelAttribute")) {
            annotation(root, "org.springframework.web.bind.annotation." + name, "PARAMETER",
                    "String value() default \"\"; String name() default \"\";");
        }
        annotation(root, "org.springframework.security.access.prepost.PreAuthorize", "TYPE,METHOD",
                "String value();");
        annotation(root, "org.springframework.security.access.annotation.Secured", "TYPE,METHOD",
                "String[] value();");
        annotation(root, "jakarta.annotation.security.RolesAllowed", "TYPE,METHOD", "String[] value();");
    }

    private static void writeApplicationFixtures(Path root) throws Exception {
        source(root, "app/OrderController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                import org.springframework.security.access.prepost.PreAuthorize;
                import org.springframework.security.access.annotation.Secured;
                import jakarta.annotation.security.RolesAllowed;
                @RestController
                @RequestMapping("/api")
                @PreAuthorize("hasRole('USER')")
                public class OrderController {
                    @GetMapping({"/orders", "/orders-alt"})
                    @Secured({"ROLE_READER"})
                    public String get(@RequestParam(name="q") String query,
                                      @RequestHeader("X-Tenant") String tenant) { return query; }
                    @PostMapping(path="/orders")
                    @RolesAllowed({"ROLE_WRITER"})
                    public void create(@RequestBody String body, @CookieValue("sid") String cookie) { }
                    @RequestMapping(path="/item/{id}", method={RequestMethod.PUT, RequestMethod.DELETE})
                    public void update(@PathVariable("id") String id, @RequestPart("part") String part) { }
                }
                """);
        source(root, "app/PlainController.java",
                "package app; public class PlainController { public void noRoute(String value) { } }\n");
        source(root, "app/FileService.java", "package app; public class FileService { }\n");
        source(root, "app/OrderRepository.java", "package app; public class OrderRepository { }\n");
    }

    private static void annotation(Path root, String type, String targets, String members) throws Exception {
        int dot = type.lastIndexOf('.');
        String packageName = type.substring(0, dot);
        String simpleName = type.substring(dot + 1);
        source(root, type.replace('.', '/') + ".java",
                "package " + packageName + ";\n"
                        + "import java.lang.annotation.*;\n"
                        + "@Retention(RetentionPolicy.RUNTIME) @Target({" + targets(targets) + "})\n"
                        + "public @interface " + simpleName + " { " + members + " }\n");
    }

    private static String targets(String targets) {
        List<String> result = new ArrayList<>();
        for (String target : targets.split(",")) result.add("ElementType." + target);
        return String.join(",", result);
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
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            Iterable<? extends javax.tools.JavaFileObject> units =
                    manager.getJavaFileObjectsFromPaths(sourceFiles);
            boolean success = compiler.getTask(null, manager, null,
                    List.of("--release", "17", "-parameters", "-d", classes.toString()), null, units).call();
            check(success, "fixture compilation");
        }
    }

    private static void createArchive(Path classes, Path archive, String classPrefix) throws Exception {
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(archive));
             Stream<Path> stream = Files.walk(classes)) {
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                String relative = classes.relativize(file).toString().replace('\\', '/');
                output.putNextEntry(new ZipEntry(classPrefix + relative));
                Files.copy(file, output);
                output.closeEntry();
            }
            output.putNextEntry(new ZipEntry(classPrefix + "application.properties"));
            output.write(("spring.datasource.url=jdbc:h2:mem:test\n"
                    + "spring.datasource.password=fixture-secret\n").getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static <T extends Throwable> void expect(Class<T> type, ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return;
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }
}

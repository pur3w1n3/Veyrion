package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.VerificationStatus;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Precise positive/negative acceptance checks for artifact-local interprocedural flow. */
public final class InterproceduralTaintAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("interprocedural-taint-test");
        try {
            Path sources = Files.createDirectories(root.resolve("sources"));
            Path classes = Files.createDirectories(root.resolve("classes"));
            fixtures(sources);
            compile(sources, classes);
            Path jar = root.resolve("flow.jar");
            archive(classes, jar);

            PreAnalysisResult result = new PreAnalysisService().analyze(
                    ArtifactMetadataReader.read(new ArtifactRegistry(root).register(jar)));
            BytecodeFactIndex index = result.bytecodeFactIndex();

            check(index.artifactCallGraph().stream().anyMatch(edge ->
                            edge.kind() == BytecodeFactIndex.EdgeKind.CHA
                                    && edge.declaredOwner().equals("app.Relay")
                                    && edge.targetOwner().equals("app.RelayImpl")
                                    && edge.targetName().equals("pass")),
                    "interface dispatch has an explicit artifact-local CHA target");
            check(index.artifactCallGraph().stream().anyMatch(edge ->
                            edge.kind() == BytecodeFactIndex.EdgeKind.DIRECT
                                    && edge.targetOwner().equals("app.Helper")
                                    && edge.targetName().equals("finish")),
                    "static helper call has an explicit direct target");
            check(index.artifactCallGraph().stream().anyMatch(edge ->
                            edge.kind() == BytecodeFactIndex.EdgeKind.UNRESOLVED
                                    && edge.targetOwner().equals("java.lang.String")
                                    && edge.targetName().equals("trim")),
                    "external transform remains explicitly unresolved");

            List<BytecodeFactIndex.TaintPath> commandPaths = index.taintPaths().stream()
                    .filter(path -> path.category().equals("COMMAND")).toList();
            check(commandPaths.stream().anyMatch(path -> path.sourceMethod().equals("danger")
                            && path.sinkOwner().equals("java.lang.Runtime")
                            && path.steps().stream().filter(step -> step.kind().equals("CALL")).count() >= 2
                            && path.steps().stream().anyMatch(step -> step.kind().equals("TRANSFORM"))),
                    "mapped parameter reaches strict Runtime.exec through CHA, helper, and transform steps");
            check(commandPaths.stream().noneMatch(path -> path.sourceMethod().equals("safe")),
                    "same-named app.SafeRuntime.exec is not a java.lang.Runtime sink");
            check(commandPaths.stream().noneMatch(path -> path.sourceMethod().equals("constant")),
                    "sink presence alone does not make an unused entry parameter controlled");
            check(commandPaths.stream().allMatch(path -> path.status().equals("STATIC_INFERRED")),
                    "static flow never claims dynamic or replay verification");
            check(result.sinkCatalog().sinks().stream().filter(sink -> sink.category().equals("COMMAND"))
                            .allMatch(sink -> sink.status() == VerificationStatus.STATIC_INFERRED),
                    "PreAnalysisService keeps taint-enriched sink candidates static");
            check(index.analysisCoverage().taintStatesVisited()
                            < index.analysisCoverage().taintStateBudget(),
                    "recursive calls terminate through state deduplication before the budget");
            check(!index.analysisCoverage().stopReasons().contains("TAINT_STATE_BUDGET_EXHAUSTED"),
                    "recursive fixture does not exhaust the state budget");
            System.out.println("InterproceduralTaintAcceptanceTest: PASS");
        } finally {
            deleteTree(root);
        }
    }

    private static void fixtures(Path root) throws Exception {
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
                public @interface GetMapping { String[] value() default {}; }
                """);
        source(root, "app/Relay.java", """
                package app;
                public interface Relay { void pass(String value) throws Exception; }
                """);
        source(root, "app/RelayImpl.java", """
                package app;
                public final class RelayImpl implements Relay {
                    public void pass(String value) throws Exception { Helper.finish(value.trim()); }
                }
                """);
        source(root, "app/Helper.java", """
                package app;
                public final class Helper {
                    public static void finish(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """);
        source(root, "app/SafeRuntime.java", """
                package app;
                public final class SafeRuntime { public static String exec(String value) { return value; } }
                """);
        source(root, "app/Recursive.java", """
                package app;
                public final class Recursive {
                    public static void loop(String value) { loop(value); }
                }
                """);
        source(root, "app/FlowController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController public final class FlowController {
                    private final Relay relay = new RelayImpl();
                    @GetMapping("/danger") public void danger(String input) throws Exception { relay.pass(input); }
                    @GetMapping("/safe") public String safe(String input) { return SafeRuntime.exec(input); }
                    @GetMapping("/constant") public Process constant(String ignored) throws Exception {
                        return Runtime.getRuntime().exec("fixed-command");
                    }
                    @GetMapping("/recursive") public void recursive(String input) { Recursive.loop(input); }
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
    }
}

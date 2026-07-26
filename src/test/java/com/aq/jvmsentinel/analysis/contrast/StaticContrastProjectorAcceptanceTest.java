package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.Sink;
import com.aq.jvmsentinel.model.StaticContrastRow;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Acceptance: taint sinks project to contrast rows with entryRefs / taintPathId.
 */
public final class StaticContrastProjectorAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("static-contrast-projector");
        try {
            Path sources = Files.createDirectories(root.resolve("sources"));
            Path classes = Files.createDirectories(root.resolve("classes"));
            fixtures(sources);
            compile(sources, classes);
            Path jar = root.resolve("flow.jar");
            archive(classes, jar);

            PreAnalysisResult result = new PreAnalysisService().analyze(
                    ArtifactMetadataReader.read(new ArtifactRegistry(root).register(jar)));
            List<BytecodeFactIndex.TaintPath> paths = result.bytecodeFactIndex().taintPaths();
            check(!paths.isEmpty(), "fixture produces at least one taint path");

            List<ApiDtos.EntryDto> entries = result.entryCatalog().entries().stream()
                    .map(entry -> new ApiDtos.EntryDto(
                            ApiDtos.SCHEMA_VERSION, "p", "d", "s", entry.id(), entry.protocol(),
                            entry.method(), entry.route(), entry.declaringClass(), "mod",
                            entry.parameters(), entry.preconditions(),
                            entry.status().name(), entry.confidence(), 0, entry.evidenceRefs()))
                    .toList();
            Map<String, ApiDtos.EvidenceDto> evidence = new HashMap<>();
            for (var ev : result.entryCatalog().evidence()) {
                evidence.put(ev.evidenceId(), new ApiDtos.EvidenceDto(
                        ApiDtos.SCHEMA_VERSION, "p", "d", "s", ev.evidenceId(),
                        ev.kind().name(), ev.source(), ev.confidence(),
                        ev.summary(), "1970-01-01T00:00:00Z", "test", "none", "none",
                        ApiDtos.MOCK, ApiDtos.STATIC_INFERRED));
            }

            StaticContrastProjector.Projection projection = new StaticContrastProjector()
                    .projectFromTaint(paths, result.sinkCatalog().sinks(), entries, evidence);

            List<StaticContrastRow> withTaint = projection.rows().stream()
                    .filter(StaticContrastRow::hasTaintPath)
                    .toList();
            check(!withTaint.isEmpty(), "taint sinks produce contrast rows with taintPathId");
            check(withTaint.stream().anyMatch(row -> !row.entryRefs().isEmpty()),
                    "taint contrast rows carry entryRefs");
            check(withTaint.stream().allMatch(row -> row.contrastStatus() == ContrastStatus.UNKNOWN),
                    "projector leaves status UNKNOWN until PathRun join");
            check(withTaint.stream().anyMatch(row ->
                            paths.stream().anyMatch(path -> path.id().equals(row.taintPathId()))),
                    "taintPathId matches BytecodeFactIndex.TaintPath.id");

            // Budget truncation is explicit and testable.
            List<Sink> many = new java.util.ArrayList<>();
            for (int i = 0; i < StaticContrastProjector.MAX_ROWS + 5; i++) {
                many.add(new Sink("sink-extra-" + i, "FILE", "x.Y#z", "unbound", 0.5,
                        List.of(), com.aq.jvmsentinel.model.VerificationStatus.STATIC_INFERRED));
            }
            StaticContrastProjector.Projection capped = new StaticContrastProjector()
                    .projectFromTaint(List.of(), many, List.of(), Map.of());
            check(capped.rows().size() == StaticContrastProjector.MAX_ROWS, "ledger row budget capped");
            check(capped.truncated(), "truncation flag set");
            check(StaticContrastProjector.STOP_BUDGET.equals(capped.stopReason()),
                    "stopReason=LEDGER_ROW_BUDGET_EXHAUSTED");

            System.out.println("StaticContrastProjectorAcceptanceTest: PASS");
        } finally {
            deleteTree(root);
        }
    }

    private static void fixtures(Path root) throws Exception {
        // Minimal reuse of InterproceduralTaintAcceptanceTest shape.
        write(root, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        write(root, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String value() default ""; }
                """);
        write(root, "org/springframework/web/bind/annotation/RequestParam.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.PARAMETER)
                public @interface RequestParam { String value() default ""; }
                """);
        write(root, "app/Relay.java", """
                package app;
                public interface Relay { String pass(String value); }
                """);
        write(root, "app/RelayImpl.java", """
                package app;
                public class RelayImpl implements Relay {
                    public String pass(String value) { return Helper.finish(value); }
                }
                """);
        write(root, "app/Helper.java", """
                package app;
                public final class Helper {
                    public static String finish(String value) { return value.trim(); }
                }
                """);
        write(root, "app/FlowController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class FlowController {
                    private final Relay relay = new RelayImpl();
                    @GetMapping("/danger")
                    public void danger(@RequestParam String cmd) throws Exception {
                        Runtime.getRuntime().exec(relay.pass(cmd));
                    }
                    @GetMapping("/safe")
                    public void safe(@RequestParam String cmd) throws Exception {
                        new SafeRuntime().exec(cmd);
                    }
                }
                """);
        write(root, "app/SafeRuntime.java", """
                package app;
                public class SafeRuntime {
                    public void exec(String cmd) { }
                }
                """);
    }

    private static void write(Path root, String relative, String source) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, source, StandardCharsets.UTF_8);
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager fm = compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            try (Stream<Path> stream = Files.walk(sources)) {
                List<Path> files = stream.filter(path -> path.toString().endsWith(".java")).toList();
                var units = fm.getJavaFileObjectsFromPaths(files);
                if (!compiler.getTask(null, fm, null, List.of("-d", classes.toString()), null, units).call()) {
                    throw new IllegalStateException("compile failed");
                }
            }
        }
    }

    private static void archive(Path classes, Path jar) throws Exception {
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            List<Path> files = stream.filter(Files::isRegularFile).toList();
            for (Path file : files) {
                String name = classes.relativize(file).toString().replace('\\', '/');
                zip.putNextEntry(new ZipEntry(name));
                Files.copy(file, zip);
                zip.closeEntry();
            }
        }
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> stream = Files.walk(root)) {
            List<Path> paths = stream.sorted((a, b) -> b.getNameCount() - a.getNameCount()).toList();
            for (Path path : paths) Files.deleteIfExists(path);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

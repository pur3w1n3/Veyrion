package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.ClassMetadata;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.model.Entrypoint;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * 验收：ArtifactMetadataReader 覆盖 BOOT-INF/lib 与 WEB-INF/lib 一层嵌套类路径，
 * 且同 FQCN 优先外层 BOOT-INF/classes；入口发现能看到 lib 内注解 handler。
 */
public final class NestedClasspathMetadataAcceptanceTest {
    static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        ASSERTIONS.set(0);
        Path root = Files.createTempDirectory("nested-classpath-meta");
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeSpringAnnotations(sources);
        writePrimarySources(sources);
        compile(sources, classes);

        // 同 FQCN 两份字节：先编译带注解的应用优先版，再覆盖为 lib 普通版。
        byte[] sharedPreferred = Files.readAllBytes(classes.resolve("app/SharedType.class"));
        source(sources, "app/SharedType.java", "package app; public class SharedType { }\n");
        compile(sources, classes);
        byte[] sharedFromLib = Files.readAllBytes(classes.resolve("app/SharedType.class"));

        Path bootJar = buildBootJarWithNestedLib(root, classes, sharedPreferred, sharedFromLib);
        ArtifactRegistry registry = new ArtifactRegistry(root);
        PreAnalysisInput bootInput = ArtifactMetadataReader.read(registry.register(bootJar));

        check(bootInput.classNames().contains("app.AppController"), "BOOT-INF/classes app controller present");
        check(bootInput.classNames().contains("lib.LibController"), "BOOT-INF/lib nested controller class present");
        check(bootInput.classNames().contains("lib.Helper"), "BOOT-INF/lib nested helper class present");
        check(!bootInput.classNames().contains("buried.DeepClass"),
                "lib-in-lib second layer must not be expanded");

        long libControllerCount = bootInput.classMetadata().stream()
                .filter(m -> "lib.LibController".equals(m.className()))
                .count();
        check(libControllerCount == 1, "nested lib controller deduped to one metadata");

        ClassMetadata preferred = bootInput.classMetadata().stream()
                .filter(m -> "app.SharedType".equals(m.className()))
                .findFirst()
                .orElseThrow();
        check(preferred.annotationMetadataValid(), "shared FQCN metadata parses");
        check(preferred.annotations().stream().anyMatch(a -> a.typeName().endsWith("RestController")),
                "FQCN priority: BOOT-INF/classes RestController wins over lib plain SharedType");

        var bootResult = new PreAnalysisService().analyze(bootInput);
        check(bootResult.entryCatalog().entries().stream().anyMatch(NestedClasspathMetadataAcceptanceTest::isLibRoute),
                "PreAnalysis discovers MVC route from nested BOOT-INF/lib class");
        check(bootResult.entryCatalog().entries().stream().anyMatch(e ->
                        "GET".equals(e.method()) && "/api/app".equals(e.route())),
                "PreAnalysis still discovers BOOT-INF/classes app route");

        Path war = buildWarWithNestedLib(root, classes);
        PreAnalysisInput warInput = ArtifactMetadataReader.read(registry.register(war));
        check(warInput.classNames().contains("lib.LibController"),
                "WEB-INF/lib nested controller class present");
        check(new PreAnalysisService().analyze(warInput).entryCatalog().entries().stream()
                        .anyMatch(NestedClasspathMetadataAcceptanceTest::isLibRoute),
                "PreAnalysis discovers MVC route from nested WEB-INF/lib class");

        System.out.println("NestedClasspathMetadataAcceptanceTest: PASS");
    }

    private static boolean isLibRoute(Entrypoint entry) {
        return entry != null
                && "GET".equals(entry.method())
                && "/api/lib".equals(entry.route())
                && "lib.LibController".equals(entry.declaringClass());
    }

    private static Path buildBootJarWithNestedLib(
            Path root,
            Path classes,
            byte[] sharedPreferred,
            byte[] sharedFromLib) throws Exception {
        byte[] deepJar = minimalNamedClassJar("buried/DeepClass.class");
        ByteArrayOutputStream nestedLibBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(nestedLibBytes)) {
            for (String relative : List.of(
                    "lib/LibController.class",
                    "lib/Helper.class",
                    "org/springframework/web/bind/annotation/RestController.class",
                    "org/springframework/web/bind/annotation/GetMapping.class",
                    "org/springframework/web/bind/annotation/RequestMapping.class",
                    "org/springframework/stereotype/Controller.class")) {
                putBytes(zos, relative, Files.readAllBytes(classes.resolve(relative)));
            }
            putBytes(zos, "app/SharedType.class", sharedFromLib);
            putBytes(zos, "BOOT-INF/lib/buried-deep.jar", deepJar);
        }

        Path jar = root.resolve("nested-boot.jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            putBytes(zos, "BOOT-INF/classes/app/AppController.class",
                    Files.readAllBytes(classes.resolve("app/AppController.class")));
            putBytes(zos, "BOOT-INF/classes/app/SharedType.class", sharedPreferred);
            for (String ann : List.of(
                    "org/springframework/web/bind/annotation/RestController.class",
                    "org/springframework/web/bind/annotation/GetMapping.class",
                    "org/springframework/web/bind/annotation/RequestMapping.class",
                    "org/springframework/stereotype/Controller.class")) {
                putBytes(zos, "BOOT-INF/classes/" + ann, Files.readAllBytes(classes.resolve(ann)));
            }
            putBytes(zos, "BOOT-INF/lib/lib-controllers.jar", nestedLibBytes.toByteArray());
        }
        return jar;
    }

    private static Path buildWarWithNestedLib(Path root, Path classes) throws Exception {
        ByteArrayOutputStream nestedLibBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(nestedLibBytes)) {
            for (String relative : List.of(
                    "lib/LibController.class",
                    "org/springframework/web/bind/annotation/RestController.class",
                    "org/springframework/web/bind/annotation/GetMapping.class",
                    "org/springframework/web/bind/annotation/RequestMapping.class",
                    "org/springframework/stereotype/Controller.class")) {
                putBytes(zos, relative, Files.readAllBytes(classes.resolve(relative)));
            }
        }
        Path war = root.resolve("nested.war");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(war))) {
            putBytes(zos, "WEB-INF/classes/app/AppController.class",
                    Files.readAllBytes(classes.resolve("app/AppController.class")));
            for (String ann : List.of(
                    "org/springframework/web/bind/annotation/RestController.class",
                    "org/springframework/web/bind/annotation/GetMapping.class",
                    "org/springframework/web/bind/annotation/RequestMapping.class",
                    "org/springframework/stereotype/Controller.class")) {
                putBytes(zos, "WEB-INF/classes/" + ann, Files.readAllBytes(classes.resolve(ann)));
            }
            putBytes(zos, "WEB-INF/lib/lib-controllers.jar", nestedLibBytes.toByteArray());
        }
        return war;
    }

    private static void writeSpringAnnotations(Path root) throws Exception {
        annotation(root, "org.springframework.stereotype.Controller", "TYPE", "");
        annotation(root, "org.springframework.web.bind.annotation.RestController", "TYPE", "");
        annotation(root, "org.springframework.web.bind.annotation.RequestMapping", "TYPE,METHOD",
                "String[] value() default {}; String[] path() default {};");
        annotation(root, "org.springframework.web.bind.annotation.GetMapping", "METHOD",
                "String[] value() default {}; String[] path() default {};");
    }

    private static void writePrimarySources(Path root) throws Exception {
        source(root, "app/AppController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class AppController {
                    @GetMapping("/api/app")
                    public String app() { return "app"; }
                }
                """);
        source(root, "lib/LibController.java", """
                package lib;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class LibController {
                    @GetMapping("/api/lib")
                    public String lib() { return "lib"; }
                }
                """);
        source(root, "lib/Helper.java", "package lib; public class Helper { }\n");
        source(root, "app/SharedType.java", """
                package app;
                import org.springframework.web.bind.annotation.RestController;
                @RestController
                public class SharedType { }
                """);
    }

    private static byte[] minimalNamedClassJar(String entryName) throws Exception {
        byte[] stub = new byte[]{
                (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, 55, 0, 1
        };
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bytes)) {
            putBytes(zos, entryName, stub);
        }
        return bytes.toByteArray();
    }

    private static void putBytes(ZipOutputStream zos, String entryName, byte[] content) throws Exception {
        zos.putNextEntry(new ZipEntry(entryName));
        zos.write(content);
        zos.closeEntry();
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
        for (String target : targets.split(",")) {
            result.add("ElementType." + target.trim());
        }
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

    private static void check(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
        AcceptanceAssertions.record();
        ASSERTIONS.incrementAndGet();
    }
}

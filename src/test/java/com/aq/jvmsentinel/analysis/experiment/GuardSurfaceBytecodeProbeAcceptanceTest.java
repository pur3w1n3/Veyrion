package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.analysis.GuardSurfaceBytecodeProbe;
import com.aq.jvmsentinel.domain.pathdebug.GuardSurface;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Collectors;

/**
 * 有界 bytecode 启发式：调用 StpUtil 的 Filter 成为 GuardSurface 候选。
 */
public final class GuardSurfaceBytecodeProbeAcceptanceTest {
    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        Path root = Files.createTempDirectory("guard-bytecode-probe-");
        try {
            writeSources(root);
            compile(root);
            Path jar = root.resolve("app.jar");
            packJar(root, jar);

            List<GuardSurface> surfaces = GuardSurfaceCatalog.harvest(jar);
            boolean mystery = surfaces.stream().anyMatch(s ->
                    s.typeNames().contains("com.example.app.MysteryWallFilter")
                            && s.decisionShape() == GuardSurface.DecisionShape.FILTER_CHAIN);
            check(mystery, "bytecode heuristic harvests MysteryWallFilter calling StpUtil");

            boolean noXss = surfaces.stream().noneMatch(s ->
                    s.typeNames().stream().anyMatch(t -> t.contains("XssFilter")));
            check(noXss, "bytecode heuristic still excludes XssFilter");

            byte[] mysteryBytes = Files.readAllBytes(
                    root.resolve("com/example/app/MysteryWallFilter.class"));
            GuardSurfaceBytecodeProbe.ProbeMatch match =
                    GuardSurfaceBytecodeProbe.classify(mysteryBytes, "com.example.app.MysteryWallFilter");
            check(match != null, "probe classifies MysteryWallFilter");
            check(match.shape() == GuardSurface.DecisionShape.FILTER_CHAIN,
                    "MysteryWallFilter shape is FILTER_CHAIN");
        } finally {
            deleteRecursive(root);
        }
        System.out.println("GuardSurfaceBytecodeProbeAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static void writeSources(Path root) throws IOException {
        write(root.resolve("javax/servlet/Filter.java"), """
                package javax.servlet;
                public interface Filter {
                    void doFilter(Object request, Object response, Object chain);
                }
                """);
        write(root.resolve("cn/dev33/satoken/stp/StpUtil.java"), """
                package cn.dev33.satoken.stp;
                public final class StpUtil {
                    private StpUtil() {}
                    public static void checkLogin() {}
                }
                """);
        write(root.resolve("com/example/app/MysteryWallFilter.java"), """
                package com.example.app;
                import cn.dev33.satoken.stp.StpUtil;
                import javax.servlet.Filter;
                public class MysteryWallFilter implements Filter {
                    @Override
                    public void doFilter(Object request, Object response, Object chain) {
                        StpUtil.checkLogin();
                    }
                }
                """);
        write(root.resolve("com/example/app/XssFilter.java"), """
                package com.example.app;
                import javax.servlet.Filter;
                public class XssFilter implements Filter {
                    @Override
                    public void doFilter(Object request, Object response, Object chain) {
                        String cleaned = String.valueOf(request).replace("<", "");
                        if (cleaned.isEmpty()) {
                            return;
                        }
                    }
                }
                """);
    }

    private static void compile(Path root) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("JDK javac required (not JRE)");
        }
        List<String> sources;
        try (var walk = Files.walk(root)) {
            sources = walk.filter(p -> p.toString().endsWith(".java"))
                    .map(Path::toString)
                    .collect(Collectors.toList());
        }
        int code = compiler.run(null, null, null,
                sources.toArray(String[]::new));
        if (code != 0) {
            throw new IllegalStateException("javac failed with code " + code);
        }
    }

    private static void packJar(Path root, Path jar) throws IOException {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar));
             var walk = Files.walk(root)) {
            List<Path> classes = walk.filter(p -> p.toString().endsWith(".class")).toList();
            for (Path classFile : classes) {
                String entry = "BOOT-INF/classes/" + root.relativize(classFile).toString().replace('\\', '/');
                jos.putNextEntry(new JarEntry(entry));
                jos.write(Files.readAllBytes(classFile));
                jos.closeEntry();
            }
        }
    }

    private static void write(Path path, String source) throws IOException {
        Files.createDirectories(path.getParent());
        Files.writeString(path, source, StandardCharsets.UTF_8);
    }

    private static void deleteRecursive(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (var walk = Files.walk(root)) {
            List<Path> paths = walk.sorted((a, b) -> b.compareTo(a)).toList();
            for (Path path : paths) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        AcceptanceAssertions.record();
    }
}

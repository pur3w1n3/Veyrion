package com.aq.jvmsentinel;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * P0-14 / P1-08 架构 dependency gate。
 *
 * <ul>
 *   <li>domain must not import control.persistence / ai.tool (exceptions in baseline file)</li>
 *   <li>control / application / adapter must not import analysis.parser (no exceptions)</li>
 * </ul>
 */
public final class ArchitectureBaselineAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final Pattern IMPORT = Pattern.compile(
            "^\\s*import\\s+(static\\s+)?([\\w.]+)\\s*;", Pattern.MULTILINE);
    private static final Set<String> DOMAIN_FORBIDDEN_PREFIXES = Set.of(
            "com.aq.jvmsentinel.control.persistence",
            "com.aq.jvmsentinel.ai.tool");
    private static final String CONTROL_PARSER_FORBIDDEN = "com.aq.jvmsentinel.analysis.parser";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = SchemaContractAcceptanceTest.projectRoot();
        verifyDomainBaseline(root);
        verifyNoControlToAnalysisParser(root);
        System.out.println("ArchitectureBaselineAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void verifyDomainBaseline(Path root) throws Exception {
        Path domain = root.resolve("src/main/java/com/aq/jvmsentinel/domain");
        Path baselineFile = root.resolve("contracts/architecture-baseline.txt");
        check(Files.isDirectory(domain), "domain package directory exists");
        check(Files.isRegularFile(baselineFile), "architecture baseline file exists");

        Set<String> baseline = readBaseline(baselineFile);
        List<String> violations = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(domain)) {
            List<Path> sources = stream
                    .filter(path -> path.toString().endsWith(".java"))
                    .sorted()
                    .toList();
            check(!sources.isEmpty(), "domain contains at least one Java source");
            for (Path source : sources) {
                String relative = root.relativize(source).toString().replace('\\', '/');
                String text = Files.readString(source, StandardCharsets.UTF_8);
                Matcher matcher = IMPORT.matcher(text);
                while (matcher.find()) {
                    String imported = matcher.group(2);
                    if (isForbidden(imported, DOMAIN_FORBIDDEN_PREFIXES)) {
                        violations.add(relative + " -> " + imported);
                    }
                }
            }
        }

        List<String> novel = new ArrayList<>();
        Set<String> observedFiles = new LinkedHashSet<>();
        for (String violation : violations) {
            String file = violation.substring(0, violation.indexOf(" -> "));
            observedFiles.add(file);
            if (!baseline.contains(file)) {
                novel.add(violation);
            }
        }
        for (String allowed : baseline) {
            check(observedFiles.contains(allowed),
                    "baseline entry no longer violates (remove from baseline): " + allowed);
        }
        check(novel.isEmpty(), "new domain architecture violations: " + novel);
        check(true, "architecture baseline enforced (" + baseline.size()
                + " exceptions, " + violations.size() + " current hits)");
    }

    /**
     * P1-08：新代码不得引入 control → analysis.parser 反向依赖。
     * 扫描 control、application、adapter 树；零 exception 允许。
     */
    private static void verifyNoControlToAnalysisParser(Path root) throws Exception {
        List<Path> roots = List.of(
                root.resolve("src/main/java/com/aq/jvmsentinel/control"),
                root.resolve("src/main/java/com/aq/jvmsentinel/application"),
                root.resolve("src/main/java/com/aq/jvmsentinel/adapter"),
                root.resolve("src/main/java/com/aq/jvmsentinel/orchestration"));
        List<String> hits = new ArrayList<>();
        for (Path packageRoot : roots) {
            if (!Files.isDirectory(packageRoot)) {
                continue;
            }
            try (Stream<Path> stream = Files.walk(packageRoot)) {
                List<Path> sources = stream
                        .filter(path -> path.toString().endsWith(".java"))
                        .sorted()
                        .toList();
                for (Path source : sources) {
                    String relative = root.relativize(source).toString().replace('\\', '/');
                    String text = Files.readString(source, StandardCharsets.UTF_8);
                    Matcher matcher = IMPORT.matcher(text);
                    while (matcher.find()) {
                        String imported = matcher.group(2);
                        if (imported.equals(CONTROL_PARSER_FORBIDDEN)
                                || imported.startsWith(CONTROL_PARSER_FORBIDDEN + ".")) {
                            hits.add(relative + " -> " + imported);
                        }
                    }
                }
            }
        }
        check(hits.isEmpty(), "control/application/adapter must not import analysis.parser: " + hits);
        check(true, "control→analysis.parser reverse dependency gate active");
    }

    private static boolean isForbidden(String imported, Set<String> prefixes) {
        for (String prefix : prefixes) {
            if (imported.equals(prefix) || imported.startsWith(prefix + ".")) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> readBaseline(Path path) throws Exception {
        Set<String> lines = new LinkedHashSet<>();
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            lines.add(trimmed.replace('\\', '/'));
        }
        return lines;
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

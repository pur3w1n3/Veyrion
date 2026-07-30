package com.aq.jvmsentinel;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * P0-14：migration 顺序 + pinned checksum 一致性（UTF-8 内容，同 persistence）
 * + Allowed paths matching semantics used by scripts/ci-gates.ps1.
 */
public final class CiGateAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final Pattern MIGRATION_NAME = Pattern.compile("^V(\\d{3})__.+\\.sql$");

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = SchemaContractAcceptanceTest.projectRoot();
        Path migrationDir = root.resolve("src/main/resources/db/migration");
        Path checksumFile = root.resolve("contracts/migration-checksums.txt");
        check(Files.isDirectory(migrationDir), "migration directory exists");
        check(Files.isRegularFile(checksumFile), "migration checksum table exists");

        List<Path> migrations = listMigrations(migrationDir);
        check(!migrations.isEmpty(), "at least one migration present");
        int expected = 1;
        for (Path migration : migrations) {
            String name = migration.getFileName().toString();
            Matcher matcher = MIGRATION_NAME.matcher(name);
            check(matcher.matches(), "migration name well-formed: " + name);
            int version = Integer.parseInt(matcher.group(1));
            check(version == expected, "migration versions contiguous at V"
                    + String.format(Locale.ROOT, "%03d", expected) + " (saw " + name + ")");
            expected++;
        }
        check(migrations.size() >= 23, "migrations include at least V001-V023");

        Map<String, String> pinned = readChecksumTable(checksumFile);
        check(pinned.size() == migrations.size(),
                "checksum table size matches migration file count ("
                        + pinned.size() + " vs " + migrations.size() + ")");

        for (Path migration : migrations) {
            String name = migration.getFileName().toString();
            check(pinned.containsKey(name), "checksum pinned for " + name);
            String actual = sha256Utf8(Files.readString(migration, StandardCharsets.UTF_8));
            check(actual.equals(pinned.get(name)),
                    "checksum mismatch for " + name + " (file rewritten?)");
        }

        // 示例：persistence class 仍按序列出相同 migration resource 名。
        Path persistence = root.resolve(
                "src/main/java/com/aq/jvmsentinel/control/persistence/SQLiteControlPlanePersistence.java");
        check(Files.isRegularFile(persistence), "SQLiteControlPlanePersistence present");
        String persistenceSource = Files.readString(persistence, StandardCharsets.UTF_8);
        for (Path migration : migrations) {
            String resource = "db/migration/" + migration.getFileName();
            check(persistenceSource.contains("\"" + resource + "\""),
                    "persistence MIGRATIONS lists " + resource);
        }

        verifyAllowedPathsGate(root);

        System.out.println("CiGateAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    /**
     * Allowed paths mode：空 changed set → skip OK；allowlist 外 path → fail 语义。
     */
    private static void verifyAllowedPathsGate(Path root) throws Exception {
        Path example = root.resolve("contracts/task-allowed-paths.example.txt");
        check(Files.isRegularFile(example), "contracts/task-allowed-paths.example.txt present");
        List<String> allowed = readAllowedPatterns(example);
        check(!allowed.isEmpty(), "example Allowed paths has patterns");
        check(allowed.stream().anyMatch(p -> p.startsWith("contracts")),
                "example allowlist covers contracts/");

        List<String> emptyDiff = List.of();
        AllowedPathsResult skip = evaluateAllowedPaths(emptyDiff, allowed);
        check(skip.skipped(), "no git diff → Allowed paths skip OK");
        check(skip.violations().isEmpty(), "skip result has no violations");

        List<String> within = List.of(
                "contracts/task-allowed-paths.example.txt",
                "frontend/src/api.ts",
                "docs/MVP_BACKLOG.md");
        AllowedPathsResult ok = evaluateAllowedPaths(within, allowed);
        check(!ok.skipped(), "non-empty diff is audited");
        check(ok.violations().isEmpty(), "in-allowlist paths pass");

        List<String> violated = List.of(
                "frontend/src/api.ts",
                "src/main/java/com/aq/jvmsentinel/Evil.java");
        AllowedPathsResult fail = evaluateAllowedPaths(violated, allowed);
        check(!fail.skipped(), "violating diff is not skipped");
        check(fail.violations().contains("src/main/java/com/aq/jvmsentinel/Evil.java"),
                "out-of-allowlist path reported");
        check(!fail.violations().contains("frontend/src/api.ts"),
                "in-allowlist path not reported as violation");

        Path script = root.resolve("scripts/ci-gates.ps1");
        check(Files.isRegularFile(script), "ci-gates.ps1 present");
        String scriptText = Files.readString(script, StandardCharsets.UTF_8);
        check(scriptText.contains("SkipAllowedPaths"), "ci-gates documents -SkipAllowedPaths");
        check(scriptText.contains("task-allowed-paths.example.txt"),
                "ci-gates defaults to example Allowed paths file");
        check(scriptText.toLowerCase(Locale.ROOT).contains("default"),
                "ci-gates documents Allowed paths as default-enabled");
    }

    static AllowedPathsResult evaluateAllowedPaths(List<String> changedPaths, List<String> allowed) {
        List<String> normalized = changedPaths == null ? List.of() : changedPaths.stream()
                .filter(path -> path != null && !path.isBlank())
                .map(path -> path.replace('\\', '/'))
                .distinct()
                .toList();
        if (normalized.isEmpty()) {
            return new AllowedPathsResult(true, List.of());
        }
        List<String> violations = new ArrayList<>();
        for (String path : normalized) {
            if (!isPathAllowed(path, allowed)) {
                violations.add(path);
            }
        }
        return new AllowedPathsResult(false, List.copyOf(violations));
    }

    static boolean isPathAllowed(String path, List<String> allowedPatterns) {
        String normalized = path.replace('\\', '/');
        for (String pattern : allowedPatterns) {
            String glob = pattern.replace('\\', '/');
            if (glob.endsWith("/**")) {
                String prefix = glob.substring(0, glob.length() - 2);
                if (normalized.startsWith(prefix)) {
                    return true;
                }
            } else if (normalized.equals(glob)
                    || normalized.startsWith(glob.replaceAll("\\*+$", ""))) {
                return true;
            }
        }
        return false;
    }

    private static List<String> readAllowedPatterns(Path path) throws Exception {
        List<String> patterns = new ArrayList<>();
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            patterns.add(trimmed);
        }
        return List.copyOf(patterns);
    }

    record AllowedPathsResult(boolean skipped, List<String> violations) {
        AllowedPathsResult {
            violations = List.copyOf(violations == null ? List.of() : violations);
        }
    }

    private static List<Path> listMigrations(Path dir) throws Exception {
        try (Stream<Path> stream = Files.list(dir)) {
            return stream
                    .filter(path -> MIGRATION_NAME.matcher(path.getFileName().toString()).matches())
                    .sorted()
                    .toList();
        }
    }

    private static Map<String, String> readChecksumTable(Path path) throws Exception {
        Map<String, String> table = new LinkedHashMap<>();
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            String[] parts = trimmed.split("\\s+", 2);
            check(parts.length == 2, "checksum line well-formed: " + trimmed);
            table.put(parts[1].trim(), parts[0].trim().toLowerCase(Locale.ROOT));
        }
        return table;
    }

    private static String sha256Utf8(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

package com.aq.jvmsentinel.analysis.recall;

import com.aq.jvmsentinel.control.JsonCodec;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * P0-15：可选开源 practical recall sample。
 * Artifact 永不 vendored；local digest 可选。无 local JAR 时，
 * scoring 返回 {@code NOT_EVALUABLE}，不得声称 production recall。
 */
public final class PracticalRecallSampleCatalog {
    public static final String BASELINE_RESOURCE = "/baselines/p0-15-practical-oss-samples.json";
    public static final String NOT_EVALUABLE = "NOT_EVALUABLE";
    public static final String SCORED = "SCORED";

    private PracticalRecallSampleCatalog() {
    }

    public record Sample(
            String sampleId,
            String kind,
            String role,
            String displayName,
            String license,
            String repositoryUrl,
            String ref,
            String buildHint,
            String artifactGlob,
            String startupProfile,
            List<String> expectedEntries,
            List<String> expectedSinkFamilies,
            List<String> knownVulnFamilies,
            List<String> knownGaps,
            boolean multiAuth,
            String notes
    ) {
        public Sample {
            Objects.requireNonNull(sampleId, "sampleId");
            expectedEntries = List.copyOf(expectedEntries == null ? List.of() : expectedEntries);
            expectedSinkFamilies = List.copyOf(expectedSinkFamilies == null ? List.of() : expectedSinkFamilies);
            knownVulnFamilies = List.copyOf(knownVulnFamilies == null ? List.of() : knownVulnFamilies);
            knownGaps = List.copyOf(knownGaps == null ? List.of() : knownGaps);
            kind = kind == null ? "" : kind;
            role = role == null ? "" : role;
            displayName = displayName == null ? sampleId : displayName;
            license = license == null ? "" : license;
            repositoryUrl = repositoryUrl == null ? "" : repositoryUrl;
            ref = ref == null ? "" : ref;
            buildHint = buildHint == null ? "" : buildHint;
            artifactGlob = artifactGlob == null ? "" : artifactGlob;
            startupProfile = startupProfile == null ? "" : startupProfile;
            notes = notes == null ? "" : notes;
        }
    }

    public record Catalog(
            int schemaVersion,
            String baselineId,
            String disclaimer,
            double maxInvalidPathRunRatio,
            double minStaticSinkRecall,
            List<Sample> samples
    ) {
        public Catalog {
            samples = List.copyOf(samples == null ? List.of() : samples);
            disclaimer = disclaimer == null ? "" : disclaimer;
            if (maxInvalidPathRunRatio < 0 || maxInvalidPathRunRatio > 1) {
                throw new IllegalArgumentException("maxInvalidPathRunRatio out of range");
            }
            if (minStaticSinkRecall < 0 || minStaticSinkRecall > 1) {
                throw new IllegalArgumentException("minStaticSinkRecall out of range");
            }
        }
    }

    public record Observation(
            Set<String> observedEntries,
            Set<String> observedSinkFamilies,
            int pathRunTotal,
            int invalidPathRuns,
            boolean artifactPresent,
            String artifactDigest
    ) {
        public Observation {
            observedEntries = Set.copyOf(observedEntries == null ? Set.of() : observedEntries);
            observedSinkFamilies = normalizeUpper(observedSinkFamilies);
            artifactDigest = artifactDigest == null ? "" : artifactDigest.trim().toLowerCase(Locale.ROOT);
        }
    }

    public record SampleScore(
            String sampleId,
            String evaluability,
            int entryTp,
            int entryFn,
            int entryFp,
            double entryRecall,
            int sinkTp,
            int sinkFn,
            double sinkRecall,
            double invalidPathRunRatio,
            boolean invalidPathRunGatePassed,
            boolean staticSinkGatePassed,
            List<String> missingEntries,
            List<String> missingSinkFamilies,
            List<String> knownGaps
    ) {
        public SampleScore {
            missingEntries = List.copyOf(missingEntries == null ? List.of() : missingEntries);
            missingSinkFamilies = List.copyOf(missingSinkFamilies == null ? List.of() : missingSinkFamilies);
            knownGaps = List.copyOf(knownGaps == null ? List.of() : knownGaps);
        }
    }

    public record Report(Catalog catalog, List<SampleScore> scores, List<String> failures) {
        public Report {
            scores = List.copyOf(scores == null ? List.of() : scores);
            failures = List.copyOf(failures == null ? List.of() : failures);
        }

        public boolean passed() {
            return failures.isEmpty();
        }
    }

    public static Catalog loadDefault() {
        try (InputStream in = PracticalRecallSampleCatalog.class.getResourceAsStream(BASELINE_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("missing classpath resource " + BASELINE_RESOURCE);
            }
            return parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException failure) {
            throw new IllegalStateException("failed to load " + BASELINE_RESOURCE, failure);
        }
    }

    public static Catalog parse(String json) {
        Map<String, Object> root = JsonCodec.parseObject(json);
        int schemaVersion = intValue(root.get("schemaVersion"), 0);
        if (schemaVersion < 1) {
            throw new IllegalArgumentException("schemaVersion must be >= 1");
        }
        List<Sample> samples = new ArrayList<>();
        Object rawSamples = root.get("samples");
        if (!(rawSamples instanceof List<?> list) || list.isEmpty()) {
            throw new IllegalArgumentException("samples must be a non-empty array");
        }
        for (Object row : list) {
            if (!(row instanceof Map<?, ?> map)) {
                throw new IllegalArgumentException("sample row must be an object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> sample = (Map<String, Object>) map;
            samples.add(new Sample(
                    text(sample.get("sampleId")),
                    text(sample.get("kind")),
                    text(sample.get("role")),
                    text(sample.get("displayName")),
                    text(sample.get("license")),
                    text(sample.get("repositoryUrl")),
                    text(sample.get("ref")),
                    text(sample.get("buildHint")),
                    text(sample.get("artifactGlob")),
                    text(sample.get("startupProfile")),
                    stringList(sample.get("expectedEntries")),
                    stringList(sample.get("expectedSinkFamilies")),
                    stringList(sample.get("knownVulnFamilies")),
                    stringList(sample.get("knownGaps")),
                    Boolean.TRUE.equals(sample.get("multiAuth"))
                            || "true".equalsIgnoreCase(text(sample.get("multiAuth"))),
                    text(sample.get("notes"))
            ));
        }
        return new Catalog(
                schemaVersion,
                text(root.get("baselineId")),
                text(root.get("disclaimer")),
                doubleValue(root.get("maxInvalidPathRunRatio"), 0.05),
                doubleValue(root.get("minStaticSinkRecall"), 0.5),
                samples
        );
    }

    public static SampleScore score(Sample sample, Observation observation, Catalog catalog) {
        Objects.requireNonNull(sample, "sample");
        Objects.requireNonNull(observation, "observation");
        Objects.requireNonNull(catalog, "catalog");
        if (!observation.artifactPresent()) {
            return new SampleScore(
                    sample.sampleId(), NOT_EVALUABLE,
                    0, sample.expectedEntries().size(), 0, 0.0,
                    0, sample.expectedSinkFamilies().size(), 0.0,
                    0.0, true, true,
                    sample.expectedEntries(), sample.expectedSinkFamilies(), sample.knownGaps());
        }
        Set<String> expectedEntries = normalizeRoutes(sample.expectedEntries());
        Set<String> observedEntries = normalizeRoutes(observation.observedEntries());
        Set<String> tpEntries = intersect(expectedEntries, observedEntries);
        Set<String> missingEntries = diff(expectedEntries, observedEntries);
        Set<String> extras = diff(observedEntries, expectedEntries);

        Set<String> expectedSinks = normalizeUpper(new LinkedHashSet<>(sample.expectedSinkFamilies()));
        Set<String> observedSinks = observation.observedSinkFamilies();
        Set<String> tpSinks = intersect(expectedSinks, observedSinks);
        Set<String> missingSinks = diff(expectedSinks, observedSinks);

        double entryRecall = expectedEntries.isEmpty()
                ? 1.0 : (double) tpEntries.size() / expectedEntries.size();
        double sinkRecall = expectedSinks.isEmpty()
                ? 1.0 : (double) tpSinks.size() / expectedSinks.size();
        double invalidRatio = observation.pathRunTotal() <= 0
                ? 0.0
                : (double) observation.invalidPathRuns() / (double) observation.pathRunTotal();
        boolean invalidOk = invalidRatio <= catalog.maxInvalidPathRunRatio();
        boolean sinkOk = sinkRecall + 1e-9 >= catalog.minStaticSinkRecall();
        return new SampleScore(
                sample.sampleId(), SCORED,
                tpEntries.size(), missingEntries.size(), extras.size(), entryRecall,
                tpSinks.size(), missingSinks.size(), sinkRecall,
                invalidRatio, invalidOk, sinkOk,
                List.copyOf(missingEntries), List.copyOf(missingSinks), sample.knownGaps());
    }

    public static Report evaluate(Catalog catalog, Map<String, Observation> observationsBySample) {
        Objects.requireNonNull(catalog, "catalog");
        Map<String, Observation> observed = observationsBySample == null
                ? Map.of() : observationsBySample;
        List<SampleScore> scores = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        validateCatalogShape(catalog, failures);
        int boot = 0;
        int bladeOrFlowable = 0;
        int multiAuth = 0;
        for (Sample sample : catalog.samples()) {
            if (sample.kind().toUpperCase(Locale.ROOT).contains("BOOT")
                    || "SPRING_BOOT".equalsIgnoreCase(sample.kind())) {
                boot++;
            }
            if (sample.kind().toUpperCase(Locale.ROOT).contains("BLADE")
                    || sample.kind().toUpperCase(Locale.ROOT).contains("FLOWABLE")) {
                bladeOrFlowable++;
            }
            if (sample.multiAuth()) multiAuth++;
            SampleScore score = score(sample, observed.getOrDefault(sample.sampleId(),
                    new Observation(Set.of(), Set.of(), 0, 0, false, "")), catalog);
            scores.add(score);
            if (SCORED.equals(score.evaluability())) {
                if (!score.invalidPathRunGatePassed()) {
                    failures.add(sample.sampleId() + ": invalid PathRun ratio "
                            + score.invalidPathRunRatio() + " exceeds "
                            + catalog.maxInvalidPathRunRatio());
                }
                if (!score.staticSinkGatePassed()) {
                    failures.add(sample.sampleId() + ": static sink recall "
                            + score.sinkRecall() + " below " + catalog.minStaticSinkRecall());
                }
            }
        }
        if (catalog.samples().size() < 3) {
            failures.add("catalog requires at least 3 selectable samples");
        }
        if (boot < 2) {
            failures.add("catalog requires at least 2 Spring Boot samples");
        }
        if (bladeOrFlowable < 1) {
            failures.add("catalog requires at least 1 Blade or Flowable sample");
        }
        if (multiAuth < 1) {
            failures.add("catalog requires at least 1 multi-auth sample");
        }
        return new Report(catalog, scores, failures);
    }

    /**
     * 在 samples root 目录下解析可选 local artifact。
     * 优先 {@link Sample#artifactGlob()} 匹配，跳过 wrapper/sources/javadoc jar，
     * 优先 {@code target/} 下更大 bootable jar，path 打破平局。
     */
    public static Path resolveLocalArtifact(Path samplesRoot, Sample sample) {
        if (samplesRoot == null || sample == null) return null;
        Path sampleDir = samplesRoot.resolve(sample.sampleId());
        if (!Files.isDirectory(sampleDir)) return null;
        try (var stream = Files.walk(sampleDir, 8)) {
            List<Path> candidates = stream
                    .filter(Files::isRegularFile)
                    .filter(path -> isCandidateJar(path.getFileName().toString()))
                    .collect(Collectors.toCollection(ArrayList::new));
            if (candidates.isEmpty()) return null;

            String glob = sample.artifactGlob();
            List<Path> preferred = candidates;
            if (glob != null && !glob.isBlank()) {
                List<Path> matched = candidates.stream()
                        .filter(path -> matchesArtifactGlob(sampleDir, path, glob))
                        .collect(Collectors.toCollection(ArrayList::new));
                if (!matched.isEmpty()) {
                    preferred = matched;
                }
            }
            return preferred.stream()
                    .max(artifactPreference(sampleDir))
                    .orElse(null);
        } catch (IOException ignored) {
            return null;
        }
    }

    static boolean isCandidateJar(String fileName) {
        if (fileName == null) return false;
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (!lower.endsWith(".jar")) return false;
        if (lower.endsWith("-sources.jar") || lower.endsWith("-javadoc.jar")) return false;
        if (lower.endsWith("-wrapper.jar")) return false;
        if (lower.contains("gradle-wrapper") || lower.contains("maven-wrapper")) return false;
        return true;
    }

    static boolean matchesArtifactGlob(Path sampleDir, Path jar, String globPattern) {
        if (sampleDir == null || jar == null || globPattern == null || globPattern.isBlank()) {
            return false;
        }
        String relative = sampleDir.relativize(jar).toString().replace('\\', '/');
        String pattern = globPattern.replace('\\', '/');
        PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + pattern);
        Path relativePath = Path.of(relative);
        return matcher.matches(relativePath) || matcher.matches(jar.getFileName());
    }

    private static Comparator<Path> artifactPreference(Path sampleDir) {
        return Comparator
                .comparingInt((Path path) -> underTargetDirectory(sampleDir, path) ? 1 : 0)
                .thenComparingLong(PracticalRecallSampleCatalog::safeSize)
                .thenComparing(path -> sampleDir.relativize(path).toString().replace('\\', '/'));
    }

    private static boolean underTargetDirectory(Path sampleDir, Path jar) {
        Path relative = sampleDir.relativize(jar);
        for (Path part : relative) {
            if ("target".equals(part.toString())) return true;
        }
        return false;
    }

    private static long safeSize(Path path) {
        try {
            return Files.size(path);
        } catch (IOException ignored) {
            return 0L;
        }
    }

    private static void validateCatalogShape(Catalog catalog, List<String> failures) {
        Set<String> ids = new LinkedHashSet<>();
        for (Sample sample : catalog.samples()) {
            if (sample.sampleId().isBlank()) {
                failures.add("blank sampleId");
                continue;
            }
            if (!ids.add(sample.sampleId())) {
                failures.add("duplicate sampleId " + sample.sampleId());
            }
            if (sample.repositoryUrl().isBlank() || !sample.repositoryUrl().startsWith("https://")) {
                failures.add(sample.sampleId() + ": repositoryUrl must be https");
            }
            if (sample.expectedEntries().isEmpty() && sample.expectedSinkFamilies().isEmpty()) {
                failures.add(sample.sampleId() + ": expectedEntries or expectedSinkFamilies required");
            }
        }
        if (catalog.disclaimer().isBlank() || !catalog.disclaimer().toUpperCase(Locale.ROOT)
                .contains("NOT")) {
            failures.add("disclaimer must state NOT evaluable/production limits");
        }
    }

    private static Set<String> normalizeRoutes(Iterable<String> routes) {
        Set<String> out = new LinkedHashSet<>();
        if (routes == null) return out;
        for (String route : routes) {
            if (route == null || route.isBlank()) continue;
            out.add(route.trim().replaceAll("\\s+", " ").toUpperCase(Locale.ROOT));
        }
        return out;
    }

    private static Set<String> normalizeUpper(Iterable<String> values) {
        Set<String> out = new LinkedHashSet<>();
        if (values == null) return out;
        for (String value : values) {
            if (value == null || value.isBlank()) continue;
            out.add(value.trim().toUpperCase(Locale.ROOT));
        }
        return out;
    }

    private static Set<String> intersect(Set<String> left, Set<String> right) {
        Set<String> out = new LinkedHashSet<>(left);
        out.retainAll(right);
        return out;
    }

    private static Set<String> diff(Set<String> left, Set<String> right) {
        Set<String> out = new LinkedHashSet<>(left);
        out.removeAll(right);
        return out;
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof List<?> list)) return List.of();
        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (item != null && !item.toString().isBlank()) out.add(item.toString().trim());
        }
        return out;
    }

    private static String text(Object value) {
        return value == null ? "" : value.toString().trim();
    }

    private static int intValue(Object value, int fallback) {
        if (value instanceof Number number) return number.intValue();
        if (value == null) return fallback;
        try {
            return Integer.parseInt(value.toString().trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static double doubleValue(Object value, double fallback) {
        if (value instanceof Number number) return number.doubleValue();
        if (value == null) return fallback;
        try {
            return Double.parseDouble(value.toString().trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    public static Map<String, Object> reportToMap(Report report) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("baselineId", report.catalog().baselineId());
        map.put("passed", report.passed());
        map.put("disclaimer", report.catalog().disclaimer());
        map.put("failures", report.failures());
        List<Map<String, Object>> scores = new ArrayList<>();
        for (SampleScore score : report.scores()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sampleId", score.sampleId());
            row.put("evaluability", score.evaluability());
            row.put("entryRecall", score.entryRecall());
            row.put("sinkRecall", score.sinkRecall());
            row.put("invalidPathRunRatio", score.invalidPathRunRatio());
            row.put("missingEntries", score.missingEntries());
            row.put("missingSinkFamilies", score.missingSinkFamilies());
            scores.add(row);
        }
        map.put("scores", scores);
        return map;
    }
}

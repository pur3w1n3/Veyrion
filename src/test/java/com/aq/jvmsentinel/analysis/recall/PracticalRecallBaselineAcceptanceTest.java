package com.aq.jvmsentinel.analysis.recall;

import com.aq.jvmsentinel.AcceptanceAssertions;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-15：开源可选 practical recall catalog + metrics gate。
 * Local JAR 可选；无则 score 为 NOT_EVALUABLE（非 production recall 声称）。
 */
public final class PracticalRecallBaselineAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        catalogShapeAndRoles();
        notEvaluableWithoutArtifact();
        prefersFatJarOverGradleWrapper();
        scoredGateWithSyntheticObservation();
        invalidPathRunRatioFailsWhenScored();
        System.out.println("PracticalRecallBaselineAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void catalogShapeAndRoles() {
        PracticalRecallSampleCatalog.Catalog catalog = PracticalRecallSampleCatalog.loadDefault();
        check(catalog.samples().size() >= 3, "≥3 selectable OSS samples");
        check(catalog.samples().stream().anyMatch(s -> "spring-petclinic".equals(s.sampleId())),
                "includes spring-petclinic");
        PracticalRecallSampleCatalog.Sample webgoat = catalog.samples().stream()
                .filter(s -> "webgoat".equals(s.sampleId()))
                .findFirst()
                .orElseThrow();
        check("v2023.8".equals(webgoat.ref()), "webgoat pinned to v2023.8 for Java 17/21");
        check(catalog.samples().stream().anyMatch(s -> "springblade".equals(s.sampleId())),
                "includes springblade");
        check(catalog.samples().stream().filter(PracticalRecallSampleCatalog.Sample::multiAuth).count() >= 1,
                "includes multi-auth sample");
        check(catalog.samples().stream().anyMatch(s -> s.kind().toUpperCase().contains("BLADE")),
                "includes Blade sample");
        PracticalRecallSampleCatalog.Report report =
                PracticalRecallSampleCatalog.evaluate(catalog, Map.of());
        check(report.passed(), "catalog shape gate passes without local jars: " + report.failures());
        check(report.scores().stream().allMatch(s ->
                        PracticalRecallSampleCatalog.NOT_EVALUABLE.equals(s.evaluability())),
                "without artifacts all scores are NOT_EVALUABLE");
    }

    private static void notEvaluableWithoutArtifact() {
        PracticalRecallSampleCatalog.Catalog catalog = PracticalRecallSampleCatalog.loadDefault();
        PracticalRecallSampleCatalog.Sample pet = catalog.samples().stream()
                .filter(s -> "spring-petclinic".equals(s.sampleId()))
                .findFirst()
                .orElseThrow();
        Path missing = PracticalRecallSampleCatalog.resolveLocalArtifact(
                Path.of("samples", "practical-oss-absent-for-test"), pet);
        check(missing == null, "missing samples root yields null artifact");
        PracticalRecallSampleCatalog.SampleScore score = PracticalRecallSampleCatalog.score(
                pet,
                new PracticalRecallSampleCatalog.Observation(Set.of(), Set.of(), 0, 0, false, ""),
                catalog);
        check(PracticalRecallSampleCatalog.NOT_EVALUABLE.equals(score.evaluability()),
                "missing artifact is NOT_EVALUABLE");
        check(score.staticSinkGatePassed(), "NOT_EVALUABLE does not fail sink gate");
    }

    private static void prefersFatJarOverGradleWrapper() throws IOException {
        PracticalRecallSampleCatalog.Catalog catalog = PracticalRecallSampleCatalog.loadDefault();
        PracticalRecallSampleCatalog.Sample pet = catalog.samples().stream()
                .filter(s -> "spring-petclinic".equals(s.sampleId()))
                .findFirst()
                .orElseThrow();
        Path root = Files.createTempDirectory("practical-recall-resolve-");
        try {
            Path sampleDir = root.resolve(pet.sampleId());
            Path wrapper = sampleDir.resolve("gradle").resolve("wrapper").resolve("gradle-wrapper.jar");
            Path fatJar = sampleDir.resolve("target")
                    .resolve("spring-petclinic-4.0.0-SNAPSHOT.jar");
            Files.createDirectories(wrapper.getParent());
            Files.createDirectories(fatJar.getParent());
            Files.write(wrapper, new byte[64]);
            Files.write(fatJar, new byte[256 * 1024]);

            check(!PracticalRecallSampleCatalog.isCandidateJar("gradle-wrapper.jar"),
                    "gradle-wrapper.jar is excluded");
            Path resolved = PracticalRecallSampleCatalog.resolveLocalArtifact(root, pet);
            check(resolved != null, "resolves a jar when fat jar exists");
            check(fatJar.toAbsolutePath().normalize().equals(resolved.toAbsolutePath().normalize()),
                    "prefers target fat jar over gradle-wrapper.jar: " + resolved);
        } finally {
            deleteRecursively(root);
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (root == null || !Files.exists(root)) return;
        try (var walk = Files.walk(root)) {
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ignored) {
                            // 尽力 cleanup
                        }
                    });
        }
    }

    private static void scoredGateWithSyntheticObservation() {
        PracticalRecallSampleCatalog.Catalog catalog = PracticalRecallSampleCatalog.loadDefault();
        PracticalRecallSampleCatalog.Sample pet = catalog.samples().stream()
                .filter(s -> "spring-petclinic".equals(s.sampleId()))
                .findFirst()
                .orElseThrow();
        Map<String, PracticalRecallSampleCatalog.Observation> observations = new LinkedHashMap<>();
        observations.put(pet.sampleId(), new PracticalRecallSampleCatalog.Observation(
                Set.copyOf(pet.expectedEntries()),
                Set.copyOf(pet.expectedSinkFamilies()),
                20, 0, true, "a".repeat(64)));
        PracticalRecallSampleCatalog.Report report =
                PracticalRecallSampleCatalog.evaluate(catalog, observations);
        PracticalRecallSampleCatalog.SampleScore petScore = report.scores().stream()
                .filter(s -> pet.sampleId().equals(s.sampleId()))
                .findFirst()
                .orElseThrow();
        check(PracticalRecallSampleCatalog.SCORED.equals(petScore.evaluability()), "petclinic scored");
        check(petScore.entryRecall() >= 0.99, "full entry recall on synthetic observation");
        check(petScore.sinkRecall() >= 0.99, "full sink recall on synthetic observation");
        check(petScore.invalidPathRunGatePassed(), "zero invalid PathRuns passes ratio gate");
        check(report.passed(), "mixed NOT_EVALUABLE + one SCORED still passes catalog shape");
    }

    private static void invalidPathRunRatioFailsWhenScored() {
        PracticalRecallSampleCatalog.Catalog catalog = PracticalRecallSampleCatalog.loadDefault();
        PracticalRecallSampleCatalog.Sample goat = catalog.samples().stream()
                .filter(s -> "webgoat".equals(s.sampleId()))
                .findFirst()
                .orElseThrow();
        Map<String, PracticalRecallSampleCatalog.Observation> observations = Map.of(
                goat.sampleId(), new PracticalRecallSampleCatalog.Observation(
                        Set.copyOf(goat.expectedEntries()),
                        Set.copyOf(goat.expectedSinkFamilies()),
                        100, 90, true, "b".repeat(64)));
        PracticalRecallSampleCatalog.Report report =
                PracticalRecallSampleCatalog.evaluate(catalog, observations);
        check(!report.passed(), "90% invalid PathRuns must fail scored gate");
        check(report.failures().stream().anyMatch(f -> f.contains("invalid PathRun")),
                "failure mentions invalid PathRun ratio");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

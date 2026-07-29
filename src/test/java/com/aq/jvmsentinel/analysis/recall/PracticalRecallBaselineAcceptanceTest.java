package com.aq.jvmsentinel.analysis.recall;

import com.aq.jvmsentinel.AcceptanceAssertions;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-15: open-source selectable practical recall catalog + metrics gate.
 * Local JARs are optional; without them scores are NOT_EVALUABLE (not a production recall claim).
 */
public final class PracticalRecallBaselineAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        catalogShapeAndRoles();
        notEvaluableWithoutArtifact();
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
        check(catalog.samples().stream().anyMatch(s -> "webgoat".equals(s.sampleId())),
                "includes webgoat");
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
                Path.of("samples", "practical-oss"), pet);
        check(missing == null, "default tree has no vendored petclinic jar");
        PracticalRecallSampleCatalog.SampleScore score = PracticalRecallSampleCatalog.score(
                pet,
                new PracticalRecallSampleCatalog.Observation(Set.of(), Set.of(), 0, 0, false, ""),
                catalog);
        check(PracticalRecallSampleCatalog.NOT_EVALUABLE.equals(score.evaluability()),
                "missing artifact is NOT_EVALUABLE");
        check(score.staticSinkGatePassed(), "NOT_EVALUABLE does not fail sink gate");
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

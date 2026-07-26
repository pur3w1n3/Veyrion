package com.aq.jvmsentinel.analysis.recall;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Synthetic multi-fixture static entry recall table for Spring / Blade annotation shapes.
 * This is a development baseline, not a production recall claim. 5/5 fixture scores must
 * never be marketed as real-world recall.
 */
public final class StaticEntryRecallBaseline {
    public record FixtureExpectation(String fixtureId, String frameworkNote,
                                     Set<String> expectedMethodRoutes,
                                     Set<String> knownGaps) {
        public FixtureExpectation {
            Objects.requireNonNull(fixtureId, "fixtureId");
            frameworkNote = frameworkNote == null ? "" : frameworkNote;
            expectedMethodRoutes = Set.copyOf(expectedMethodRoutes == null ? Set.of() : expectedMethodRoutes);
            knownGaps = Set.copyOf(knownGaps == null ? Set.of() : knownGaps);
        }
    }

    public record Score(String fixtureId, int expected, int observed, int truePositives,
                        int falsePositives, int falseNegatives, double recall, double precision,
                        List<String> missing, List<String> extras, List<String> knownGaps) {
        public Score {
            missing = List.copyOf(missing == null ? List.of() : missing);
            extras = List.copyOf(extras == null ? List.of() : extras);
            knownGaps = List.copyOf(knownGaps == null ? List.of() : knownGaps);
        }
    }

    public record Report(List<Score> scores, String disclaimer) {
        public Report {
            scores = List.copyOf(scores == null ? List.of() : scores);
            disclaimer = disclaimer == null ? "" : disclaimer;
        }
    }

    private StaticEntryRecallBaseline() { }

    public static List<FixtureExpectation> catalog() {
        return List.of(
                new FixtureExpectation(
                        "spring-mvc-direct",
                        "Spring MVC direct @RequestMapping / GetMapping (synthetic)",
                        Set.of(
                                "GET /api/orders",
                                "GET /api/orders-alt",
                                "POST /api/orders",
                                "PUT /api/item/{id}",
                                "DELETE /api/item/{id}"),
                        Set.of("composed meta-annotations", "interface-inherited mappings")),
                new FixtureExpectation(
                        "blade-preauth-surface",
                        "Blade-style routes with @PreAuth alignment (synthetic gap list)",
                        Set.of(
                                "GET /blade-auth/user",
                                "POST /blade-auth/admin"),
                        Set.of("custom Blade Secure registry", "runtime route registration")),
                new FixtureExpectation(
                        "spring-composed-gap",
                        "Documents composed/meta-annotation gap (expected empty static hit)",
                        Set.of(),
                        Set.of("@GetMapping composed custom alias", "inheritance from base controller")));
    }

    public static Score score(FixtureExpectation expectation, Set<String> observedMethodRoutes) {
        Objects.requireNonNull(expectation, "expectation");
        Set<String> observed = observedMethodRoutes == null ? Set.of() : Set.copyOf(observedMethodRoutes);
        Set<String> expected = expectation.expectedMethodRoutes();
        Set<String> tp = new LinkedHashSet<>(expected);
        tp.retainAll(observed);
        Set<String> missing = new LinkedHashSet<>(expected);
        missing.removeAll(observed);
        Set<String> extras = new LinkedHashSet<>(observed);
        extras.removeAll(expected);
        int truePositives = tp.size();
        int falseNegatives = missing.size();
        int falsePositives = extras.size();
        double recall = expected.isEmpty() ? 1.0 : (double) truePositives / expected.size();
        double precision = observed.isEmpty()
                ? (expected.isEmpty() ? 1.0 : 0.0)
                : (double) truePositives / observed.size();
        return new Score(
                expectation.fixtureId(),
                expected.size(),
                observed.size(),
                truePositives,
                falsePositives,
                falseNegatives,
                recall,
                precision,
                List.copyOf(missing),
                List.copyOf(extras),
                List.copyOf(expectation.knownGaps()));
    }

    public static Report report(Map<String, Set<String>> observedByFixture) {
        List<Score> scores = new java.util.ArrayList<>();
        Map<String, Set<String>> observed = observedByFixture == null
                ? Map.of() : new LinkedHashMap<>(observedByFixture);
        for (FixtureExpectation expectation : catalog()) {
            scores.add(score(expectation, observed.getOrDefault(expectation.fixtureId(), Set.of())));
        }
        return new Report(scores,
                "SYNTHETIC_BASELINE_ONLY: do not claim production recall from fixture scores.");
    }
}

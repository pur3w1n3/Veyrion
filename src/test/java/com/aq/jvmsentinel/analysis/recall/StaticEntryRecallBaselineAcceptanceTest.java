package com.aq.jvmsentinel.analysis.recall;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * P1-04：合成 static entry recall baseline — 分数仅 development，非 production recall。
 */
public final class StaticEntryRecallBaselineAcceptanceTest {
    public static void main(String[] args) {
        catalogDocumentsKnownGaps();
        perfectFixtureScoreStillCarriesDisclaimer();
        composedGapFixtureDocumentsMiss();
        System.out.println("StaticEntryRecallBaselineAcceptanceTest: PASS");
    }

    private static void catalogDocumentsKnownGaps() {
        check(StaticEntryRecallBaseline.catalog().size() >= 3, "catalog has ≥3 synthetic fixtures");
        boolean hasComposedGap = StaticEntryRecallBaseline.catalog().stream()
                .anyMatch(item -> item.fixtureId().contains("composed") && !item.knownGaps().isEmpty());
        check(hasComposedGap, "composed/inheritance gaps are documented");
    }

    private static void perfectFixtureScoreStillCarriesDisclaimer() {
        Map<String, Set<String>> observed = new LinkedHashMap<>();
        for (StaticEntryRecallBaseline.FixtureExpectation expectation : StaticEntryRecallBaseline.catalog()) {
            if ("spring-mvc-direct".equals(expectation.fixtureId())) {
                observed.put(expectation.fixtureId(), expectation.expectedMethodRoutes());
            } else {
                observed.put(expectation.fixtureId(), Set.of());
            }
        }
        StaticEntryRecallBaseline.Report report = StaticEntryRecallBaseline.report(observed);
        check(report.disclaimer().contains("SYNTHETIC_BASELINE_ONLY"),
                "disclaimer forbids production recall claims");
        StaticEntryRecallBaseline.Score spring = report.scores().stream()
                .filter(score -> "spring-mvc-direct".equals(score.fixtureId()))
                .findFirst()
                .orElseThrow();
        check(spring.recall() == 1.0 && spring.falseNegatives() == 0,
                "synthetic perfect score allowed for fixture");
        check(report.disclaimer().toLowerCase().contains("production"),
                "disclaimer must mention production");
    }

    private static void composedGapFixtureDocumentsMiss() {
        StaticEntryRecallBaseline.FixtureExpectation composed = StaticEntryRecallBaseline.catalog().stream()
                .filter(item -> "spring-composed-gap".equals(item.fixtureId()))
                .findFirst()
                .orElseThrow();
        check(composed.expectedMethodRoutes().isEmpty(),
                "composed-gap fixture expects empty static hits by design");
        check(!composed.knownGaps().isEmpty(), "composed-gap lists known annotation gaps");
        StaticEntryRecallBaseline.Score score = StaticEntryRecallBaseline.score(composed, Set.of());
        check(score.recall() == 1.0, "empty expected → recall 1.0 (gap documentation, not marketing)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

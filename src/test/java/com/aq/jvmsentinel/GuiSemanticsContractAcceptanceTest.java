package com.aq.jvmsentinel;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P1-23: GUI semantics contract — download labels, results views, and Worker/BLOCKED
 * status text stay consistent with GUI_DESIGN (asserted against frontend sources).
 */
public final class GuiSemanticsContractAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = projectRoot();
        String semantics = Files.readString(root.resolve("frontend/src/guiSemantics.ts"), StandardCharsets.UTF_8);
        String results = Files.readString(root.resolve("frontend/src/components/ResultsPage.tsx"), StandardCharsets.UTF_8);
        String labels = Files.readString(root.resolve("frontend/src/labels.ts"), StandardCharsets.UTF_8);
        String audit = Files.readString(root.resolve("frontend/src/components/AuditPage.tsx"), StandardCharsets.UTF_8);
        String api = Files.readString(root.resolve("frontend/src/api.ts"), StandardCharsets.UTF_8);

        downloadArtifactsAreDistinct(semantics, results);
        resultsViewsIncludeCoverageHypothesisEvidence(semantics, results);
        workerBlockedProjectionLabels(labels, audit);
        auditUsesTwoGiBDefaultMemory(audit);
        evidenceAndCoverageApiEntrypoints(api);
        modelThinkingMarkedUntrusted(semantics, labels);
        privacyDeferredWithSsoDocumented(semantics);

        System.out.println("GuiSemanticsContractAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void downloadArtifactsAreDistinct(String semantics, String results) {
        for (String id : List.of(
                "FINAL_REPORT_MARKDOWN", "FINDINGS_SUMMARY_HTML", "SCAN_DASHBOARD_JSON")) {
            check(semantics.contains(id), "guiSemantics declares " + id);
        }
        check(semantics.contains("veyrion-report-{scanId}.md"), "report markdown filename pattern");
        check(semantics.contains("veyrion-findings-{scanId}.html"),
                "findings HTML filename distinct from report");
        check(semantics.contains("veyrion-scan-{scanId}.json"), "dashboard JSON filename pattern");
        check(results.contains("DOWNLOAD_ARTIFACTS"), "ResultsPage uses DOWNLOAD_ARTIFACTS");
        check(results.contains("downloadFilename('reportMarkdown'"), "report download uses contract");
        check(results.contains("downloadFilename('findingsHtml'"), "findings HTML uses contract");
        check(results.contains("downloadFilename('dashboardJson'"), "dashboard JSON uses contract");
        check(!results.contains("veyrion-report-${safeScanId}.html"),
                "findings HTML no longer reuses report markdown filename stem");
    }

    private static void resultsViewsIncludeCoverageHypothesisEvidence(String semantics, String results) {
        for (String view : List.of(
                "'coverage'", "'hypotheses'", "'evidenceGraph'", "'pathRuns'", "'report'")) {
            check(semantics.contains(view), "RESULTS_VIEW_IDS includes " + view);
        }
        check(results.contains("RESULTS_VIEW_IDS"), "ResultsPage imports RESULTS_VIEW_IDS");
        check(results.contains("activeView === 'coverage'"), "Coverage Matrix view entry");
        check(results.contains("activeView === 'hypotheses'"), "SecurityHypothesis view entry");
        check(results.contains("activeView === 'evidenceGraph'"), "Evidence Graph view entry");
        check(results.contains("getScanCoverage") && results.contains("getEvidenceGraph"),
                "Coverage/Evidence Graph fetched via API boundary");
    }

    private static void workerBlockedProjectionLabels(String labels, String audit) {
        check(labels.contains("WORKER_UNAVAILABLE"), "labels expose WORKER_UNAVAILABLE");
        check(labels.contains("PROJECTION_FAILED"), "labels expose PROJECTION_FAILED");
        check(labels.contains("pipelineStatusLabel"), "pipelineStatusLabel helper present");
        check(labels.contains("无 Worker") || labels.contains("Worker 不可用"),
                "Chinese Worker-unavailable copy present");
        check(audit.contains("pipelineStatusLabel"), "AuditPage surfaces pipelineStatusLabel");
        check(audit.contains("BLOCKED"), "AuditPage still treats BLOCKED as unavailable");
    }

    private static void auditUsesTwoGiBDefaultMemory(String audit) {
        check(audit.contains("name=\"memory\"")
                        && audit.contains("max=\"4096\"")
                        && audit.contains("defaultValue=\"2048\""),
                "audit form defaults runtime memory to 2048 MiB within the 4096 MiB worker limit");
    }

    private static void evidenceAndCoverageApiEntrypoints(String api) {
        check(api.contains("getScanCoverage"), "api.ts declares getScanCoverage");
        check(api.contains("getEvidenceGraph"), "api.ts declares getEvidenceGraph");
        check(api.contains("/coverage"), "coverage path uses /scans/{id}/coverage");
        check(api.contains("evidence-graph"), "evidence graph path uses /evidence-graph");
        check(api.contains("parseCoverageMatrix") && api.contains("parseEvidenceGraph"),
                "parsers validate coverage/evidence graph at boundary");
        int coverageStart = api.indexOf("export const parseCoverageMatrix");
        int coverageEnd = api.indexOf("const knownEvidenceNodeKinds", coverageStart);
        check(coverageStart >= 0 && coverageEnd > coverageStart, "coverage parser body is discoverable");
        String coverageParser = api.substring(coverageStart, coverageEnd);
        for (String field : List.of("callResolution:", "detectors:", "dynamicExperiments:",
                "stopReasons:", "honestyFlags:")) {
            check(coverageParser.contains(field), "coverage parser consumes required wire section " + field);
        }
        for (String invariant : List.of(
                "unresolvedIsGap !== true", "countedAsCovered !== false",
                "scanSuccessMeans !== 'analysis_finished_not_safe'", "invalid coverage.checksum")) {
            check(coverageParser.contains(invariant), "coverage parser rejects dishonest invariant " + invariant);
        }
        int graphStart = api.indexOf("export const parseEvidenceGraph =");
        int graphEnd = api.indexOf("export const parseScanHypotheses", graphStart);
        check(graphStart >= 0 && graphEnd > graphStart, "evidence graph parser body is discoverable");
        String graphParser = api.substring(graphStart, graphEnd);
        for (String invariant : List.of(
                "invalid evidenceGraph.nodes", "invalid evidenceGraph.edges",
                "invalid evidenceGraph.compatibilityGap", "compatibilityGap:")) {
            check(graphParser.contains(invariant), "evidence graph parser is fail-closed for " + invariant);
        }
        check(api.contains(": 'UNKNOWN'"), "missing evidence provenance never defaults to FACT");
        check(api.contains("invalid scanHypotheses.hypotheses"),
                "missing hypotheses envelope cannot degrade to an empty valid result");
    }

    private static void modelThinkingMarkedUntrusted(String semantics, String labels) {
        check(semantics.contains("MODEL_THINKING"), "MODEL_THINKING in semantics contract");
        check(semantics.contains("不可信审计元数据") || semantics.toLowerCase(Locale.ROOT)
                        .contains("untrusted"),
                "MODEL_THINKING marked untrusted audit metadata");
        check(labels.contains("MODEL_THINKING") || semantics.contains("MODEL_THINKING"),
                "thinking remains distinguishable from FACT evidence");
    }

    private static void privacyDeferredWithSsoDocumented(String semantics) {
        check(semantics.contains("GUI_CONTRACT_AUDIT"), "GUI_CONTRACT_AUDIT exported");
        check(semantics.contains("contract-tests-not-manual-visual"),
                "audited scope is contract tests, not manual visual");
        check(semantics.contains("productionPrivacyDeferredWithSso"),
                "production privacy deferred with SSO is explicit");
        check(semantics.contains("modelThinkingRetentionDeferred"),
                "MODEL_THINKING retention deferred is explicit");
    }

    static Path projectRoot() throws Exception {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        for (Path cursor = dir; cursor != null; cursor = cursor.getParent()) {
            if (Files.isRegularFile(cursor.resolve("pom.xml"))
                    && Files.isDirectory(cursor.resolve("frontend"))) {
                return cursor;
            }
        }
        throw new IllegalStateException("project root with pom.xml + frontend/ not found from " + dir);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

package com.aq.jvmsentinel.domain.analyzer;

import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.universe.CoverageGap;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * 已校验 Analyzer evidence 原子发布的 port。
 * 实现不得授予 Analyzer DB/model/authorization/Worker 权限。
 */
public interface AnalyzerEvidenceStore {
    void publishAtomically(PublishedEvidence evidence);

    Optional<PublishedEvidence> findBySubmissionId(String submissionId);

    /** Snapshot published for a scan; used to prove Analyzer removal does not erase history. */
    List<PublishedEvidence> findByScanId(String scanId);

    record PublishedEvidence(
            String submissionId,
            AnalyzerScope scope,
            String fingerprint,
            AnalyzerTerminalState terminalState,
            List<IrNode> nodes,
            List<CoverageGap> coverageGaps,
            List<AnalyzerDiagnostic> diagnostics,
            AnalyzerResourceUsage resourceUsage,
            String stopReason
    ) {
        public PublishedEvidence {
            Objects.requireNonNull(submissionId, "submissionId");
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(fingerprint, "fingerprint");
            Objects.requireNonNull(terminalState, "terminalState");
            nodes = List.copyOf(nodes == null ? List.of() : nodes);
            coverageGaps = List.copyOf(coverageGaps == null ? List.of() : coverageGaps);
            diagnostics = List.copyOf(diagnostics == null ? List.of() : diagnostics);
            Objects.requireNonNull(resourceUsage, "resourceUsage");
            stopReason = stopReason == null ? "" : stopReason;
        }
    }
}

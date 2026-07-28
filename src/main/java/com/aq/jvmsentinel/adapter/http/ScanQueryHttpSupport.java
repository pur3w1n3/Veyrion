package com.aq.jvmsentinel.adapter.http;

import com.aq.jvmsentinel.application.port.CoverageQueryPort;
import com.aq.jvmsentinel.application.port.EvidenceGraphQueryPort;
import com.aq.jvmsentinel.application.port.HypothesisQueryPort;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Maps application query ports to legacy {@code /api/v1} JSON maps (P1-08).
 * Transport (HttpExchange) stays in ControlPlaneServer; this class only projects.
 */
public final class ScanQueryHttpSupport {
    private final EvidenceGraphQueryPort evidenceGraphs;
    private final CoverageQueryPort coverage;
    private final HypothesisQueryPort hypotheses;

    public ScanQueryHttpSupport(EvidenceGraphQueryPort evidenceGraphs,
                                CoverageQueryPort coverage,
                                HypothesisQueryPort hypotheses) {
        this.evidenceGraphs = Objects.requireNonNull(evidenceGraphs, "evidenceGraphs");
        this.coverage = Objects.requireNonNull(coverage, "coverage");
        this.hypotheses = Objects.requireNonNull(hypotheses, "hypotheses");
    }

    public Optional<Map<String, Object>> evidenceGraphBody(String scanId) {
        return evidenceGraphs.evidenceGraph(scanId).map(EvidenceGraph::toMap);
    }

    public Optional<Map<String, Object>> coverageBody(String scanId) {
        return coverage.coverage(scanId).map(CoverageMatrix::toMap);
    }

    public Optional<Map<String, Object>> hypothesesBody(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return Optional.empty();
        }
        List<SecurityHypothesis> items = hypotheses.hypotheses(scanId);
        // Empty list is a valid response when the scan exists; caller checks existence.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", SecurityHypothesis.SCHEMA_VERSION);
        body.put("scanId", scanId);
        List<Object> maps = new ArrayList<>(items.size());
        for (SecurityHypothesis item : items) {
            maps.add(item.toMap());
        }
        body.put("hypotheses", maps);
        body.put("count", maps.size());
        return Optional.of(body);
    }
}

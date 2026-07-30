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
 * 将 application 查询 port 映射为 legacy {@code /api/v1} JSON map（P1-08）。
 * 传输层（HttpExchange）留在 ControlPlaneServer；本类仅做投影。
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
        // scan 存在时空列表也是合法响应；调用方自行检查存在性。
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

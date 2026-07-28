package com.aq.jvmsentinel.application.port;

import com.aq.jvmsentinel.domain.ir.EvidenceGraph;

import java.util.Optional;

/**
 * Read-only Evidence Graph query (P1-08). Returns domain IR, not HTTP DTOs.
 */
public interface EvidenceGraphQueryPort {
    Optional<EvidenceGraph> evidenceGraph(String scanId);
}

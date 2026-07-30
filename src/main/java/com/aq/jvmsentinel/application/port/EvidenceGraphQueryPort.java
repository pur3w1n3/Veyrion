package com.aq.jvmsentinel.application.port;

import com.aq.jvmsentinel.domain.ir.EvidenceGraph;

import java.util.Optional;

/**
 * 只读 Evidence Graph 查询（P1-08）。返回 domain IR，而非 HTTP DTO。
 */
public interface EvidenceGraphQueryPort {
    Optional<EvidenceGraph> evidenceGraph(String scanId);
}

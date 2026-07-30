package com.aq.jvmsentinel.application.port;

import com.aq.jvmsentinel.domain.ir.ProgramNode;

import java.util.List;

/**
 * 接受 LanguageAnalyzer / Test Analyzer 风格的 ProgramNode overlay（P1-08）。
 *
 * <p>节点与语言无关；未知 {@code language} 与 namespaced
 * {@code extensions} 保留供查询/展示，且不得提升 verification status。
 */
public interface AnalyzerIrIngestPort {
    void ingestProgramNodes(String scanId, List<ProgramNode> nodes);

    List<ProgramNode> supplementalProgramNodes(String scanId);
}

package com.aq.jvmsentinel.application.port;

import com.aq.jvmsentinel.domain.ir.ProgramNode;

import java.util.List;

/**
 * Accepts LanguageAnalyzer / Test Analyzer style ProgramNode overlays (P1-08).
 *
 * <p>Nodes are language-agnostic; unknown {@code language} and namespaced
 * {@code extensions} are preserved for query/display and never elevate verification status.
 */
public interface AnalyzerIrIngestPort {
    void ingestProgramNodes(String scanId, List<ProgramNode> nodes);

    List<ProgramNode> supplementalProgramNodes(String scanId);
}

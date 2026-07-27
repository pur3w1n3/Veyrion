package com.aq.jvmsentinel.analysis.fuzz;

import com.aq.jvmsentinel.ai.RootCauseAnalysis;
import com.aq.jvmsentinel.analysis.CweMapper;

import java.util.List;

/** MVP-4/5 acceptance: fuzz strategies, CWE mapping, Mermaid root cause. */
public final class FuzzStrategyAcceptanceTest {
    public static void main(String[] args) {
        sqlStrategyHasAtLeastThreeTemplates();
        cweMapperCoversFiveCategories();
        rootCauseMermaidHasThreeSteps();
        System.out.println("FuzzStrategyAcceptanceTest: PASS");
    }

    private static void sqlStrategyHasAtLeastThreeTemplates() {
        FuzzStrategyRegistry.FuzzStrategy strategy = FuzzStrategyRegistry.forSink("SQL");
        check(strategy.probeTemplates().size() >= 3, "SQL strategy templates >= 3");
        check(strategy.probeTemplates().stream().anyMatch(t -> "union".equals(t.name())),
                "SQL strategy includes union probe");
    }

    private static void cweMapperCoversFiveCategories() {
        check("CWE-89".equals(CweMapper.cweMappingFor("SQL")), "SQL→CWE-89");
        check("CWE-78".equals(CweMapper.cweMappingFor("COMMAND")), "COMMAND→CWE-78");
        check("CWE-22".equals(CweMapper.cweMappingFor("PATH_TRAVERSAL")), "PATH→CWE-22");
        check("CWE-502".equals(CweMapper.cweMappingFor("DESERIALIZATION")), "DESER→CWE-502");
        check("CWE-918".equals(CweMapper.cweMappingFor("SSRF")), "SSRF→CWE-918");
    }

    private static void rootCauseMermaidHasThreeSteps() {
        RootCauseAnalysis analysis = new RootCauseAnalysis(
                List.of(
                        new RootCauseAnalysis.AttackStep("HTTP", "POST /api/user", List.of("pathrun:1")),
                        new RootCauseAnalysis.AttackStep("param", "username", List.of("evidence:1")),
                        new RootCauseAnalysis.AttackStep("sink", "SQL concat", List.of("sink:1"))),
                "string concat into SQL",
                "com.Example#query",
                "CWE-89",
                "use PreparedStatement");
        String mermaid = RootCauseAnalysis.toMermaid(analysis);
        check(mermaid.contains("mermaid"), "mermaid fence");
        check(mermaid.contains("S0") && mermaid.contains("S2"), "three steps");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

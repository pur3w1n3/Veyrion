package com.aq.jvmsentinel.ai;

import java.util.List;
import java.util.Objects;

/** VULNERABILITY_TRIAGE / REPORT_GENERATION 的结构化 root-cause 输出。 */
public record RootCauseAnalysis(
        List<AttackStep> attackPath,
        String rootCauseStatement,
        String affectedComponent,
        String cweId,
        String fixSuggestion
) {
    public record AttackStep(String layer, String label, List<String> evidenceRefs) {
        public AttackStep {
            layer = layer == null || layer.isBlank() ? "unknown" : layer;
            label = Objects.requireNonNull(label, "label");
            if (label.isBlank()) throw new IllegalArgumentException("label cannot be blank");
            evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
            if (evidenceRefs.isEmpty()) {
                throw new IllegalArgumentException("attack step requires evidenceRefs");
            }
        }
    }

    public RootCauseAnalysis {
        attackPath = List.copyOf(attackPath == null ? List.of() : attackPath);
        rootCauseStatement = rootCauseStatement == null ? "" : rootCauseStatement;
        affectedComponent = affectedComponent == null ? "" : affectedComponent;
        cweId = cweId == null ? "" : cweId;
        fixSuggestion = fixSuggestion == null ? "" : fixSuggestion;
    }

    public static String toMermaid(RootCauseAnalysis analysis) {
        if (analysis == null || analysis.attackPath().isEmpty()) {
            return "```mermaid\nflowchart LR\n    A[insufficient evidence]\n```";
        }
        StringBuilder sb = new StringBuilder("```mermaid\nflowchart LR\n");
        List<AttackStep> steps = analysis.attackPath();
        for (int i = 0; i < steps.size(); i++) {
            String id = "S" + i;
            String label = steps.get(i).label().replace("\"", "'");
            if (label.length() > 48) label = label.substring(0, 45) + "...";
            sb.append("    ").append(id).append("[\"").append(label).append("\"]\n");
            if (i > 0) {
                sb.append("    S").append(i - 1).append(" --> ").append(id).append('\n');
            }
        }
        sb.append("```");
        return sb.toString();
    }
}

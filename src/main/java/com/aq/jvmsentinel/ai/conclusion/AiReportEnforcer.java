package com.aq.jvmsentinel.ai.conclusion;

import com.aq.jvmsentinel.ai.FindingBindings;
import com.aq.jvmsentinel.ai.context.ContrastContextBuilder;
import com.aq.jvmsentinel.ai.context.FindingBindingsContextBuilder;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;

/** REPORT 阶段 findingBindings 与 contrastLedger 服务端强制。 */
public final class AiReportEnforcer {
    private final ContrastContextBuilder contrastContext;
    private final FindingBindingsContextBuilder findingBindingsContext;

    public AiReportEnforcer(
            ContrastContextBuilder contrastContext,
            FindingBindingsContextBuilder findingBindingsContext) {
        this.contrastContext = java.util.Objects.requireNonNull(contrastContext, "contrastContext");
        this.findingBindingsContext = java.util.Objects.requireNonNull(findingBindingsContext, "findingBindingsContext");
    }

    public ReportLedgerEnforced enforceReportContrastLedger(
            SQLiteControlPlanePersistence.AiJobData job,
            String summary,
            String conclusionJson,
            AiOutputLanguage language) {
        ContrastLedger.Ledger ledger = contrastContext.loadContrastLedger(job);
        ContrastLedger.EnforceResult enforced = ContrastLedger.enforceReport(
                summary, ledger, language == AiOutputLanguage.EN);
        String conclusion = conclusionJson;
        try {
            com.fasterxml.jackson.databind.node.ObjectNode node;
            try {
                node = (ObjectNode) AiConclusionJson.JSON.readTree(conclusionJson);
            } catch (Exception ignored) {
                node = AiConclusionJson.JSON.createObjectNode();
                node.put("schemaVersion", 1);
                node.put("classification", "INFERENCE");
            }
            node.put("summary", enforced.summary());
            com.fasterxml.jackson.databind.node.ArrayNode ledgerNode = node.putArray("contrastLedger");
            for (var row : ledger.staticOnlyRows()) {
                if (ledgerNode.size() >= ContrastLedger.MAX_FORCED_STATIC_ONLY) break;
                ledgerNode.add(ContrastLedger.toFactNode(row));
            }
            node.put("contrastLedgerIncomplete", enforced.incomplete());
            node.put("contrastLedgerTruncated", ledger.truncated());
            conclusion = node.toString();
        } catch (Exception ignored) {
            // 补丁失败时保留原 conclusion JSON。
        }
        return new ReportLedgerEnforced(
                enforced.summary(), conclusion, enforced.incomplete(), enforced.missingRowIds());
    }

    public record ReportLedgerEnforced(
            String summary, String conclusionJson, boolean incomplete, List<String> missingRowIds) {
        public ReportLedgerEnforced {
            summary = summary == null ? "" : summary;
            conclusionJson = conclusionJson == null ? "" : conclusionJson;
            missingRowIds = List.copyOf(missingRowIds == null ? List.of() : missingRowIds);
        }
    }

    public record ReportBindingsEnforced(
            String summary, String conclusionJson, boolean appendedByServer, boolean localeRepaired) {
        public ReportBindingsEnforced {
            summary = summary == null ? "" : summary;
            conclusionJson = conclusionJson == null ? "" : conclusionJson;
        }
    }

    /** PATH：合并 AI findingBindings 与服务端 findings×PathRun/PathTrace 装配。 */
    public String annotateFindingBindings(
            SQLiteControlPlanePersistence.AiJobData job,
            String summary,
            String conclusionJson,
            AiOutputLanguage language) {
        List<FindingBindings.Binding> server = findingBindingsContext.assembleFindingBindings(job, language);
        List<FindingBindings.Binding> ai = FindingBindings.parseFromConclusion(
                conclusionJson + "\n" + (summary == null ? "" : summary));
        List<FindingBindings.Binding> merged = FindingBindings.mergePreferringServer(ai, server);
        try {
            com.fasterxml.jackson.databind.node.ObjectNode node;
            try {
                node = (ObjectNode) AiConclusionJson.JSON.readTree(conclusionJson);
            } catch (Exception ignored) {
                node = AiConclusionJson.JSON.createObjectNode();
                node.put("schemaVersion", 1);
                node.put("classification", "INFERENCE");
                node.put("summary", summary == null ? "" : summary);
            }
            node.set("findingBindings", FindingBindings.toJsonArray(merged));
            node.put("findingBindingsSource", "SERVER_GATED");
            node.put("findingBindingsCount", merged.size());
            return node.toString();
        } catch (Exception failure) {
            return conclusionJson;
        }
    }

    public ReportBindingsEnforced enforceReportFindingBindings(
            SQLiteControlPlanePersistence.AiJobData job,
            String summary,
            String conclusionJson,
            AiOutputLanguage language) {
        // 始终按当前 PathRun/PathTrace 重算（含 H4 enricher），不得沿用 PATH 阶段
        // 落库的 STATIC_INFERRED bindings 导致报告计数全为静态。
        List<FindingBindings.Binding> bindings =
                findingBindingsContext.assembleFindingBindings(job, language);
        if (bindings.isEmpty()) {
            bindings = findingBindingsContext.loadPathFindingBindings(job, language);
        }
        FindingBindings.EnforceResult enforced = FindingBindings.enforceReportSection(
                summary, bindings, language);
        String conclusion = conclusionJson;
        try {
            com.fasterxml.jackson.databind.node.ObjectNode node;
            try {
                node = (ObjectNode) AiConclusionJson.JSON.readTree(conclusionJson);
            } catch (Exception ignored) {
                node = AiConclusionJson.JSON.createObjectNode();
                node.put("schemaVersion", 1);
                node.put("classification", "INFERENCE");
            }
            node.put("summary", enforced.summary());
            node.set("findingBindings", FindingBindings.toJsonArray(bindings));
            node.put("findingBindingsEnforced", enforced.appendedByServer());
            node.put("findingBindingsLocaleRepaired", enforced.localeRepaired());
            conclusion = node.toString();
        } catch (Exception ignored) {
            // 补丁失败时保留原 conclusion JSON。
        }
        return new ReportBindingsEnforced(
                enforced.summary(), conclusion, enforced.appendedByServer(), enforced.localeRepaired());
    }
}

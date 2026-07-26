package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.StaticContrastRow;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Bounded CONTRAST_LEDGER for REPORT / PATH / TRIAGE prompts and server-side
 * incomplete-ledger enforcement.
 */
public final class ContrastLedger {
    public static final String EVENT_INCOMPLETE = "REPORT_LEDGER_INCOMPLETE";
    public static final String SECTION_ZH = "## 静态·动态对照账本（服务端）";
    public static final String SECTION_EN = "## Static-Dynamic Contrast Ledger (server)";
    /** Max STATIC_ONLY summary lines forced into the report body. */
    public static final int MAX_FORCED_STATIC_ONLY = 40;
    /** Max rows inlined into the user prompt. */
    public static final int MAX_PROMPT_ROWS = 32;

    private static final ObjectMapper JSON = new ObjectMapper();

    private ContrastLedger() { }

    public record Ledger(List<StaticContrastRow> rows, int staticOnlyCount, boolean truncated,
                         String stopReason) {
        public Ledger {
            rows = List.copyOf(rows == null ? List.of() : rows);
            stopReason = stopReason == null ? "" : stopReason;
        }

        public List<StaticContrastRow> staticOnlyRows() {
            List<StaticContrastRow> out = new ArrayList<>();
            for (StaticContrastRow row : rows) {
                if (row.contrastStatus() == ContrastStatus.STATIC_ONLY) out.add(row);
            }
            return List.copyOf(out);
        }
    }

    public static Ledger build(
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.SinkDto> sinks,
            Map<String, ApiDtos.EvidenceDto> evidence,
            List<ApiDtos.PathRunDto> pathRuns) {
        StaticContrastProjector.Projection projection = new StaticContrastProjector()
                .projectFromScan(entries, sinks, evidence);
        StaticDynamicContraster.Result joined = new StaticDynamicContraster()
                .join(projection.rows(), pathRuns);
        String stop = projection.stopReason();
        if (joined.truncated() && (stop == null || stop.isBlank())) {
            stop = StaticContrastProjector.STOP_BUDGET;
        }
        return new Ledger(joined.rows(), joined.staticOnlyCount(),
                projection.truncated() || joined.truncated(), stop);
    }

    public static String formatForPrompt(Ledger ledger, boolean english) {
        StringBuilder block = new StringBuilder();
        if (english) {
            block.append("CONTRAST_LEDGER (server FACT/INFERENCE; not VERIFIED):\n")
                    .append("- STATIC_ONLY means static candidate with no pass-gate PathRun ")
                    .append("(e.g. all 401). Never narrate as bypassed/confirmed.\n")
                    .append("- MATCHED/PARTIAL still max DYNAMIC_SUSPECTED.\n");
        } else {
            block.append("CONTRAST_LEDGER（服务端 FACT/INFERENCE，非 VERIFIED）：\n")
                    .append("- STATIC_ONLY：有静态候选但无过闸 PathRun（如全 401），不得写成已绕过/已确认。\n")
                    .append("- MATCHED/PARTIAL 仍最高 DYNAMIC_SUSPECTED。\n");
        }
        if (ledger == null || ledger.rows().isEmpty()) {
            block.append(english ? "- (empty)\n" : "- （空）\n");
            return block.toString();
        }
        int emitted = 0;
        for (StaticContrastRow row : ledger.rows()) {
            if (emitted >= MAX_PROMPT_ROWS) break;
            block.append("- ").append(row.rowId())
                    .append(" status=").append(row.contrastStatus().name())
                    .append(" sink=").append(row.sinkId())
                    .append(" category=").append(row.category())
                    .append(" entryRefs=").append(row.entryRefs())
                    .append(" taintPathId=").append(row.taintPathId().isBlank() ? "-" : row.taintPathId())
                    .append(" pathRunRefs=").append(row.pathRunRefs())
                    .append(" stopReason=").append(row.stopReason())
                    .append('\n');
            emitted++;
        }
        if (ledger.rows().size() > MAX_PROMPT_ROWS) {
            block.append(english
                    ? "- …" + (ledger.rows().size() - MAX_PROMPT_ROWS)
                    + " more omitted; fetch facts_search kind=STATIC_CONTRAST.\n"
                    : "- …另有 " + (ledger.rows().size() - MAX_PROMPT_ROWS)
                    + " 条未内联，请用 facts_search kind=STATIC_CONTRAST。\n");
        }
        if (ledger.truncated()) {
            block.append(english
                    ? "- truncated=true stopReason=" + ledger.stopReason() + "\n"
                    : "- truncated=true stopReason=" + ledger.stopReason() + "\n");
        }
        return block.toString();
    }

    /**
     * Ensures every STATIC_ONLY (and unmatched) summary appears in the report text.
     * If the model omitted them, append a server section and mark incomplete.
     */
    public static EnforceResult enforceReport(String summaryMarkdown, Ledger ledger, boolean english) {
        if (ledger == null) {
            return new EnforceResult(summaryMarkdown == null ? "" : summaryMarkdown, false, List.of());
        }
        List<StaticContrastRow> required = new ArrayList<>();
        for (StaticContrastRow row : ledger.rows()) {
            if (row.contrastStatus() == ContrastStatus.STATIC_ONLY
                    || row.contrastStatus() == ContrastStatus.DYNAMIC_ONLY) {
                required.add(row);
            }
        }
        if (required.size() > MAX_FORCED_STATIC_ONLY) {
            required = required.subList(0, MAX_FORCED_STATIC_ONLY);
        }
        String body = summaryMarkdown == null ? "" : summaryMarkdown;
        List<String> missing = new ArrayList<>();
        for (StaticContrastRow row : required) {
            if (!bodyContainsRow(body, row)) missing.add(row.rowId());
        }
        if (missing.isEmpty()) {
            return new EnforceResult(body, false, List.of());
        }
        StringBuilder appendix = new StringBuilder();
        appendix.append('\n').append(english ? SECTION_EN : SECTION_ZH).append('\n');
        if (english) {
            appendix.append("Server appended because the model omitted STATIC_ONLY / unmatched rows. ")
                    .append("These remain static candidates without pass-gate confirmation.\n");
        } else {
            appendix.append("以下由服务端补写（模型未完整覆盖 STATIC_ONLY / 未匹配行）。")
                    .append("仅表示静态候选未获动态过闸确认，不是绕过结论。\n");
        }
        for (StaticContrastRow row : required) {
            if (!missing.contains(row.rowId()) && bodyContainsRow(body, row)) continue;
            appendix.append("- ").append(row.rowId())
                    .append(" | ").append(row.contrastStatus().name())
                    .append(" | sink=").append(row.sinkId())
                    .append(" | ").append(row.category())
                    .append(" | entryRefs=").append(row.entryRefs())
                    .append(" | taintPathId=").append(row.taintPathId().isBlank() ? "-" : row.taintPathId())
                    .append(" | pathRunRefs=").append(row.pathRunRefs())
                    .append(" | ").append(row.stopReason())
                    .append('\n');
        }
        if (ledger.truncated() || required.size() >= MAX_FORCED_STATIC_ONLY) {
            appendix.append(english
                    ? "- truncation applied; maxForced=" + MAX_FORCED_STATIC_ONLY + "\n"
                    : "- 已截断；maxForced=" + MAX_FORCED_STATIC_ONLY + "\n");
        }
        return new EnforceResult(body + appendix, true, List.copyOf(missing));
    }

    public static ObjectNode toFactNode(StaticContrastRow row) {
        ObjectNode node = JSON.createObjectNode();
        node.put("rowId", row.rowId());
        node.put("sinkId", row.sinkId());
        node.put("category", row.category());
        node.put("sinkSymbol", row.sinkSymbol());
        node.put("taintPathId", row.taintPathId());
        node.put("track", row.track());
        node.put("contrastStatus", row.contrastStatus().name());
        node.put("stopReason", row.stopReason());
        node.put("truncated", row.truncated());
        node.put("verificationStatus", "STATIC_INFERRED");
        node.put("classification", "INFERENCE");
        ArrayNode entries = node.putArray("entryRefs");
        for (String ref : row.entryRefs()) entries.add(ref);
        ArrayNode pathRuns = node.putArray("pathRunRefs");
        for (String ref : row.pathRunRefs()) pathRuns.add(ref);
        return node;
    }

    private static boolean bodyContainsRow(String body, StaticContrastRow row) {
        if (body == null || body.isBlank()) return false;
        if (body.contains(row.rowId())) return true;
        String lower = body.toLowerCase(Locale.ROOT);
        if (!row.sinkId().isBlank() && lower.contains(row.sinkId().toLowerCase(Locale.ROOT))
                && lower.contains(row.contrastStatus().name().toLowerCase(Locale.ROOT))) {
            return true;
        }
        return !row.taintPathId().isBlank() && body.contains(row.taintPathId())
                && lower.contains("static_only");
    }

    public record EnforceResult(String summary, boolean incomplete, List<String> missingRowIds) {
        public EnforceResult {
            summary = summary == null ? "" : summary;
            missingRowIds = List.copyOf(missingRowIds == null ? List.of() : missingRowIds);
        }
    }
}

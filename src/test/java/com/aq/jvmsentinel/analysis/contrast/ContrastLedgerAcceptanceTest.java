package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.Sink;
import com.aq.jvmsentinel.model.StaticContrastRow;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.provider.AgentRole;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Acceptance: REPORT CONTRAST_LEDGER forces all STATIC_ONLY summary rows (bounded).
 */
public final class ContrastLedgerAcceptanceTest {
    public static void main(String[] args) {
        forcesStaticOnlyIntoReport();
        truncationIsExplicit();
        noSeventhAgentRole();
        System.out.println("ContrastLedgerAcceptanceTest: PASS");
    }

    private static void forcesStaticOnlyIntoReport() {
        ApiDtos.EntryDto entry = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "s", "entry-ann-1", "HTTP", "GET",
                "/api/x", "app.X", "mod", List.of(), List.of(), ApiDtos.STATIC_INFERRED,
                0.9, 0, List.of("ann-1"));
        Map<String, ApiDtos.EvidenceDto> evidence = new HashMap<>();
        evidence.put("ann-1", new ApiDtos.EvidenceDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "s", "ann-1", "FACT",
                "classfile-annotation:app.X#handler", 1.0, "mapping",
                "1970-01-01T00:00:00Z", "t", "n", "n", ApiDtos.MOCK, ApiDtos.STATIC_INFERRED));
        evidence.put("call-1", new ApiDtos.EvidenceDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "s", "call-1", "FACT",
                "classfile-call:app.X#handler()V", 1.0, "call",
                "1970-01-01T00:00:00Z", "t", "n", "n", ApiDtos.MOCK, ApiDtos.STATIC_INFERRED));
        ApiDtos.SinkDto sink = new ApiDtos.SinkDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "s", "sink-1", "COMMAND",
                "Runtime#exec", "bytecode; taint-path=taint-abc; bounded",
                ApiDtos.STATIC_INFERRED, 0.8, List.of("call-1"));
        ApiDtos.PathRunDto only401 = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-1", "s", "entry:entry-ann-1", "UNAUTH",
                "a1", "", "GET", "application/json", "summary", "AUTH_CHALLENGE", 401,
                false, false, List.of(), "STOP", ApiDtos.DYNAMIC_SUSPECTED,
                List.of(), "MOCK", "");

        ContrastLedger.Ledger ledger = ContrastLedger.build(
                List.of(entry), List.of(sink), evidence, List.of(only401));
        check(ledger.staticOnlyCount() >= 1, "401 PathRun → STATIC_ONLY in ledger");
        StaticContrastRow row = ledger.staticOnlyRows().get(0);
        check(row.hasTaintPath() || "taint-abc".equals(row.taintPathId())
                        || row.taintPathId().contains("taint"),
                "taintPathId present on static row");
        check(!row.entryRefs().isEmpty(), "entryRefs present");

        String prompt = ContrastLedger.formatForPrompt(ledger, false);
        check(prompt.contains("CONTRAST_LEDGER"), "prompt injects CONTRAST_LEDGER");
        check(prompt.contains("STATIC_ONLY"), "prompt lists STATIC_ONLY");

        // Model omits STATIC_ONLY → server appends + REPORT_LEDGER_INCOMPLETE.
        ContrastLedger.EnforceResult incomplete = ContrastLedger.enforceReport(
                "# 审计报告\n\n只有摘要，没有对照表。\n", ledger, false);
        check(incomplete.incomplete(), "omission triggers incomplete");
        check(!incomplete.missingRowIds().isEmpty(), "missing row ids recorded");
        check(incomplete.summary().contains(ContrastLedger.SECTION_ZH),
                "server appends contrast section");
        check(incomplete.summary().contains(row.rowId())
                        || incomplete.summary().contains("STATIC_ONLY"),
                "forced STATIC_ONLY summary present");
        check(!incomplete.summary().contains("已绕过"),
                "server appendix never claims bypassed");

        // Model already covered → no incomplete event.
        ContrastLedger.EnforceResult complete = ContrastLedger.enforceReport(
                "# 报告\n" + row.rowId() + " STATIC_ONLY 静态未动态确认\n", ledger, false);
        check(!complete.incomplete(), "covered ledger is complete");
    }

    private static void truncationIsExplicit() {
        List<StaticContrastRow> many = new ArrayList<>();
        for (int i = 0; i < ContrastLedger.MAX_FORCED_STATIC_ONLY + 10; i++) {
            many.add(new StaticContrastRow(
                    "contrast-" + i, "sink-" + i, "FILE", "sym",
                    List.of("entry:e" + i), "", "", ContrastStatus.STATIC_ONLY,
                    List.of(), StaticDynamicContraster.STOP_NO_PATHRUN, false));
        }
        ContrastLedger.Ledger ledger = new ContrastLedger.Ledger(many, many.size(), true,
                StaticContrastProjector.STOP_BUDGET);
        ContrastLedger.EnforceResult enforced = ContrastLedger.enforceReport("", ledger, true);
        check(enforced.incomplete(), "empty report incomplete");
        long forcedLines = enforced.summary().lines()
                .filter(line -> line.startsWith("- contrast-")).count();
        check(forcedLines <= ContrastLedger.MAX_FORCED_STATIC_ONLY,
                "forced STATIC_ONLY capped at MAX_FORCED_STATIC_ONLY");
        check(enforced.summary().contains("maxForced=")
                        || enforced.summary().contains("truncation"),
                "truncation strategy visible in appendix");
    }

    private static void noSeventhAgentRole() {
        check(AgentRole.values().length == 6, "AgentRole count unchanged (no seventh role)");
        for (AgentRole role : AgentRole.values()) {
            check(role != null && !role.name().contains("STATIC_AUDIT"),
                    "no STATIC_AUDIT role");
        }
        // Sink model still usable for projection without new AI stage.
        Sink sink = new Sink("s", "AUTH_GAP", "c#m", "gap", 0.5, List.of(),
                VerificationStatus.STATIC_INFERRED);
        check("AUTH_GAP".equals(sink.category()), "AUTH_GAP remains secondary sink fact");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

package com.aq.jvmsentinel.analysis.contrast;

import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Multi-round ContrastLedger diff for REPORT_GENERATION. */
public final class LedgerDiff {
    private LedgerDiff() {
    }

    public record LedgerDiffResult(
            List<String> newlyMatched,
            List<String> regressions,
            int unchangedCount,
            float coverageDelta
    ) {
        public LedgerDiffResult {
            newlyMatched = List.copyOf(newlyMatched == null ? List.of() : newlyMatched);
            regressions = List.copyOf(regressions == null ? List.of() : regressions);
        }
    }

    public static LedgerDiffResult diff(ContrastLedger.Ledger previous, ContrastLedger.Ledger current) {
        Map<String, ContrastStatus> prior = index(previous);
        Map<String, ContrastStatus> now = index(current);
        List<String> newly = new ArrayList<>();
        List<String> regressions = new ArrayList<>();
        int unchanged = 0;
        for (Map.Entry<String, ContrastStatus> entry : now.entrySet()) {
            ContrastStatus old = prior.get(entry.getKey());
            if (old == null) {
                if (isHit(entry.getValue())) newly.add(entry.getKey());
                continue;
            }
            if (old == entry.getValue()) unchanged++;
            if (!isHit(old) && isHit(entry.getValue())) newly.add(entry.getKey());
            if (isHit(old) && !isHit(entry.getValue())) regressions.add(entry.getKey());
        }
        float prevRate = hitRate(previous);
        float currRate = hitRate(current);
        return new LedgerDiffResult(newly, regressions, unchanged, currRate - prevRate);
    }

    public static String formatSummary(LedgerDiffResult diff, boolean english) {
        Objects.requireNonNull(diff, "diff");
        if (english) {
            return "LEDGER_DIFF_SUMMARY: newlyMatched=" + diff.newlyMatched().size()
                    + " regressions=" + diff.regressions().size()
                    + " unchanged=" + diff.unchangedCount()
                    + " coverageDelta=" + String.format(java.util.Locale.ROOT, "%+.0f%%",
                    diff.coverageDelta() * 100f);
        }
        return "LEDGER_DIFF_SUMMARY：本轮新命中=" + diff.newlyMatched().size()
                + " 回退=" + diff.regressions().size()
                + " 未变=" + diff.unchangedCount()
                + " 覆盖率变化=" + String.format(java.util.Locale.ROOT, "%+.0f%%",
                diff.coverageDelta() * 100f);
    }

    private static Map<String, ContrastStatus> index(ContrastLedger.Ledger ledger) {
        Map<String, ContrastStatus> map = new LinkedHashMap<>();
        if (ledger == null) return map;
        for (StaticContrastRow row : ledger.rows()) {
            map.put(row.rowId(), row.contrastStatus());
        }
        return map;
    }

    private static boolean isHit(ContrastStatus status) {
        return status == ContrastStatus.MATCHED
                || status == ContrastStatus.PARTIAL
                || status == ContrastStatus.DYNAMIC_REACHED;
    }

    private static float hitRate(ContrastLedger.Ledger ledger) {
        if (ledger == null || ledger.rows().isEmpty()) return 0f;
        int hits = 0;
        for (StaticContrastRow row : ledger.rows()) {
            if (isHit(row.contrastStatus())) hits++;
        }
        return hits / (float) ledger.rows().size();
    }
}

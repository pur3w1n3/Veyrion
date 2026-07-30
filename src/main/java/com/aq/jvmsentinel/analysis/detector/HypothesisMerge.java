package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * 以稳定 dedupe 合并 projector 与 detector hypothesis。
 * 合并键：family + securityProperty + source + effect（case-insensitive）。
 */
public final class HypothesisMerge {
    private HypothesisMerge() {
    }

    public static List<SecurityHypothesis> merge(
            List<SecurityHypothesis> projected,
            List<SecurityHypothesis> detected) {
        Map<String, SecurityHypothesis> byKey = new LinkedHashMap<>();
        for (SecurityHypothesis item : projected == null ? List.<SecurityHypothesis>of() : projected) {
            if (item == null) continue;
            byKey.putIfAbsent(dedupeKey(item), item);
        }
        for (SecurityHypothesis item : detected == null ? List.<SecurityHypothesis>of() : detected) {
            if (item == null) continue;
            byKey.putIfAbsent(dedupeKey(item), item);
        }
        return List.copyOf(byKey.values());
    }

    public static String dedupeKey(SecurityHypothesis hypothesis) {
        Objects.requireNonNull(hypothesis, "hypothesis");
        return hypothesis.family().name()
                + "|" + normalize(hypothesis.securityProperty())
                + "|" + normalize(hypothesis.source())
                + "|" + normalize(hypothesis.effect());
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    public static List<SecurityHypothesis> appendAll(List<List<SecurityHypothesis>> batches) {
        List<SecurityHypothesis> out = new ArrayList<>();
        for (List<SecurityHypothesis> batch : batches == null ? List.<List<SecurityHypothesis>>of() : batches) {
            if (batch == null) continue;
            out.addAll(batch);
        }
        return List.copyOf(out);
    }
}

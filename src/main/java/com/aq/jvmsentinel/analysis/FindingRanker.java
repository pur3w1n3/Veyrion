package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * P0-20: static-first finding ranking for dashboard / report.
 * Dynamic failures demote; never invents VERIFIED; never upgrades status.
 */
public final class FindingRanker {
    private FindingRanker() {
    }

    public record RankedFinding(ApiDtos.FindingDto finding, double score, List<String> reasons) {
        public RankedFinding {
            Objects.requireNonNull(finding, "finding");
            reasons = List.copyOf(reasons == null ? List.of() : reasons);
            if (!Double.isFinite(score)) {
                throw new IllegalArgumentException("score must be finite");
            }
        }
    }

    public static List<ApiDtos.FindingDto> rank(List<ApiDtos.FindingDto> findings) {
        return ranked(findings).stream().map(RankedFinding::finding).toList();
    }

    public static List<RankedFinding> ranked(List<ApiDtos.FindingDto> findings) {
        List<ApiDtos.FindingDto> input = findings == null ? List.of() : findings;
        List<RankedFinding> scored = new ArrayList<>();
        for (ApiDtos.FindingDto finding : input) {
            if (finding == null) continue;
            scored.add(score(finding));
        }
        scored.sort(Comparator
                .comparingDouble(RankedFinding::score).reversed()
                .thenComparing(r -> r.finding().findingId(), Comparator.nullsLast(String::compareTo)));
        return List.copyOf(scored);
    }

    private static RankedFinding score(ApiDtos.FindingDto finding) {
        double score = Math.max(0.0, Math.min(1.0, finding.confidence()));
        List<String> reasons = new ArrayList<>();
        reasons.add(String.format(Locale.ROOT, "confidence=%.2f", finding.confidence()));

        String status = safe(finding.verificationStatus()).toUpperCase(Locale.ROOT);
        switch (status) {
            case "DYNAMIC_CONFIRMED" -> {
                score += 0.35;
                reasons.add("+0.35 DYNAMIC_CONFIRMED");
            }
            case "DYNAMIC_SUSPECTED" -> {
                score += 0.10;
                reasons.add("+0.10 DYNAMIC_SUSPECTED");
            }
            case "STATIC_INFERRED" -> {
                score += 0.25;
                reasons.add("+0.25 STATIC_INFERRED");
            }
            case "UNREACHED" -> {
                score -= 0.40;
                reasons.add("-0.40 UNREACHED");
            }
            case "VERIFIED" -> {
                // Gate-closed scaffolding may appear; do not over-boost.
                score += 0.05;
                reasons.add("+0.05 VERIFIED scaffolding");
            }
            default -> reasons.add("status=" + status);
        }

        String severity = safe(finding.severity()).toLowerCase(Locale.ROOT);
        switch (severity) {
            case "critical" -> {
                score += 0.20;
                reasons.add("+0.20 severity:critical");
            }
            case "high" -> {
                score += 0.15;
                reasons.add("+0.15 severity:high");
            }
            case "medium" -> {
                score += 0.05;
                reasons.add("+0.05 severity:medium");
            }
            case "low", "info" -> {
                score -= 0.05;
                reasons.add("-0.05 severity:" + severity);
            }
            default -> {
            }
        }

        if (looksLikeStaticSink(finding)) {
            score += 0.12;
            reasons.add("+0.12 staticSinkSignal");
        }
        if ("MOCK".equalsIgnoreCase(safe(finding.dependencyMode()))
                && "DYNAMIC_SUSPECTED".equals(status)) {
            score -= 0.15;
            reasons.add("-0.15 MOCK dynamic");
        }

        score = Math.max(0.0, Math.min(2.0, score));
        return new RankedFinding(finding, score, reasons);
    }

    private static boolean looksLikeStaticSink(ApiDtos.FindingDto finding) {
        String sink = safe(finding.sink()) + " " + safe(finding.sinkId()) + " " + safe(finding.title());
        String upper = sink.toUpperCase(Locale.ROOT);
        return upper.contains("SQL")
                || upper.contains("COMMAND")
                || upper.contains("DESERIAL")
                || upper.contains("JNDI")
                || upper.contains("SSRF")
                || upper.contains("TEMPLATE")
                || upper.contains("SPEL")
                || upper.contains("FILE")
                || upper.contains("JWT");
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}

package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.SqlExperimentCard;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 从展示良性 vs 元字符语句级 SQL（D2）的 PathRun 对构建 D3 可重放 SQL 实验卡片。永不输出 VERIFIED。
 */
public final class SqlExperimentCardBuilder {
    private SqlExperimentCardBuilder() { }

    public static List<SqlExperimentCard> fromPathRuns(String scanId, List<ApiDtos.PathRunDto> pathRuns) {
        if (scanId == null || scanId.isBlank() || pathRuns == null || pathRuns.isEmpty()) {
            return List.of();
        }
        Map<String, List<ApiDtos.PathRunDto>> byKey = new LinkedHashMap<>();
        for (ApiDtos.PathRunDto run : pathRuns) {
            if (run == null || run.sqlEvents() == null || run.sqlEvents().isEmpty()) continue;
            String key = run.entrypointRef() + "|" + run.track();
            byKey.computeIfAbsent(key, ignored -> new ArrayList<>()).add(run);
        }
        List<SqlExperimentCard> cards = new ArrayList<>();
        for (Map.Entry<String, List<ApiDtos.PathRunDto>> entry : byKey.entrySet()) {
            ApiDtos.PathRunDto benign = null;
            ApiDtos.PathRunDto meta = null;
            for (ApiDtos.PathRunDto run : entry.getValue()) {
                boolean hasMeta = run.sqlEvents().stream().anyMatch(SqlExperimentCardBuilder::hasMetaMarker);
                if (hasMeta) {
                    if (meta == null) meta = run;
                } else if (benign == null) {
                    benign = run;
                }
            }
            if (benign == null || meta == null) continue;
            String sqlBefore = firstSql(benign);
            String sqlAfter = firstSql(meta);
            if (sqlBefore.isBlank() || sqlAfter.isBlank()) continue;
            SqlEvent left = new SqlEvent(sqlBefore, "", "UNKNOWN", sqlBefore.contains("?"), false, "MOCK");
            SqlEvent right = new SqlEvent(sqlAfter, "", "UNKNOWN", sqlAfter.contains("?"),
                    sqlAfter.toLowerCase(Locale.ROOT).contains(SqlDiffProbe.META_MARKER.toLowerCase(Locale.ROOT)),
                    "MOCK");
            SqlDiffProbe.DiffResult diff = SqlDiffProbe.compare(left, right);
            IdentityTrack track;
            try {
                track = IdentityTrack.valueOf(meta.track());
            } catch (RuntimeException ignored) {
                track = IdentityTrack.UNAUTH;
            }
            String status = VerificationStatus.DYNAMIC_CONFIRMED.name().equals(meta.verificationStatus())
                    ? VerificationStatus.DYNAMIC_CONFIRMED.name()
                    : VerificationStatus.DYNAMIC_SUSPECTED.name();
            String cardId = "sqlexp-" + shortHash(scanId + "|" + entry.getKey() + "|" + sqlBefore + "|" + sqlAfter);
            cards.add(new SqlExperimentCard(
                    cardId,
                    scanId,
                    meta.entrypointRef(),
                    track,
                    meta.experimentPlanId(),
                    extractInputHint(benign),
                    extractInputHint(meta),
                    truncate(sqlBefore, 1024),
                    truncate(sqlAfter, 1024),
                    diff.structureInfluenced(),
                    meta.stopReason() == null ? "COMPLETED" : meta.stopReason(),
                    meta.identityProvenance() == null ? "MOCK" : meta.identityProvenance(),
                    status,
                    List.of(benign.pathRunId(), meta.pathRunId()),
                    mergeRefs(benign.evidenceRefs(), meta.evidenceRefs())));
            if (cards.size() >= 32) break;
        }
        return List.copyOf(cards);
    }

    private static boolean hasMetaMarker(ApiDtos.SqlEventDto event) {
        if (event == null) return false;
        if (event.maliciousFragmentPresent()) return true;
        String sql = event.sqlText() == null ? "" : event.sqlText().toLowerCase(Locale.ROOT);
        return sql.contains(SqlDiffProbe.META_MARKER.toLowerCase(Locale.ROOT));
    }

    private static String firstSql(ApiDtos.PathRunDto run) {
        for (ApiDtos.SqlEventDto event : run.sqlEvents()) {
            if (event != null && event.sqlText() != null && !event.sqlText().isBlank()) {
                return event.sqlText().trim();
            }
        }
        return "";
    }

    private static String extractInputHint(ApiDtos.PathRunDto run) {
        String summary = run.requestSummary() == null ? "" : run.requestSummary();
        if (summary.toLowerCase(Locale.ROOT).contains(SqlDiffProbe.META_MARKER.toLowerCase(Locale.ROOT))) {
            return "q=" + SqlDiffProbe.META_MARKER;
        }
        if (summary.contains("?")) {
            int at = summary.indexOf('?');
            return truncate(summary.substring(at + 1), 256);
        }
        return summary.contains("track=") ? "q=benign" : truncate(summary, 128);
    }

    private static List<String> mergeRefs(List<String> left, List<String> right) {
        List<String> merged = new ArrayList<>();
        if (left != null) merged.addAll(left);
        if (right != null) {
            for (String value : right) {
                if (!merged.contains(value)) merged.add(value);
            }
        }
        return List.copyOf(merged.stream().limit(16).toList());
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static String shortHash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (Exception failure) {
            return Integer.toHexString(value.hashCode());
        }
    }
}

package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 为 dashboard / AI 事实解释 T2+T3 身份轨预算分配。
 * 不执行探针，且永不升级验证状态。
 */
public final class ProbeBudgetExplainer {
    private ProbeBudgetExplainer() { }

    public record TrackBudgetSummary(
            int maxProbes,
            int plannedProbes,
            int unreachedEntries,
            String strategy,
            List<Map<String, Object>> entryTrackPlans
    ) {
        public TrackBudgetSummary {
            strategy = strategy == null ? "" : strategy;
            entryTrackPlans = List.copyOf(entryTrackPlans == null ? List.of() : entryTrackPlans);
        }
    }

    public static TrackBudgetSummary explain(
            List<ApiDtos.EntryDto> httpEntries,
            int maxProbes,
            List<ExternalArtifactTaskExecutor.ProbeTarget> expanded,
            List<ApiDtos.PathDto> unreached) {
        int cap = Math.max(1, Math.min(512, maxProbes));
        List<Map<String, Object>> rows = new ArrayList<>();
        Map<String, List<String>> tracksByEntry = new LinkedHashMap<>();
        if (expanded != null) {
            for (ExternalArtifactTaskExecutor.ProbeTarget probe : expanded) {
                String key = probe.method() + " " + probe.route();
                tracksByEntry.computeIfAbsent(key, ignored -> new ArrayList<>()).add(probe.track());
            }
        }
        if (httpEntries != null) {
            for (ApiDtos.EntryDto entry : httpEntries) {
                if (entry == null || !"HTTP".equalsIgnoreCase(entry.protocol())) continue;
                String key = (entry.method() == null ? "GET" : entry.method().toUpperCase(Locale.ROOT))
                        + " " + entry.route();
                List<String> tracks = tracksByEntry.getOrDefault(key, List.of());
                boolean highValue = isHighValue(entry.route());
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("entryId", entry.id());
                row.put("method", entry.method());
                row.put("route", entry.route());
                row.put("highValue", highValue);
                row.put("plannedTracks", tracks);
                row.put("policy", highValue
                        ? "T2: UNAUTH+USER+ADMIN+BYPASS when synthesizable"
                        : "T3: UNAUTH+ADMIN when synthesizable");
                if (tracks.isEmpty()) {
                    row.put("stopReason", "PROBE_BUDGET");
                }
                rows.add(row);
                if (rows.size() >= 64) break;
            }
        }
        return new TrackBudgetSummary(
                cap,
                expanded == null ? 0 : expanded.size(),
                unreached == null ? 0 : unreached.size(),
                "T2 high-value four-track / T3 UNAUTH+ADMIN; hard cap " + cap,
                rows);
    }

    private static boolean isHighValue(String route) {
        if (route == null) return false;
        String value = route.toLowerCase(Locale.ROOT);
        return value.contains("admin") || value.contains("upload") || value.contains("deploy")
                || value.contains("token") || value.contains("exec") || value.contains("oauth")
                || value.contains("blade-");
    }

    public static List<String> defaultTracks(boolean highValue) {
        if (highValue) {
            return List.of(
                    IdentityTrack.UNAUTH.name(),
                    IdentityTrack.USER.name(),
                    IdentityTrack.ADMIN.name(),
                    IdentityTrack.BYPASS_CANDIDATE.name());
        }
        return List.of(IdentityTrack.UNAUTH.name(), IdentityTrack.ADMIN.name());
    }
}

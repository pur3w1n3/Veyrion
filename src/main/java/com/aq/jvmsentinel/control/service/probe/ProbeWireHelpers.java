package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.analysis.experiment.ProbeParameterHeuristics;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** 探针 wire 字段规范化与高价值路由判定。 */
public final class ProbeWireHelpers {
    private ProbeWireHelpers() {
    }

    /** 将 `{pathVar}` 模板替换为有界合成 token，供 loopback 探针使用。 */
    public static String materializeRoute(String route) {
        if (route == null || route.isBlank()) return "/";
        String materialized = route.replaceAll("\\{[A-Za-z_][A-Za-z0-9_]{0,63}}", "1");
        if (!materialized.matches("/[A-Za-z0-9_./:-]{0,1023}")) {
            throw new IllegalArgumentException("materialized probe route is invalid");
        }
        return materialized;
    }

    /** 针对已发现参数生成有界合成 query（仅 INFERENCE 刺激）。 */
    public static String syntheticQuery(ApiDtos.EntryDto entry) {
        if (entry == null || entry.parameters() == null || entry.parameters().isEmpty()) {
            return "";
        }
        return ProbeParameterHeuristics.buildSyntheticQuery(entry.parameters(), entry.route());
    }

    /** 剥离 Authorization / secondary-auth token 前导 Bearer scheme。 */
    public static String normalizeProbeToken(String authorizationHeader) {
        if (authorizationHeader == null) return "";
        String token = authorizationHeader.trim();
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return token.substring(7).trim();
        }
        // 保留刻意留空的 material（如 EMPTY_BEARER " "），避免 trim 抹掉。
        if (token.isEmpty() && !authorizationHeader.isEmpty()) return authorizationHeader;
        return token;
    }

    /** 将 ProbeTarget.query 约束在 wire charset/长度内。 */
    public static String sanitizeQuery(String query) {
        if (query == null || query.isBlank()) {
            return "";
        }
        String safe = query.trim().replaceAll("[^A-Za-z0-9_=&%./{}:-]", "");
        if (safe.length() > 256) {
            safe = safe.substring(0, 256);
        }
        return safe.matches("[A-Za-z0-9_=&%./{}:-]{1,256}") ? safe : "";
    }

    /** 将 ProbeTarget.experimentPlanId 约束在 wire charset/长度内。 */
    public static String sanitizeExperimentPlanId(String experimentPlanId) {
        if (experimentPlanId == null || experimentPlanId.isBlank()) {
            return "";
        }
        String safe = experimentPlanId.trim().replaceAll("[^A-Za-z0-9_.:/-]", "_");
        if (safe.length() > 128) {
            safe = safe.substring(0, 100) + "-" + Integer.toHexString(safe.hashCode());
            if (safe.length() > 128) {
                safe = safe.substring(0, 128);
            }
        }
        return safe.matches("[A-Za-z0-9_.:/-]{1,128}") ? safe : "";
    }

    public static IdentityTrack identityTrackFromWire(String track) {
        if (track == null || track.isBlank()) {
            return IdentityTrack.ADMIN;
        }
        try {
            return IdentityTrack.valueOf(track.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return IdentityTrack.ADMIN;
        }
    }

    public static boolean containsHighValueSignal(String value) {
        return FrameworkAdapterRegistry.containsHighValueSignal(value);
    }

    public static boolean isHighValueRoute(String route) {
        return containsHighValueSignal(route);
    }

    public static boolean isHighValueEntry(ApiDtos.EntryDto entry) {
        return containsHighValueSignal(entry.declaringClass())
                || containsHighValueSignal(entry.module())
                || entry.preconditions().stream().anyMatch(ProbeWireHelpers::containsHighValueSignal)
                || entry.evidenceRefs().stream().anyMatch(ProbeWireHelpers::containsHighValueSignal);
    }

    public static String routeKey(ApiDtos.EntryDto entry) {
        String method = entry.method() == null || "UNKNOWN".equalsIgnoreCase(entry.method())
                ? "GET" : entry.method().toUpperCase(Locale.ROOT);
        return routeKey(method, entry.route());
    }

    public static String routeKey(String method, String route) {
        return method.toUpperCase(Locale.ROOT) + " " + materializeRoute(route);
    }

    public static String parameterName(String parameter) {
        String name = ProbeParameterHeuristics.resolveName(parameter);
        return name.isBlank() ? null : name;
    }

    public static ExternalArtifactTaskExecutor.ProbeTarget probeTargetFor(ApiDtos.EntryDto entry) {
        String method = entry.method() == null ? "GET" : entry.method().toUpperCase(Locale.ROOT);
        if ("UNKNOWN".equals(method)) method = "GET";
        return new ExternalArtifactTaskExecutor.ProbeTarget(
                method, materializeRoute(entry.route()), syntheticQuery(entry), "UNAUTH", "");
    }

    /** 拒绝无 experimentPlanId 的空 GET/POST 探针作为主覆盖（P0-18/P0-21）。 */
    public static List<ExternalArtifactTaskExecutor.ProbeTarget> rejectEmptyCoverageWithoutPlan(
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes) {
        if (probes == null || probes.isEmpty()) return List.of();
        List<ExternalArtifactTaskExecutor.ProbeTarget> kept = new ArrayList<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
            if (probe == null) continue;
            boolean getOrPost = "GET".equals(probe.method()) || "POST".equals(probe.method());
            boolean emptyInput = probe.query() == null || probe.query().isBlank();
            boolean missingPlan = probe.experimentPlanId() == null || probe.experimentPlanId().isBlank();
            if (getOrPost && emptyInput && missingPlan) {
                continue;
            }
            kept.add(probe);
        }
        return List.copyOf(kept);
    }
}

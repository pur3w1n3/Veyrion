package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.worker.AgentJsonlTraceConverter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 将孤儿 PROCESS/EFFECT 事件按路由回挂到 PathRun 窗口。
 *
 * <p>并行探针 / 轨迹预算可能导致 LOOPBACK correlation 与 in-app EFFECT correlation
 * 不一致；同 route 上的危险 sink 效果仍应进入对应 PathTrace，供 H4 确认门禁使用。
 */
public final class EffectRouteBinder {
    private EffectRouteBinder() {
    }

    /**
     * @param corrToRoutes correlationId → routes observed on filter/servlet events
     * @param orphanEffects PROCESS/EFFECT events not drained into any PathRun window
     * @param route        PathRun route (e.g. {@code /generator/check/code})
     */
    public static List<AgentJsonlTraceConverter.AgentEvent> effectsForRoute(
            Map<String, Set<String>> corrToRoutes,
            List<AgentJsonlTraceConverter.AgentEvent> orphanEffects,
            String route) {
        String normalized = normalizeRoute(route);
        if (normalized.isBlank() || orphanEffects == null || orphanEffects.isEmpty()) {
            return List.of();
        }
        List<AgentJsonlTraceConverter.AgentEvent> out = new ArrayList<>();
        for (AgentJsonlTraceConverter.AgentEvent event : orphanEffects) {
            if (event == null) continue;
            if (!isEffectLike(event)) continue;
            String corr = correlationOf(event);
            if (corr.isBlank()) continue;
            Set<String> routes = corrToRoutes == null ? Set.of() : corrToRoutes.getOrDefault(corr, Set.of());
            if (routes.stream().anyMatch(r -> routesMatch(normalized, r))) {
                out.add(event);
            }
        }
        return List.copyOf(out);
    }

    /**
     * 预算耗尽后 filter/servlet 可能未写入 route 索引；仍按探针 correlation
     * 挂接已写入的危险 EFFECT（含 DATASOURCE_METHOD SSRF）。
     */
    public static List<AgentJsonlTraceConverter.AgentEvent> effectsForCorrelation(
            List<AgentJsonlTraceConverter.AgentEvent> orphanEffects,
            String correlationId) {
        String corr = correlationId == null ? "" : correlationId.trim();
        if (corr.isBlank() || orphanEffects == null || orphanEffects.isEmpty()) {
            return List.of();
        }
        List<AgentJsonlTraceConverter.AgentEvent> out = new ArrayList<>();
        for (AgentJsonlTraceConverter.AgentEvent event : orphanEffects) {
            if (event == null || !isEffectLike(event)) continue;
            if (corr.equals(correlationOf(event))) {
                out.add(event);
            }
        }
        return List.copyOf(out);
    }

    public static void rememberRoute(
            Map<String, Set<String>> corrToRoutes,
            AgentJsonlTraceConverter.AgentEvent event) {
        if (corrToRoutes == null || event == null) return;
        Map<String, String> detail = event.detail();
        if (detail == null) return;
        String route = detail.getOrDefault("route", "").trim();
        String corr = correlationOf(event);
        if (route.isBlank() || corr.isBlank()) return;
        corrToRoutes.computeIfAbsent(corr, ignored -> new LinkedHashSet<>()).add(normalizeRoute(route));
    }

    public static Map<String, Set<String>> newCorrRouteIndex() {
        return new LinkedHashMap<>();
    }

    public static boolean isEffectLike(AgentJsonlTraceConverter.AgentEvent event) {
        if (event == null) return false;
        String type = event.eventType() == null ? "" : event.eventType();
        if ("PROCESS".equals(type) || "JNDI".equals(type) || "FILE".equals(type)
                || "HTTP_CLIENT".equals(type)) {
            return true;
        }
        Map<String, String> detail = event.detail();
        return detail != null && "EFFECT_TRIGGERED".equals(detail.getOrDefault("pathDebugKind", ""));
    }

    private static String correlationOf(AgentJsonlTraceConverter.AgentEvent event) {
        if (event == null || event.detail() == null) return "";
        return event.detail().getOrDefault("correlationId", "").trim();
    }

    private static String normalizeRoute(String route) {
        if (route == null) return "";
        String trimmed = route.trim();
        if (trimmed.isBlank()) return "";
        int q = trimmed.indexOf('?');
        if (q >= 0) trimmed = trimmed.substring(0, q);
        if (!trimmed.startsWith("/")) trimmed = "/" + trimmed;
        while (trimmed.length() > 1 && trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static boolean routesMatch(String expected, String candidate) {
        String a = normalizeRoute(expected).toLowerCase(Locale.ROOT);
        String b = normalizeRoute(candidate).toLowerCase(Locale.ROOT);
        return !a.isBlank() && a.equals(b);
    }
}

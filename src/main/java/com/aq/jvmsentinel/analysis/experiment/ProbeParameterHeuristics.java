package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.model.ParameterSpec;

import java.util.Locale;
import java.util.Set;

/**
 * 说明：dynamic probe query/body binding 有界 charset-safe 样本值。
 * 存在命名 parameter 时优先诚实 exploration literal 而非空 input。
 * 值须 survive {@code ProbeTarget.query} wire charset {@code [A-Za-z0-9_=&%./{}:-]}。
 */
public final class ProbeParameterHeuristics {
    private static final Set<String> EXPRESSION_NAMES = Set.of(
            "code", "expr", "expression", "script", "spel", "ognl", "mvel", "aviator",
            "formula", "template", "eval", "groovy", "jexl", "el", "ql", "qlexpress");

    private ProbeParameterHeuristics() {
    }

    /** Resolve a parameter name from entry legacy encodings or simple {@code name=value}. */
    public static String resolveName(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String trimmed = raw.trim();
        if (trimmed.contains("name=")) {
            return ParameterSpec.fromLegacy(trimmed).name();
        }
        if (trimmed.contains("=") && !trimmed.contains(",")) {
            String name = trimmed.substring(0, trimmed.indexOf('=')).trim();
            return name.matches("[A-Za-z][A-Za-z0-9_]{0,63}") ? name : "";
        }
        if (trimmed.matches("[A-Za-z][A-Za-z0-9_]{0,63}")) {
            return trimmed;
        }
        return ParameterSpec.fromLegacy(trimmed).name();
    }

    /**
     * 来自简单 {@code name=value} 编码的显式样本；结构性
     * {@code name=…, type=…} encodings (sample must come from heuristics).
     */
    public static String declaredSample(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String trimmed = raw.trim();
        if (trimmed.contains("name=")) {
            return "";
        }
        if (trimmed.contains("=") && !trimmed.contains(",")) {
            return trimmed.substring(trimmed.indexOf('=') + 1).trim();
        }
        return "";
    }

    public static String sampleValueFor(String paramName, String routeHint) {
        String name = paramName == null ? "" : paramName.trim();
        if (name.isBlank()) {
            return "";
        }
        String lower = name.toLowerCase(Locale.ROOT);
        String route = routeHint == null ? "" : routeHint.toLowerCase(Locale.ROOT);
        if (looksExpression(lower, route)) {
            // 数字 literal：charset-safe，QLExpress / SpEL / Aviator / MVEL 可接受。
            return "1";
        }
        if ("businessId".equals(name) || lower.endsWith("id") || lower.endsWith("ids")) {
            return "1";
        }
        if (lower.contains("sql") || lower.contains("query") || "q".equals(lower)
                || lower.contains("where") || lower.contains("filter")) {
            return "1";
        }
        return "synthetic";
    }

    public static boolean looksExpression(String lowerName, String routeHint) {
        if (lowerName == null || lowerName.isBlank()) {
            return false;
        }
        if (EXPRESSION_NAMES.contains(lowerName)) {
            return true;
        }
        if (lowerName.endsWith("expr") || lowerName.endsWith("script")
                || lowerName.endsWith("expression") || lowerName.endsWith("formula")) {
            return true;
        }
        String route = routeHint == null ? "" : routeHint.toLowerCase(Locale.ROOT);
        if (route.contains("check/code") || route.contains("/express")
                || route.contains("/eval") || route.contains("qlexpress")
                || route.contains("spel") || route.contains("aviator")) {
            return "code".equals(lowerName) || "value".equals(lowerName)
                    || "content".equals(lowerName) || "input".equals(lowerName);
        }
        return false;
    }

    /**
     * 仅当 compiled query 绑定至少一个真实 entry parameter 名时优先；
     * 否则 fallback 到 {@code fallback}（通常 {@link #buildSyntheticQuery}）。
     */
    public static String preferHonestQuery(String compiledQuery, String fallback,
                                           Iterable<String> parameterEncodings) {
        String fallbackSafe = fallback == null ? "" : fallback;
        if (compiledQuery == null || compiledQuery.isBlank()) {
            return fallbackSafe;
        }
        boolean sawNamedParam = false;
        boolean hit = false;
        if (parameterEncodings != null) {
            for (String encoding : parameterEncodings) {
                String name = resolveName(encoding);
                if (name.isBlank()) {
                    continue;
                }
                sawNamedParam = true;
                if (compiledQuery.contains(name + "=")) {
                    hit = true;
                    break;
                }
            }
        }
        if (sawNamedParam && !hit) {
            return fallbackSafe;
        }
        return compiledQuery;
    }

    public static String buildSyntheticQuery(Iterable<String> parameterEncodings, String routeHint) {
        if (parameterEncodings == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (String encoding : parameterEncodings) {
            if (count >= 12) {
                break;
            }
            String name = resolveName(encoding);
            if (name.isBlank()) {
                continue;
            }
            String declared = declaredSample(encoding);
            String sample = !declared.isBlank() ? declared : sampleValueFor(name, routeHint);
            if (sample.isBlank()) {
                continue;
            }
            // 保持 wire-safe：丢弃 ProbeTarget query charset 外字符。
            String safeSample = sample.replaceAll("[^A-Za-z0-9_%./{}:-]", "");
            if (safeSample.isBlank()) {
                continue;
            }
            if (!sb.isEmpty()) {
                sb.append('&');
            }
            sb.append(name).append('=').append(safeSample);
            count++;
        }
        String joined = sb.toString();
        return joined.length() <= 256 ? joined : joined.substring(0, 256);
    }
}

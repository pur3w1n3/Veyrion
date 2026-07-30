package com.aq.jvmsentinel.analysis.executor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 从配置行解析主站 / management / executor 端口与 path 元数据，供
 * {@link ExecutorEntryAdapter} 与探针合成 {@code host:port/context/...}。
 *
 * <p>证据驱动：未出现的键保持空/未设置；不猜测业务 MVC 路由。
 */
public final class ExecutorSurfaceConfig {
    private static final Pattern KEY_VALUE = Pattern.compile(
            "(?i)^\\s*([A-Za-z0-9._-]+)\\s*[=:]\\s*(.+?)\\s*$");
    private static final Pattern INLINE_KEY_VALUE = Pattern.compile(
            "(?i)([A-Za-z0-9._-]+)\\s*[=:]\\s*([^\\s,;]+)");

    private ExecutorSurfaceConfig() {
    }

    public record Surface(
            int serverPort,
            int managementPort,
            int xxlExecutorPort,
            String servletContextPath,
            String managementBasePath,
            String managementExposureInclude,
            boolean managementPortDistinct
    ) {
        public Surface {
            servletContextPath = normalizePath(servletContextPath);
            managementBasePath = normalizePath(
                    managementBasePath == null || managementBasePath.isBlank()
                            ? "/actuator" : managementBasePath);
            managementExposureInclude = managementExposureInclude == null
                    ? "" : managementExposureInclude.trim();
            managementPortDistinct = managementPort > 0 && serverPort > 0
                    && managementPort != serverPort;
        }

        /** Actuator / management HTTP 应打的端口；未配置 management.port 时回退主站。 */
        public int actuatorListenPort() {
            if (managementPort > 0) {
                return managementPort;
            }
            return serverPort;
        }

        /**
         * management 独立端口时通常不挂 servlet context-path；
         * 同端口时合成 {@code context-path + base-path}。
         */
        public String actuatorContextPath() {
            if (managementPortDistinct) {
                return "";
            }
            return servletContextPath;
        }

        public List<String> toPreconditions(String frameworkTag) {
            List<String> out = new ArrayList<>();
            if (frameworkTag != null && !frameworkTag.isBlank()) {
                out.add(frameworkTag);
            }
            if (serverPort > 0) {
                out.add("serverPort=" + serverPort);
            }
            if (managementPort > 0) {
                out.add("managementPort=" + managementPort);
            }
            if (xxlExecutorPort > 0) {
                out.add("executorPort=" + xxlExecutorPort);
            }
            if (!servletContextPath.isEmpty()) {
                out.add("contextPath=" + servletContextPath);
            }
            if (!managementBasePath.isEmpty()) {
                out.add("basePath=" + managementBasePath);
            }
            if (managementPortDistinct) {
                out.add("portRole=management-distinct");
            }
            return List.copyOf(out);
        }
    }

    public static Surface parse(List<String> configurationLines) {
        Map<String, String> props = flatten(configurationLines);
        int serverPort = parsePort(props.get("server.port"));
        int managementPort = parsePort(first(
                props.get("management.server.port"),
                props.get("management.port")));
        int xxlExecutorPort = parsePort(first(
                props.get("xxl.job.executor.port"),
                props.get("xxl.job.port")));
        String contextPath = first(
                props.get("server.servlet.context-path"),
                props.get("server.servlet.contextPath"),
                props.get("server.context-path"));
        String basePath = first(
                props.get("management.endpoints.web.base-path"),
                props.get("management.endpoints.web.basePath"),
                props.get("management.context-path"));
        String exposure = first(
                props.get("management.endpoints.web.exposure.include"),
                props.get("management.endpoints.web.exposure.include".toLowerCase(Locale.ROOT)));
        return new Surface(serverPort, managementPort, xxlExecutorPort,
                contextPath, basePath, exposure, false);
    }

    public static int listenPortOf(List<String> preconditions) {
        return intTag(preconditions, "listenPort");
    }

    public static int executorPortOf(List<String> preconditions) {
        int listen = intTag(preconditions, "listenPort");
        if (listen > 0) {
            return listen;
        }
        return intTag(preconditions, "executorPort");
    }

    public static String contextPathOf(List<String> preconditions) {
        return stringTag(preconditions, "contextPath");
    }

    public static String basePathOf(List<String> preconditions) {
        return stringTag(preconditions, "basePath");
    }

    /** 合成探针逻辑 route：contextPath + address（已含 basePath 时不重复）。 */
    public static String composeProbeRoute(String contextPath, String address) {
        return joinPath(contextPath, address);
    }

    public static String joinPath(String prefix, String route) {
        String ctx = normalizePath(prefix);
        String path = route == null || route.isBlank() ? "/" : route.trim();
        if (!path.startsWith("/") && !path.contains(":")) {
            path = "/" + path;
        }
        if (ctx.isEmpty()) {
            return path;
        }
        if (path.equals(ctx) || path.startsWith(ctx + "/")) {
            return path;
        }
        if ("/".equals(path)) {
            return ctx;
        }
        return ctx + path;
    }

    public static String normalizePath(String raw) {
        if (raw == null) {
            return "";
        }
        String value = raw.trim();
        if (value.isEmpty() || "/".equals(value)) {
            return "";
        }
        // 去掉引号
        if ((value.startsWith("\"") && value.endsWith("\""))
                || (value.startsWith("'") && value.endsWith("'"))) {
            value = value.substring(1, value.length() - 1).trim();
        }
        if (value.isEmpty() || "/".equals(value)) {
            return "";
        }
        if (!value.startsWith("/")) {
            value = "/" + value;
        }
        while (value.length() > 1 && value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.length() > 128) {
            return "";
        }
        return value;
    }

    public static List<String> withListenPort(List<String> base, int listenPort) {
        List<String> out = new ArrayList<>(base == null ? List.of() : base);
        if (listenPort > 0 && listenPort <= 65_535) {
            out.removeIf(p -> p != null && p.regionMatches(true, 0, "listenPort=", 0, 11));
            out.add("listenPort=" + listenPort);
        }
        return List.copyOf(out);
    }

    public static List<String> withContextPath(List<String> base, String contextPath) {
        List<String> out = new ArrayList<>(base == null ? List.of() : base);
        String normalized = normalizePath(contextPath);
        out.removeIf(p -> p != null && p.regionMatches(true, 0, "contextPath=", 0, 12));
        if (!normalized.isEmpty()) {
            out.add("contextPath=" + normalized);
        }
        return List.copyOf(out);
    }

    private static Map<String, String> flatten(List<String> lines) {
        LinkedHashMap<String, String> props = new LinkedHashMap<>();
        if (lines == null) {
            return props;
        }
        for (String raw : lines) {
            if (raw == null || raw.isBlank() || raw.trim().startsWith("#")) {
                continue;
            }
            Matcher exact = KEY_VALUE.matcher(raw);
            if (exact.find()) {
                props.putIfAbsent(exact.group(1).trim().toLowerCase(Locale.ROOT),
                        exact.group(2).trim());
                continue;
            }
            Matcher inline = INLINE_KEY_VALUE.matcher(raw);
            while (inline.find()) {
                props.putIfAbsent(inline.group(1).trim().toLowerCase(Locale.ROOT),
                        inline.group(2).trim());
            }
        }
        return props;
    }

    private static String first(String... values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private static int parsePort(String raw) {
        if (raw == null || raw.isBlank()) {
            return 0;
        }
        String value = raw.trim();
        if ((value.startsWith("\"") && value.endsWith("\""))
                || (value.startsWith("'") && value.endsWith("'"))) {
            value = value.substring(1, value.length() - 1).trim();
        }
        if (!value.matches("\\d{2,5}")) {
            return 0;
        }
        try {
            int port = Integer.parseInt(value);
            return port >= 1 && port <= 65_535 ? port : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static int intTag(List<String> preconditions, String key) {
        String value = stringTag(preconditions, key);
        if (value.isBlank() || !value.matches("\\d{1,5}")) {
            return 0;
        }
        try {
            int port = Integer.parseInt(value);
            return port >= 1 && port <= 65_535 ? port : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static String stringTag(List<String> preconditions, String key) {
        if (preconditions == null || key == null || key.isBlank()) {
            return "";
        }
        String prefix = key + "=";
        for (String item : preconditions) {
            if (item != null && item.regionMatches(true, 0, prefix, 0, prefix.length())) {
                return item.substring(prefix.length()).trim();
            }
        }
        return "";
    }
}

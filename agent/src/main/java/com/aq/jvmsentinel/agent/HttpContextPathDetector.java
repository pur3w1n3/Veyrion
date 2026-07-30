package com.aq.jvmsentinel.agent;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 从 Tomcat/Catalina / Spring Boot 启动日志与配置行解析 servlet context path，
 * 供 loopback 探针给 MVC 路由加前缀。
 *
 * <p>静态注解映射通常不含 {@code server.servlet.context-path}；缺此前缀时探针打到
 * {@code /} 会全量 404（例如 xxl-job-admin 的 {@code /xxl-job-admin}）。</p>
 */
public final class HttpContextPathDetector {
    /**
     * Catalina 完整 logger：
     * {@code ContainerBase.[Tomcat].[localhost].[/xxl-job-admin]}。
     */
    private static final Pattern CATALINA_FULL = Pattern.compile(
            "(?i)ContainerBase\\.\\[[^\\]]*]\\.\\[[^\\]]*]\\.\\[(/[^\\]\\s]{0,128})]");
    /**
     * 缩短形态（logback 常见）：
     * {@code o.a.c.c.C.[.[.[/xxl-job-admin]}。
     */
    private static final Pattern CATALINA_ABBREV = Pattern.compile(
            "(?i)\\bC\\.\\[\\.\\[\\.\\[(/[^\\]\\s]{1,128})]");
    /** Spring Boot：{@code with context path '/xxl-job-admin'}。 */
    private static final Pattern SPRING_BOOT_CONTEXT = Pattern.compile(
            "(?i)with\\s+context\\s+path\\s+'(/[^']{0,128})'");
    /** 配置：{@code server.servlet.context-path=/xxl-job-admin}。 */
    private static final Pattern SERVER_SERVLET_CONTEXT = Pattern.compile(
            "(?i)server\\.servlet\\.context-path\\s*[=:]\\s*(/\\S{0,128})");

    private static final long MAX_LOG_BYTES = 512L * 1024;

    private HttpContextPathDetector() {
    }

    /**
     * 规范化 context path：空/根 → {@code ""}；否则以 {@code /} 开头、无尾随 {@code /}。
     */
    public static String normalize(String raw) {
        if (raw == null) return "";
        String value = raw.trim();
        if (value.isEmpty() || "/".equals(value)) return "";
        if (!value.startsWith("/")) value = "/" + value;
        while (value.length() > 1 && value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.length() > 128 || !value.matches("/[A-Za-z0-9_./-]{1,127}")) {
            return "";
        }
        return value;
    }

    /** 将逻辑 MVC route 接到 servlet context path（已带前缀则不重复）。 */
    public static String join(String contextPath, String route) {
        String ctx = normalize(contextPath);
        String path = route == null || route.isBlank() ? "/" : route.trim();
        if (!path.startsWith("/")) path = "/" + path;
        if (ctx.isEmpty()) return path;
        if (path.equals(ctx) || path.startsWith(ctx + "/")) return path;
        if ("/".equals(path)) return ctx;
        return ctx + path;
    }

    /**
     * 对可能含 query 的 {@code requestTarget} 仅前缀 path 段。
     */
    public static String joinRequestTarget(String contextPath, String requestTarget) {
        if (requestTarget == null || requestTarget.isBlank()) {
            return join(contextPath, "/");
        }
        int q = requestTarget.indexOf('?');
        if (q < 0) {
            return join(contextPath, requestTarget);
        }
        return join(contextPath, requestTarget.substring(0, q)) + requestTarget.substring(q);
    }

    /** 从日志/配置文本提取 context path；未识别则 {@code ""}。 */
    public static String detectFromText(String text) {
        if (text == null || text.isBlank()) return "";
        String fromSpring = firstGroup(SPRING_BOOT_CONTEXT, text);
        if (!fromSpring.isEmpty()) return fromSpring;
        String fromProperty = firstGroup(SERVER_SERVLET_CONTEXT, text);
        if (!fromProperty.isEmpty()) return fromProperty;
        String fromFull = firstGroup(CATALINA_FULL, text);
        if (!fromFull.isEmpty()) return fromFull;
        return firstGroup(CATALINA_ABBREV, text);
    }

    /** 读取 application.log（尾部有界）并解析；缺失/失败 → {@code ""}。 */
    public static String detectFromApplicationLog(Path traceDir) {
        if (traceDir == null) return "";
        Path log = traceDir.resolve("application.log");
        try {
            if (!Files.isRegularFile(log) || Files.isSymbolicLink(log)) return "";
            long size = Files.size(log);
            if (size <= 0) return "";
            byte[] bytes;
            if (size <= MAX_LOG_BYTES) {
                bytes = Files.readAllBytes(log);
            } else {
                try (var channel = Files.newByteChannel(log)) {
                    channel.position(size - MAX_LOG_BYTES);
                    bytes = new byte[(int) MAX_LOG_BYTES];
                    int read = channel.read(java.nio.ByteBuffer.wrap(bytes));
                    if (read < bytes.length) {
                        byte[] slim = new byte[Math.max(read, 0)];
                        System.arraycopy(bytes, 0, slim, 0, slim.length);
                        bytes = slim;
                    }
                }
            }
            return detectFromText(new String(bytes, StandardCharsets.UTF_8));
        } catch (Exception ignored) {
            return "";
        }
    }

    public static void writeContextPathFile(Path traceDir, String contextPath) {
        if (traceDir == null) return;
        String normalized = normalize(contextPath);
        try {
            Files.createDirectories(traceDir);
            Files.writeString(traceDir.resolve("http-context-path.txt"),
                    normalized + "\n", StandardCharsets.US_ASCII);
        } catch (Exception ignored) {
            // 尽力；探针侧仍可直接解析 application.log。
        }
    }

    public static String readContextPathFile(Path traceDir) {
        if (traceDir == null) return "";
        Path file = traceDir.resolve("http-context-path.txt");
        try {
            if (!Files.isRegularFile(file) || Files.isSymbolicLink(file)) return "";
            long size = Files.size(file);
            if (size < 1 || size > 160) return "";
            return normalize(Files.readString(file, StandardCharsets.US_ASCII));
        } catch (Exception ignored) {
            return "";
        }
    }

    /**
     * 解析顺序：系统属性 → http-context-path.txt → application.log。
     */
    public static String resolve(Path traceDir) {
        String configured = System.getProperty("veyrion.loopbackProbe.contextPath");
        if (configured != null && !configured.isBlank()) {
            return normalize(configured);
        }
        String fromFile = readContextPathFile(traceDir);
        if (!fromFile.isEmpty()) return fromFile;
        return detectFromApplicationLog(traceDir);
    }

    private static String firstGroup(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            String normalized = normalize(matcher.group(1));
            if (!normalized.isEmpty()) return normalized;
            // 显式根 context（"/"）视为无前缀。
            String raw = matcher.group(1) == null ? "" : matcher.group(1).trim();
            if ("/".equals(raw)) return "";
        }
        return "";
    }
}

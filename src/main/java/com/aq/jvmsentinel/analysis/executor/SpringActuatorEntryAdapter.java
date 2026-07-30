package com.aq.jvmsentinel.analysis.executor;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Spring Boot Actuator 管理口适配器。
 *
 * <p>从 {@code management.endpoints.web.exposure.include} /
 * {@code management.server.port} / {@code management.endpoints.web.base-path}
 * 与依赖/类名证据可靠产出 {@code /actuator/*}（或自定义 base-path）入口；
 * 未命中证据不硬造业务 MVC 页。
 */
public final class SpringActuatorEntryAdapter implements ExecutorEntryAdapter {
    public static final String ID = "spring-actuator";
    public static final String FRAMEWORK = "spring-actuator";

    private static final List<EndpointDef> KNOWN = List.of(
            new EndpointDef("health", "GET", "Actuator health"),
            new EndpointDef("info", "GET", "Actuator info"),
            new EndpointDef("env", "GET", "Actuator env (sensitive)"),
            new EndpointDef("loggers", "POST", "Actuator loggers write"),
            new EndpointDef("shutdown", "POST", "Actuator shutdown (if enabled)"),
            new EndpointDef("beans", "GET", "Actuator beans"),
            new EndpointDef("mappings", "GET", "Actuator mappings"),
            new EndpointDef("configprops", "GET", "Actuator configprops"),
            new EndpointDef("threaddump", "GET", "Actuator threaddump"),
            new EndpointDef("heapdump", "GET", "Actuator heapdump"),
            new EndpointDef("prometheus", "GET", "Actuator prometheus")
    );

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String frameworkId() {
        return FRAMEWORK;
    }

    @Override
    public boolean matches(ExecutorEntryContext context) {
        if (context == null) {
            return false;
        }
        return context.configContains("management.endpoints")
                || context.configContains("management.endpoint")
                || context.configContains("management.server")
                || context.classNameContains("org.springframework.boot.actuate")
                || context.classNameContains("EndpointAutoConfiguration")
                || context.archiveEntryContains("spring-boot-actuator");
    }

    @Override
    public List<RuntimeCallbackEntry> discover(ExecutorEntryContext context) {
        if (!matches(context)) {
            return List.of();
        }
        ExecutorSurfaceConfig.Surface surface = ExecutorSurfaceConfig.parse(context.configurationLines());
        String signal = context.configContains("management.endpoints")
                || context.configContains("management.endpoint")
                ? "config:management.endpoints"
                : context.archiveEntryContains("spring-boot-actuator")
                ? "archive:spring-boot-actuator"
                : "class-name:actuate";

        String basePath = surface.managementBasePath().isEmpty()
                ? "/actuator" : surface.managementBasePath();
        Set<String> exposed = parseExposure(surface.managementExposureInclude());
        boolean exposureConfigured = !surface.managementExposureInclude().isBlank();

        List<String> frameworkPre = new ArrayList<>();
        frameworkPre.add("framework:" + FRAMEWORK);
        frameworkPre.add("callbackKind:management-http");
        frameworkPre.addAll(surface.toPreconditions(null));
        int listenPort = surface.actuatorListenPort();
        frameworkPre = new ArrayList<>(ExecutorSurfaceConfig.withListenPort(frameworkPre, listenPort));
        String ctxPath = surface.actuatorContextPath();
        frameworkPre = new ArrayList<>(ExecutorSurfaceConfig.withContextPath(frameworkPre, ctxPath));
        if (frameworkPre.stream().noneMatch(p -> p != null && p.startsWith("basePath="))) {
            frameworkPre.add("basePath=" + basePath);
        }

        List<RuntimeCallbackEntry> out = new ArrayList<>();
        // index
        out.add(entry(basePath, "GET", "org.springframework.boot.actuate.endpoint.web.servlet.WebMvcEndpointHandlerMapping",
                frameworkPre, signal, surface, "Actuator index"));

        for (EndpointDef def : KNOWN) {
            if (exposureConfigured && !exposed.contains("*") && !exposed.contains(def.id())) {
                continue;
            }
            // 无 exposure 配置时仅产出常见安全相关子集，避免无证据灌入全量端点。
            if (!exposureConfigured && !Set.of("health", "info", "env", "loggers", "shutdown").contains(def.id())) {
                continue;
            }
            String route = ExecutorSurfaceConfig.joinPath(basePath, "/" + def.id());
            out.add(entry(route, def.method(),
                    "org.springframework.boot.actuate.endpoint.web.servlet.WebMvcEndpointHandlerMapping",
                    frameworkPre, signal, surface, def.summary()));
        }
        return List.copyOf(out);
    }

    @Override
    public Set<String> highValueRouteSignals() {
        return Set.of("/actuator", "/actuator/env", "/actuator/shutdown",
                "/actuator/heapdump", "/actuator/mappings");
    }

    @Override
    public Set<String> highValueClassSignals() {
        return Set.of("springframework.boot.actuate", "actuator");
    }

    private static RuntimeCallbackEntry entry(
            String route,
            String method,
            String symbol,
            List<String> preconditions,
            String signal,
            ExecutorSurfaceConfig.Surface surface,
            String summary) {
        StringBuilder detail = new StringBuilder(summary);
        detail.append("; presence=").append(signal);
        detail.append("; basePath=").append(surface.managementBasePath().isEmpty()
                ? "/actuator" : surface.managementBasePath());
        if (surface.managementPort() > 0) {
            detail.append("; management.server.port=").append(surface.managementPort());
        }
        if (surface.managementPortDistinct()) {
            detail.append("; distinct management port (no servlet context-path)");
        } else if (!surface.servletContextPath().isEmpty()) {
            detail.append("; contextPath=").append(surface.servletContextPath());
        }
        if (!surface.managementExposureInclude().isBlank()) {
            detail.append("; exposure.include=").append(surface.managementExposureInclude());
        } else {
            detail.append("; exposure not configured — default sensitive subset only");
        }
        detail.append("; security not proven; INFERENCE from actuator signals");
        return new RuntimeCallbackEntry(
                ID,
                FRAMEWORK,
                "HTTP",
                method,
                route,
                symbol,
                List.of(),
                List.copyOf(preconditions),
                "executor-adapter:" + ID + ":" + route,
                detail.toString(),
                "INFERENCE",
                0.74);
    }

    private static Set<String> parseExposure(String raw) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (raw == null || raw.isBlank()) {
            return out;
        }
        for (String part : raw.split("[,\\s]+")) {
            if (part == null || part.isBlank()) {
                continue;
            }
            out.add(part.trim().toLowerCase(Locale.ROOT));
        }
        return out;
    }

    private record EndpointDef(String id, String method, String summary) {
    }
}

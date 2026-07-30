package com.aq.jvmsentinel.analysis.executor;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Spring Boot Actuator 管理口轻量启发式（第二适配器骨架）。
 * 仅在配置 / 类名 / archive 证据命中时产出常见 actuator 路由；不硬造业务 MVC 页。
 */
public final class SpringActuatorEntryAdapter implements ExecutorEntryAdapter {
    public static final String ID = "spring-actuator";
    public static final String FRAMEWORK = "spring-actuator";

    private static final List<Surface> SURFACES = List.of(
            new Surface("GET", "/actuator", "Actuator index"),
            new Surface("GET", "/actuator/health", "Actuator health"),
            new Surface("GET", "/actuator/info", "Actuator info"),
            new Surface("GET", "/actuator/env", "Actuator env (sensitive)"),
            new Surface("POST", "/actuator/loggers", "Actuator loggers write"),
            new Surface("POST", "/actuator/shutdown", "Actuator shutdown (if enabled)")
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
        String signal = context.configContains("management.endpoints")
                || context.configContains("management.endpoint")
                ? "config:management.endpoints"
                : context.archiveEntryContains("spring-boot-actuator")
                ? "archive:spring-boot-actuator"
                : "class-name:actuate";
        List<RuntimeCallbackEntry> out = new ArrayList<>();
        for (Surface surface : SURFACES) {
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    surface.method(),
                    surface.route(),
                    "org.springframework.boot.actuate.endpoint.web.servlet.WebMvcEndpointHandlerMapping",
                    List.of(),
                    List.of("framework:" + FRAMEWORK, "callbackKind:management-http"),
                    "executor-adapter:" + ID + ":" + surface.route(),
                    surface.summary() + "; presence=" + signal
                            + "; exposure/security not proven; INFERENCE from actuator signals",
                    "INFERENCE",
                    0.72));
        }
        return List.copyOf(out);
    }

    @Override
    public Set<String> highValueRouteSignals() {
        return Set.of("/actuator", "/actuator/env", "/actuator/shutdown");
    }

    @Override
    public Set<String> highValueClassSignals() {
        return Set.of("springframework.boot.actuate", "actuator");
    }

    private record Surface(String method, String route, String summary) {
    }
}

package com.aq.jvmsentinel.instrumentation;

import com.aq.jvmsentinel.instrumentation.mock.DependencyMockBootstrap;

import java.lang.instrument.Instrumentation;
import java.util.Map;

/**
 * 最小 Java 17 观测 agent。非沙箱，也非安全边界。
 */
public final class VeyrionAgent {
    private VeyrionAgent() {
    }

    public static void premain(String arguments, Instrumentation instrumentation) {
        start(arguments, instrumentation, "premain");
    }

    public static void agentmain(String arguments, Instrumentation instrumentation) {
        start(arguments, instrumentation, "agentmain");
    }

    private static void start(String arguments, Instrumentation instrumentation, String entryPoint) {
        if (instrumentation == null) throw new IllegalArgumentException("instrumentation is required");
        AgentConfig config = AgentConfig.parse(arguments);
        EventWriter writer = new EventWriter(config);
        boolean installed = false;
        try {
            AgentRuntime.install(writer, config.coverageEnabled);
            installed = true;
            if (!writer.writeObserved("AGENT_STARTED", VeyrionAgent.class.getName(), entryPoint,
                    Map.of("captureMode", "BYTE_BUDDY_STARTUP_INSTRUMENTATION",
                            "securityBoundary", "false",
                            "bootstrapTransform", "false"))) {
                throw new IllegalStateException("agent output budget cannot hold startup event");
            }
            java.util.LinkedHashMap<String, String> caps = new java.util.LinkedHashMap<>();
            caps.put("springServlet", "CONDITIONAL_NON_BOOTSTRAP_METHOD");
            caps.put("jdbc", config.dependencyMock
                    ? "MOCK_DRIVER_OR_LOOPBACK_MYSQL_CLASSIC" : "NON_BOOTSTRAP_IMPLEMENTATION_METHOD");
            caps.put("redis", config.dependencyMock ? "LOOPBACK_RESP2_RESP3_SUBSET" : "UNSUPPORTED");
            caps.put("networkRequests", "APPLICATION_CALL_SITE_URL_HTTPURLCONNECTION");
            caps.put("dnsLookups", "APPLICATION_CALL_SITE_GATED");
            caps.put("socketConnect", "NOT_HOOKED_TOO_COARSE");
            caps.put("jdkHttpClient", "APPLICATION_CALL_SITE");
            caps.put("fileWrite", "APPLICATION_CALL_SITE_FILE_WRITE");
            caps.put("fileRead", "APPLICATION_CALL_SITE_FILE_READ_GATED");
            caps.put("deserialization", "APPLICATION_CALL_SITE_OBJECT_INPUT");
            caps.put("process", "APPLICATION_CALL_SITE");
            caps.put("branchCoverage", config.coverageEnabled
                    ? "REQUEST_SCOPED_BRANCH_SITE_HITS" : "DISABLED");
            caps.put("bootstrapClasses", "UNSUPPORTED_FAIL_EXPLICIT");
            writer.writeObserved("INSTRUMENTATION_CAPABILITY", VeyrionAgent.class.getName(),
                    entryPoint, caps);
            DependencyMockBootstrap.install(instrumentation, config.dependencyMock, config.worldPackDependencyMode);
            instrumentation.addTransformer(new ObservationTransformer(config), false);
            AutomaticInstrumentation.install(instrumentation, config, writer);
        } catch (RuntimeException | Error failure) {
            if (installed) AgentRuntime.uninstall(writer);
            try {
                writer.close();
            } catch (Exception ignored) {
                failure.addSuppressed(ignored);
            }
            throw failure;
        }
    }
}

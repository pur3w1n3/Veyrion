package com.aq.jvmsentinel.instrumentation;

import com.aq.jvmsentinel.instrumentation.mock.DependencyMockBootstrap;

import java.lang.instrument.Instrumentation;
import java.util.Map;

/**
 * Minimal Java 17 observation agent. It is not a sandbox or a security boundary.
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
            writer.writeObserved("INSTRUMENTATION_CAPABILITY", VeyrionAgent.class.getName(), entryPoint,
                    Map.of("springServlet", "CONDITIONAL_NON_BOOTSTRAP_METHOD",
                            "jdbc", config.dependencyMock ? "MOCK_DRIVER_OR_LOOPBACK_MYSQL_CLASSIC" : "NON_BOOTSTRAP_IMPLEMENTATION_METHOD",
                            "redis", config.dependencyMock ? "LOOPBACK_RESP2_RESP3_SUBSET" : "UNSUPPORTED",
                            "networkRequests", "APPLICATION_CALL_SITE",
                            "dnsLookups", "APPLICATION_CALL_SITE",
                            "jdkHttpClient", "APPLICATION_CALL_SITE",
                            "fileWrite", "APPLICATION_CALL_SITE",
                            "process", "APPLICATION_CALL_SITE",
                            "branchCoverage", config.coverageEnabled
                                    ? "REQUEST_SCOPED_BRANCH_SITE_HITS" : "DISABLED",
                            "bootstrapClasses", "UNSUPPORTED_FAIL_EXPLICIT"));
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

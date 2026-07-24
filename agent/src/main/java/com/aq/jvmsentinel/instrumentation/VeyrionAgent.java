package com.aq.jvmsentinel.instrumentation;

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
            AgentRuntime.install(writer);
            installed = true;
            if (!writer.write("AGENT_STARTED", VeyrionAgent.class.getName(), entryPoint,
                    Map.of("captureMode", "CLASS_LOAD_AND_EXPLICIT_PROBES",
                            "automaticMethodCapture", "false",
                            "automaticDependencyCapture", "false"))) {
                throw new IllegalStateException("agent output budget cannot hold startup event");
            }
            instrumentation.addTransformer(new ObservationTransformer(config.classPrefix), false);
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

package com.aq.jvmsentinel.instrumentation;

import java.util.Map;

/**
 * Explicit observation probes for trusted fixture or application integration.
 *
 * <p>This first slice does not rewrite bytecode and therefore does not automatically capture method calls,
 * HTTP, JDBC, file, or process operations. Those event types are emitted only when code calls this API.</p>
 */
public final class AgentRuntime {
    private static volatile EventWriter writer;

    private AgentRuntime() {
    }

    public static boolean recordHttp(String className, String methodName, Map<String, String> detail) {
        return record("HTTP", className, methodName, detail);
    }

    public static boolean recordFile(String className, String methodName, Map<String, String> detail) {
        return record("FILE", className, methodName, detail);
    }

    public static boolean recordJdbc(String className, String methodName, Map<String, String> detail) {
        return record("JDBC", className, methodName, detail);
    }

    public static boolean recordProcess(String className, String methodName, Map<String, String> detail) {
        return record("PROCESS", className, methodName, detail);
    }

    static boolean recordClassLoad(String className) {
        return record("CLASS_LOAD", className, "", Map.of("captureMode", "CLASSFILE_OBSERVATION"));
    }

    static void install(EventWriter eventWriter) {
        if (writer != null) throw new IllegalStateException("agent runtime is already installed");
        writer = eventWriter;
    }

    static void uninstall(EventWriter eventWriter) {
        if (writer == eventWriter) writer = null;
    }

    static boolean record(String eventType, String className, String methodName, Map<String, String> detail) {
        EventWriter current = writer;
        return current != null && !current.isStopped() && current.write(eventType, className, methodName, detail);
    }
}

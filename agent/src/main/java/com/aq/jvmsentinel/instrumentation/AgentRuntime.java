package com.aq.jvmsentinel.instrumentation;

import java.util.Map;

/**
 * Explicit observation probes for trusted fixture or application integration.
 *
 * <p>Events emitted through this public API are always {@code APPLICATION_REPORTED}. Automatic bytecode
 * instrumentation uses a separate path. Because the Agent shares a JVM with the target, even instrumented
 * events remain suspect until an out-of-process Worker validates and replays the trace.</p>
 */
public final class AgentRuntime {
    private static volatile EventWriter writer;
    private static final ThreadLocal<Boolean> IN_AUTOMATIC_OBSERVATION =
            ThreadLocal.withInitial(() -> false);

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
        EventWriter current = writer;
        return current != null && !current.isStopped()
                && current.writeObserved("CLASS_LOAD", className, "",
                Map.of("captureMode", "CLASSFILE_OBSERVATION"));
    }

    public static void recordInstrumentedCall(String eventType, String callerClass, String callerMethod,
                                              String targetClass, String targetMethod,
                                              String instructionOrdinal) {
        recordInstrumented(eventType, callerClass, callerMethod,
                Map.of("captureMode", "APPLICATION_CALL_SITE",
                        "targetClass", targetClass,
                        "targetMethod", targetMethod,
                        "instructionOrdinal", instructionOrdinal));
    }

    public static void recordTransformedMethod(String eventType, String className, String methodName,
                                               String captureMode) {
        recordInstrumented(eventType, className, methodName,
                Map.of("captureMode", captureMode, "operation", methodName));
    }

    private static void recordInstrumented(String eventType, String className, String methodName,
                                           Map<String, String> detail) {
        EventWriter current = writer;
        if (current == null || current.isStopped() || IN_AUTOMATIC_OBSERVATION.get()) return;
        IN_AUTOMATIC_OBSERVATION.set(true);
        try {
            current.writeInstrumented(eventType, className, methodName, detail);
        } finally {
            IN_AUTOMATIC_OBSERVATION.set(false);
        }
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
        return current != null && !current.isStopped()
                && current.writeApplication(eventType, className, methodName, detail);
    }
}

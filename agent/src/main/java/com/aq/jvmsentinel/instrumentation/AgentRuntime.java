package com.aq.jvmsentinel.instrumentation;

import java.util.BitSet;
import java.util.LinkedHashMap;
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
    private static volatile boolean coverageEnabled;
    private static final ThreadLocal<Boolean> IN_AUTOMATIC_OBSERVATION =
            ThreadLocal.withInitial(() -> false);
    private static final ThreadLocal<CoverageState> COVERAGE_STATE =
            ThreadLocal.withInitial(CoverageState::new);
    /** Per-request correlation for HTTP→JDBC join (P0-06). */
    private static final ThreadLocal<String> REQUEST_CORRELATION =
            ThreadLocal.withInitial(() -> "");
    private static final ThreadLocal<Integer> REQUEST_CORRELATION_DEPTH =
            ThreadLocal.withInitial(() -> 0);

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
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put("captureMode", "APPLICATION_CALL_SITE");
        detail.put("targetClass", targetClass);
        detail.put("targetMethod", targetMethod);
        detail.put("instructionOrdinal", instructionOrdinal);
        if ("PROCESS".equals(eventType) || "FILE".equals(eventType) || "HTTP_CLIENT".equals(eventType)) {
            detail.putAll(PathDebugDetail.effectTriggered(eventType));
        }
        recordInstrumented(eventType, callerClass, callerMethod, detail);
    }

    public static void recordTransformedMethod(String eventType, String className, String methodName,
                                               String captureMode) {
        recordInstrumented(eventType, className, methodName,
                Map.of("captureMode", captureMode, "operation", methodName));
    }

    /** Instrumented observation with additional sanitized detail fields (route, SQL, etc.). */
    public static void recordTransformedDetail(String eventType, String className, String methodName,
                                               Map<String, String> detail) {
        recordInstrumented(eventType, className, methodName, detail);
    }

    /**
     * Starts (or nests inside) an HTTP request coverage scope. Public because Byte Buddy advice is
     * inlined into application and framework classes.
     */
    public static boolean beginCoverageRequest() {
        if (!coverageEnabled) return false;
        CoverageState state = COVERAGE_STATE.get();
        if (state.depth == 0) state.hits.clear();
        state.depth++;
        return true;
    }

    /** Bind server-observed correlation id for the active HTTP request scope. */
    public static void bindRequestCorrelation(String correlationId) {
        // Every HTTP Advice enter owns one balanced scope, even if that layer cannot
        // access the request header. Otherwise a blank nested view clears the outer id.
        REQUEST_CORRELATION_DEPTH.set(REQUEST_CORRELATION_DEPTH.get() + 1);
        if (correlationId == null) return;
        String trimmed = correlationId.trim();
        if (trimmed.isEmpty() || trimmed.length() > 64) return;
        if (!trimmed.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")) return;
        if (REQUEST_CORRELATION.get().isEmpty()) {
            REQUEST_CORRELATION.set(trimmed);
        }
    }

    public static String currentRequestCorrelation() {
        String value = REQUEST_CORRELATION.get();
        return value == null ? "" : value;
    }

    public static void releaseRequestCorrelation() {
        int depth = REQUEST_CORRELATION_DEPTH.get() - 1;
        if (depth <= 0) {
            REQUEST_CORRELATION.remove();
            REQUEST_CORRELATION_DEPTH.remove();
            return;
        }
        REQUEST_CORRELATION_DEPTH.set(depth);
    }

    /**
     * Ends an HTTP scope and emits compact coverage events when the outermost boundary returns.
     * Prefer the no-arg form from Byte Buddy advice so {@code disableClassFormatChanges} paths
     * do not depend on {@code @Advice.Enter} locals (boolean enter breaks HTTP advice weaving).
     */
    public static void endCoverageRequest() {
        endCoverageRequest(coverageEnabled);
    }

    /** Ends an HTTP scope when {@code entered} is true (legacy Advice.Enter boolean path). */
    public static void endCoverageRequest(boolean entered) {
        if (!entered || !coverageEnabled) return;
        CoverageState state = COVERAGE_STATE.get();
        if (state.depth <= 0) {
            COVERAGE_STATE.remove();
            return;
        }
        state.depth--;
        if (state.depth != 0) return;
        try {
            for (Map.Entry<MethodKey, BitSet> entry : state.hits.entrySet()) {
                MethodKey method = entry.getKey();
                for (Map<String, String> detail : CoverageEventSerializer.serialize(
                        method.className, method.methodDescriptor, entry.getValue())) {
                    recordInstrumented("BRANCH_COVERAGE", method.className,
                            method.methodDescriptor, detail);
                }
            }
        } finally {
            COVERAGE_STATE.remove();
        }
    }

    /** Records one reached conditional-branch or switch site in the active request scope. */
    public static void recordBranchHit(String className, String methodDescriptor, int branchIndex) {
        if (!coverageEnabled || branchIndex < 0) return;
        CoverageState state = COVERAGE_STATE.get();
        if (state.depth <= 0) return;
        MethodKey key = new MethodKey(className == null ? "" : className,
                methodDescriptor == null ? "" : methodDescriptor);
        state.hits.computeIfAbsent(key, ignored -> new BitSet()).set(branchIndex);
    }

    private static void recordInstrumented(String eventType, String className, String methodName,
                                           Map<String, String> detail) {
        EventWriter current = writer;
        if (current == null || current.isStopped() || IN_AUTOMATIC_OBSERVATION.get()) return;
        IN_AUTOMATIC_OBSERVATION.set(true);
        try {
            current.writeInstrumented(eventType, className, methodName, withCorrelation(detail));
        } finally {
            IN_AUTOMATIC_OBSERVATION.set(false);
        }
    }

    private static Map<String, String> withCorrelation(Map<String, String> detail) {
        String corr = currentRequestCorrelation();
        if (corr.isEmpty()) return detail == null ? Map.of() : detail;
        Map<String, String> merged = new LinkedHashMap<>();
        if (detail != null) merged.putAll(detail);
        merged.putIfAbsent("correlationId", corr);
        return Map.copyOf(merged);
    }

    static void install(EventWriter eventWriter, boolean enableCoverage) {
        if (writer != null) throw new IllegalStateException("agent runtime is already installed");
        writer = eventWriter;
        coverageEnabled = enableCoverage;
    }

    static void uninstall(EventWriter eventWriter) {
        if (writer == eventWriter) {
            coverageEnabled = false;
            writer = null;
            COVERAGE_STATE.remove();
            REQUEST_CORRELATION.remove();
            REQUEST_CORRELATION_DEPTH.remove();
        }
    }

    static boolean record(String eventType, String className, String methodName, Map<String, String> detail) {
        EventWriter current = writer;
        // Application-reported JDBC/HTTP helpers must carry request correlation when bound so
        // Worker PathRun windows can join SQL statements to the probe that produced them (H3).
        return current != null && !current.isStopped()
                && current.writeApplication(eventType, className, methodName, withCorrelation(detail));
    }

    private record MethodKey(String className, String methodDescriptor) {
    }

    private static final class CoverageState {
        private int depth;
        private final Map<MethodKey, BitSet> hits = new LinkedHashMap<>();
    }
}

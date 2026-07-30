package com.aq.jvmsentinel.instrumentation;

import java.util.BitSet;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 可信 fixture 或应用集成的显式观测探针。
 *
 * <p>经此公共 API 发出的事件恒为 {@code APPLICATION_REPORTED}。自动字节码
 * 插桩走独立路径。因 Agent 与目标共享 JVM，即使插桩事件在进程外 Worker 校验并重放轨迹前仍属可疑。</p>
 */
public final class AgentRuntime {
    private static volatile EventWriter writer;
    private static volatile boolean coverageEnabled;
    private static final ThreadLocal<Boolean> IN_AUTOMATIC_OBSERVATION =
            ThreadLocal.withInitial(() -> false);
    private static final ThreadLocal<CoverageState> COVERAGE_STATE =
            ThreadLocal.withInitial(CoverageState::new);
    /** 每条请求的 HTTP→JDBC 关联（P0-06）。 */
    private static final ThreadLocal<String> REQUEST_CORRELATION =
            ThreadLocal.withInitial(() -> "");
    private static final ThreadLocal<Integer> REQUEST_CORRELATION_DEPTH =
            ThreadLocal.withInitial(() -> 0);
    /**
     * 每条请求的 METHOD_HOP 预算。否则 XSS 包装（HTMLFilter）会在 FORCED 探针
     * 记录 Controller→Service 跳转前耗尽 maxEvents。
     */
    private static final ThreadLocal<Integer> METHOD_HOP_COUNT =
            ThreadLocal.withInitial(() -> 0);
    static final int MAX_METHOD_HOPS_PER_REQUEST = 64;

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
        detail.put("targetClass", targetClass == null ? "" : targetClass);
        detail.put("targetMethod", targetMethod == null ? "" : targetMethod);
        detail.put("instructionOrdinal", instructionOrdinal);
        String effectKind = primaryEffectKind(eventType, targetClass, targetMethod);
        if (effectKind != null) {
            detail.putAll(PathDebugDetail.effectTriggered(effectKind));
            String secondary = secondaryEffectKinds(targetClass, targetMethod);
            if (secondary != null && !secondary.isBlank()) {
                detail.put("secondaryEffectKinds", secondary);
            }
        }
        recordInstrumented(eventType, callerClass, callerMethod, detail);
    }

    /**
     * 将插桩 call site 映射到 PathDebug effectKind，同时保持顶层
     * eventType 在 agent-jsonl 白名单内。
     */
    static String primaryEffectKind(String eventType, String targetClass, String targetMethod) {
        String owner = targetClass == null ? "" : targetClass;
        String method = targetMethod == null ? "" : targetMethod;
        if ("java.sql.DriverManager".equals(owner) && "getConnection".equals(method)
                || "java.sql.Driver".equals(owner) && "connect".equals(method)) {
            return "SSRF";
        }
        if (("javax.naming.InitialContext".equals(owner) || "javax.naming.Context".equals(owner)
                || "javax.naming.directory.InitialDirContext".equals(owner))
                && ("lookup".equals(method) || "doLookup".equals(method))) {
            return "JNDI";
        }
        if ("java.lang.Class".equals(owner) && ("forName".equals(method) || "newInstance".equals(method))) {
            return "CLASS_LOADING";
        }
        if ("java.net.URLClassLoader".equals(owner)) {
            return "CLASS_LOADING";
        }
        if ("java.io.ObjectInputStream".equals(owner)
                && ("readObject".equals(method) || "readUnshared".equals(method))) {
            return "DESERIALIZATION";
        }
        if (("javax.script.ScriptEngine".equals(owner) || "jakarta.script.ScriptEngine".equals(owner))
                && "eval".equals(method)) {
            return "EXPRESSION";
        }
        if ("com.ql.util.express.ExpressRunner".equals(owner)
                && ("execute".equals(method) || "executeExt".equals(method))) {
            return "EXPRESSION";
        }
        return switch (eventType == null ? "" : eventType) {
            case "HTTP_CLIENT" -> "SSRF";
            case "PROCESS" -> "PROCESS";
            case "FILE" -> "FILE";
            case "JDBC" -> "SQL";
            case "JNDI" -> "JNDI";
            case "CLASS_LOAD" -> "CLASS_LOADING";
            default -> null;
        };
    }

    static String secondaryEffectKinds(String targetClass, String targetMethod) {
        String owner = targetClass == null ? "" : targetClass;
        String method = targetMethod == null ? "" : targetMethod;
        if ("java.sql.DriverManager".equals(owner) && "getConnection".equals(method)
                || "java.sql.Driver".equals(owner) && "connect".equals(method)) {
            return "COMMAND,CLASS_LOADING";
        }
        if (("javax.naming.InitialContext".equals(owner) || "javax.naming.Context".equals(owner))
                && ("lookup".equals(method) || "doLookup".equals(method))) {
            return "CLASS_LOADING,DESERIALIZATION";
        }
        if ("java.net.URLClassLoader".equals(owner)) {
            return "SSRF";
        }
        if (("javax.script.ScriptEngine".equals(owner) || "jakarta.script.ScriptEngine".equals(owner))
                && "eval".equals(method)) {
            return "COMMAND";
        }
        if ("com.ql.util.express.ExpressRunner".equals(owner)
                && ("execute".equals(method) || "executeExt".equals(method))) {
            return "COMMAND";
        }
        return null;
    }

    public static void recordTransformedMethod(String eventType, String className, String methodName,
                                               String captureMode) {
        recordInstrumented(eventType, className, methodName,
                Map.of("captureMode", captureMode, "operation", methodName));
    }

    /** 带额外净化 detail 字段（route、SQL 等）的插桩观测。 */
    public static void recordTransformedDetail(String eventType, String className, String methodName,
                                               Map<String, String> detail) {
        recordInstrumented(eventType, className, methodName, detail);
    }

    /**
     * 启动（或嵌套于）HTTP 请求 coverage 范围。公开因 Byte Buddy advice
     * 内联到应用与框架类。
     */
    public static boolean beginCoverageRequest() {
        if (!coverageEnabled) return false;
        CoverageState state = COVERAGE_STATE.get();
        if (state.depth == 0) {
            state.hits.clear();
            METHOD_HOP_COUNT.set(0);
        }
        state.depth++;
        return true;
    }

    /**
     * 是否应记录应用 METHOD_HOP。丢弃 XSS/CGLIB 噪声并
     * 强制执行每请求 hop 上限，使 FORCED PathTrace 保留有意义的业务跳转。
     */
    public static boolean shouldRecordMethodHop(String className, String methodName) {
        if (className == null || className.isBlank()) {
            return false;
        }
        String name = className;
        if (name.contains("$$FastClassBy") || name.contains("$$EnhancerBy")
                || name.contains("$$SpringCGLIB$$") || name.contains("$FastClassBy")) {
            return false;
        }
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        if (lower.contains(".xss.")
                || lower.endsWith("htmlfilter")
                || lower.endsWith("xsshttprequestwrapper")
                || lower.endsWith("xsshttpservletrequestwrapper")
                || lower.endsWith("xssfilter")) {
            return false;
        }
        // 保留 filter/guard 面供 GUARD_DECISION；MethodHopAdvice 仅应用层。
        int count = METHOD_HOP_COUNT.get();
        if (count >= MAX_METHOD_HOPS_PER_REQUEST) {
            return false;
        }
        METHOD_HOP_COUNT.set(count + 1);
        return true;
    }

    /** 为 active HTTP 请求范围绑定服务端观测的 correlation id。 */
    public static void bindRequestCorrelation(String correlationId) {
        // 每条 HTTP Advice enter 拥有一个平衡 scope，即使该层无法
        // 访问 request header。否则空白嵌套视图会清除外层 id。
        int prior = REQUEST_CORRELATION_DEPTH.get();
        REQUEST_CORRELATION_DEPTH.set(prior + 1);
        if (prior == 0) {
            METHOD_HOP_COUNT.set(0);
        }
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
            METHOD_HOP_COUNT.remove();
            return;
        }
        REQUEST_CORRELATION_DEPTH.set(depth);
    }

    /**
     * 结束 HTTP scope，在最外层边界返回时发出紧凑 coverage 事件。
     * 优先 Byte Buddy advice 的无参形式，使 {@code disableClassFormatChanges} 路径
     * 不依赖 {@code @Advice.Enter} 局部变量（boolean enter 会破坏 HTTP advice 织入）。
     */
    public static void endCoverageRequest() {
        endCoverageRequest(coverageEnabled);
    }

    /** 当 {@code entered} 为 true 时结束 HTTP scope（旧 Advice.Enter boolean 路径）。 */
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
            METHOD_HOP_COUNT.remove();
        }
    }

    /** 在 active 请求范围内记录一处已到达的条件分支或 switch 站点。 */
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
        // 应用上报的 JDBC/HTTP helper 在绑定时须携带 request correlation，以便
        // Worker PathRun 窗口将 SQL 语句关联到产生它们的探针（H3）。
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

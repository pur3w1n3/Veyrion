package com.aq.jvmsentinel.instrumentation;

import java.util.BitSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 可信 fixture 或应用集成的显式观测探针。
 *
 * <p>经此公共 API 发出的事件恒为 {@code APPLICATION_REPORTED}。自动字节码
 * 插桩走独立路径。因 Agent 与目标共享 JVM，即使插桩事件在进程外 Worker 校验并重放轨迹前仍属可疑。</p>
 *
 * <p>JDK 危险原语在应用 call-site 观测（bootstrap 类不变换）。effectKind 细分
 * {@code FILE_WRITE}/{@code FILE_READ}/{@code FILE_DELETE} 等；观测细、确认严——
 * EFFECT 出轨不等于 {@code DYNAMIC_CONFIRMED}（见 DynamicConfirmedGate）。</p>
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
    /** Call-site 注入的 path/URL 摘要（单次消费）。 */
    private static final ThreadLocal<String> PENDING_EFFECT_ARG =
            ThreadLocal.withInitial(() -> "");
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

    /**
     * Call-site 在 invoke 前压入 path/URL/File 参数摘要，供紧随的
     * {@link #recordInstrumentedCall} 写入 detail。
     */
    public static void captureEffectArg(Object arg) {
        String summary = summarizePathOrUrl(arg);
        if (!summary.isBlank()) {
            PENDING_EFFECT_ARG.set(summary);
        }
    }

    public static void recordInstrumentedCall(String eventType, String callerClass, String callerMethod,
                                              String targetClass, String targetMethod,
                                              String instructionOrdinal) {
        String pathOrUrl = PENDING_EFFECT_ARG.get();
        PENDING_EFFECT_ARG.remove();
        if (pathOrUrl == null) {
            pathOrUrl = "";
        }

        String effectKind = primaryEffectKind(eventType, targetClass, targetMethod);
        String effectOp = effectOp(targetClass, targetMethod, effectKind);
        if (!shouldEmitJdkEffect(effectKind, effectOp, pathOrUrl)) {
            return;
        }

        Map<String, String> detail = new LinkedHashMap<>();
        detail.put("captureMode", "APPLICATION_CALL_SITE");
        detail.put("targetClass", targetClass == null ? "" : targetClass);
        detail.put("targetMethod", targetMethod == null ? "" : targetMethod);
        detail.put("instructionOrdinal", instructionOrdinal == null ? "" : instructionOrdinal);
        if (effectOp != null && !effectOp.isBlank()) {
            detail.put("effectOp", effectOp);
        }
        if (!pathOrUrl.isBlank()) {
            detail.put("pathOrUrl", pathOrUrl);
        }
        String corr = currentRequestCorrelation();
        detail.put("requestBound", corr.isEmpty() ? "false" : "true");
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
     * 噪音门控：无 correlation 的弱 IO/DNS 丢弃；写/反序列化/命令/SSRF 原语仍发出。
     * EFFECT 出轨 ≠ 确认——确认由控制面 DynamicConfirmedGate 严判。
     */
    static boolean shouldEmitJdkEffect(String effectKind, String effectOp, String pathOrUrl) {
        String kind = effectKind == null ? "" : effectKind;
        String corr = currentRequestCorrelation();
        boolean bound = !corr.isEmpty();
        if ("DNS_LOOKUP".equals(kind)) {
            return bound;
        }
        if ("FILE_READ".equals(kind)) {
            return bound || looksUserControlledPath(pathOrUrl);
        }
        if ("FILE_DELETE".equals(kind) || "move".equals(effectOp)) {
            return bound || looksUserControlledPath(pathOrUrl);
        }
        // FILE_WRITE / SSRF / DESERIALIZATION / COMMAND / JNDI / EXPRESSION：高价值，始终观测
        return true;
    }

    static boolean looksUserControlledPath(String pathOrUrl) {
        if (pathOrUrl == null || pathOrUrl.isBlank()) {
            return false;
        }
        String lower = pathOrUrl.toLowerCase(Locale.ROOT);
        return lower.contains("..")
                || lower.contains("%2e")
                || lower.contains("etc/passwd")
                || lower.contains("windows\\system")
                || lower.contains("/proc/")
                || lower.contains("veyrion")
                || lower.contains("://");
    }

    /**
     * 将插桩 call site 映射到 PathDebug effectKind，同时保持顶层
     * eventType 在 agent-jsonl 白名单内。
     */
    static String primaryEffectKind(String eventType, String targetClass, String targetMethod) {
        String owner = targetClass == null ? "" : targetClass;
        String method = targetMethod == null ? "" : targetMethod;
        if ("java.sql.DriverManager".equals(owner) && "getConnection".equals(method)
                || "java.sql.Driver".equals(owner) && "connect".equals(method)
                || isJdbcUrlSsrfSink(owner, method)) {
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
        if (isExpressionEvalSink(owner, method)) {
            return "EXPRESSION";
        }
        if (isCommandExecSink(owner, method)) {
            return "COMMAND";
        }
        if (isDnsLookupSink(owner, method)) {
            return "DNS_LOOKUP";
        }
        if (isJdkHttpSsrfSink(owner, method) || isHttpClientSsrfSink(owner, method)) {
            return "SSRF";
        }
        if (isMultipartFileWriteSink(owner, method) || isFileWriteSink(owner, method)) {
            return "FILE_WRITE";
        }
        if (isFileDeleteSink(owner, method)) {
            return "FILE_DELETE";
        }
        if (isFileReadSink(owner, method)) {
            return "FILE_READ";
        }
        return switch (eventType == null ? "" : eventType) {
            case "HTTP_CLIENT" -> "SSRF";
            case "PROCESS" -> "PROCESS";
            case "FILE" -> "FILE_WRITE";
            case "JDBC" -> "SQL";
            case "JNDI" -> "JNDI";
            case "CLASS_LOAD" -> "CLASS_LOADING";
            default -> null;
        };
    }

    /** 诊断用操作类型：write|read|delete|move|connect|deserialize|exec|eval|lookup|dns。 */
    static String effectOp(String targetClass, String targetMethod, String effectKind) {
        String owner = targetClass == null ? "" : targetClass;
        String method = targetMethod == null ? "" : targetMethod;
        if ("DESERIALIZATION".equals(effectKind)) {
            return "deserialize";
        }
        if ("COMMAND".equals(effectKind)) {
            return "exec";
        }
        if ("EXPRESSION".equals(effectKind)) {
            return "eval";
        }
        if ("JNDI".equals(effectKind)) {
            return "lookup";
        }
        if ("DNS_LOOKUP".equals(effectKind)) {
            return "dns";
        }
        if ("SSRF".equals(effectKind)) {
            return "connect";
        }
        if ("java.nio.file.Files".equals(owner) && "move".equals(method)
                || "org.apache.commons.io.FileUtils".equals(owner)
                && (method.startsWith("move"))) {
            return "move";
        }
        if ("FILE_DELETE".equals(effectKind)) {
            return "delete";
        }
        if ("FILE_READ".equals(effectKind)) {
            return "read";
        }
        if ("FILE_WRITE".equals(effectKind) || "FILE".equals(effectKind)) {
            return "write";
        }
        return method == null ? "" : method;
    }

    static String secondaryEffectKinds(String targetClass, String targetMethod) {
        String owner = targetClass == null ? "" : targetClass;
        String method = targetMethod == null ? "" : targetMethod;
        if ("java.sql.DriverManager".equals(owner) && "getConnection".equals(method)
                || "java.sql.Driver".equals(owner) && "connect".equals(method)
                || isJdbcUrlSsrfSink(owner, method)) {
            return "COMMAND,CLASS_LOADING";
        }
        if (("javax.naming.InitialContext".equals(owner) || "javax.naming.Context".equals(owner))
                && ("lookup".equals(method) || "doLookup".equals(method))) {
            return "CLASS_LOADING,DESERIALIZATION";
        }
        if ("java.net.URLClassLoader".equals(owner)) {
            return "SSRF";
        }
        if (isExpressionEvalSink(owner, method)) {
            return "COMMAND";
        }
        return null;
    }

    /**
     * Spring/Druid/DBCP {@code setUrl}、Hikari {@code setJdbcUrl} 与 ad-hoc
     * {@code DriverManagerDataSource#getConnection}——与静态 JDBC URL sink 对齐；
     * 勿对池化 DataSource#getConnection 一律标 SSRF（会淹没业务连接）。
     */
    public static boolean isJdbcUrlSsrfSink(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if ("setUrl".equals(method)
                && ("org.springframework.jdbc.datasource.DriverManagerDataSource".equals(owner)
                || "com.alibaba.druid.pool.DruidDataSource".equals(owner)
                || "org.apache.commons.dbcp2.BasicDataSource".equals(owner)
                || "org.apache.tomcat.dbcp.dbcp2.BasicDataSource".equals(owner))) {
            return true;
        }
        if ("setJdbcUrl".equals(method)
                && ("com.zaxxer.hikari.HikariConfig".equals(owner)
                || "com.zaxxer.hikari.HikariDataSource".equals(owner))) {
            return true;
        }
        return "getConnection".equals(method)
                && "org.springframework.jdbc.datasource.DriverManagerDataSource".equals(owner);
    }

    /** JDK URL / HttpURLConnection / HttpClient ——底层出站汇聚。 */
    public static boolean isJdkHttpSsrfSink(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if ("java.net.URL".equals(owner)) {
            return "openConnection".equals(method) || "openStream".equals(method);
        }
        if ("java.net.HttpURLConnection".equals(owner)
                || "javax.net.ssl.HttpsURLConnection".equals(owner)
                || owner.endsWith(".HttpURLConnection")
                || owner.endsWith(".HttpsURLConnection")) {
            return "connect".equals(method) || "getInputStream".equals(method)
                    || "getOutputStream".equals(method);
        }
        if ("java.net.http.HttpClient".equals(owner)) {
            return "send".equals(method) || "sendAsync".equals(method);
        }
        return false;
    }

    /** DNS 解析：可观测但不作为 SSRF 确认信号（过粗）。 */
    public static boolean isDnsLookupSink(String owner, String method) {
        return "java.net.InetAddress".equals(owner)
                && ("getByName".equals(method) || "getAllByName".equals(method)
                || "getCanonicalHostName".equals(method));
    }

    public static boolean isCommandExecSink(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if ("java.lang.ProcessBuilder".equals(owner) && "start".equals(method)) {
            return true;
        }
        return "java.lang.Runtime".equals(owner) && method.startsWith("exec");
    }

    /** Spring RestTemplate / Apache HttpClient / OkHttp ——与静态 SSRF sink 对齐。 */
    public static boolean isHttpClientSsrfSink(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if ("org.springframework.web.client.RestTemplate".equals(owner)) {
            return "getForObject".equals(method) || "getForEntity".equals(method)
                    || "postForObject".equals(method) || "postForEntity".equals(method)
                    || "exchange".equals(method) || "execute".equals(method);
        }
        if ("org.apache.http.client.HttpClient".equals(owner)
                || "org.apache.http.impl.client.CloseableHttpClient".equals(owner)) {
            return "execute".equals(method);
        }
        if ("okhttp3.Call".equals(owner)) {
            return "execute".equals(method) || "enqueue".equals(method);
        }
        return false;
    }

    /** SpEL / QLExpress / Aviator / OGNL / MVEL ——与静态 EXPRESSION sink 对齐。 */
    public static boolean isExpressionEvalSink(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if (("javax.script.ScriptEngine".equals(owner) || "jakarta.script.ScriptEngine".equals(owner))
                && "eval".equals(method)) {
            return true;
        }
        if ("com.ql.util.express.ExpressRunner".equals(owner)
                && ("execute".equals(method) || "executeExt".equals(method))) {
            return true;
        }
        if ("org.springframework.expression.Expression".equals(owner)
                || "org.springframework.expression.spel.standard.SpelExpression".equals(owner)) {
            return "getValue".equals(method) || "getValueType".equals(method);
        }
        if ("org.springframework.expression.spel.standard.SpelExpressionParser".equals(owner)
                && "parseExpression".equals(method)) {
            return true;
        }
        if ("com.googlecode.aviator.AviatorEvaluator".equals(owner)
                && ("execute".equals(method) || "exec".equals(method))) {
            return true;
        }
        if ("ognl.Ognl".equals(owner)
                && ("getValue".equals(method) || "setValue".equals(method))) {
            return true;
        }
        if ("org.mvel2.MVEL".equals(owner)
                && ("eval".equals(method) || "evalToString".equals(method)
                || "executeExpression".equals(method))) {
            return true;
        }
        if ("freemarker.template.Template".equals(owner) && "process".equals(method)) {
            return true;
        }
        return false;
    }

    /** JDK / Commons-IO 写盘面（应用 call site）。 */
    public static boolean isFileWriteSink(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if ("java.io.FileOutputStream".equals(owner) || "java.io.FileWriter".equals(owner)) {
            return "<init>".equals(method);
        }
        if ("java.io.RandomAccessFile".equals(owner) && "<init>".equals(method)) {
            // 模式含 w 时为写；call-site 无模式时按写观测（读侧另有 FILE_READ 启发式）
            return true;
        }
        if ("java.nio.channels.FileChannel".equals(owner) && "open".equals(method)) {
            return true;
        }
        if ("java.nio.file.Files".equals(owner)) {
            return method.startsWith("write") || "newOutputStream".equals(method)
                    || "newBufferedWriter".equals(method) || "copy".equals(method)
                    || "move".equals(method);
        }
        if ("org.apache.commons.io.FileUtils".equals(owner)) {
            return "write".equals(method) || "writeStringToFile".equals(method)
                    || "writeByteArrayToFile".equals(method) || "copyFile".equals(method)
                    || "copyFileToDirectory".equals(method) || "copyDirectory".equals(method)
                    || "moveFile".equals(method) || "moveDirectory".equals(method);
        }
        return false;
    }

    /** JDK / Commons-IO 读盘面。 */
    public static boolean isFileReadSink(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if ("java.io.FileInputStream".equals(owner) || "java.io.FileReader".equals(owner)) {
            return "<init>".equals(method);
        }
        if ("java.nio.file.Files".equals(owner)) {
            return method.startsWith("read") || "newInputStream".equals(method)
                    || "newBufferedReader".equals(method) || "lines".equals(method);
        }
        if ("org.apache.commons.io.FileUtils".equals(owner)) {
            return "readFileToString".equals(method) || "readFileToByteArray".equals(method)
                    || "openInputStream".equals(method);
        }
        return false;
    }

    /** 删除 / 穿越相关。 */
    public static boolean isFileDeleteSink(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if ("java.io.File".equals(owner)) {
            return "delete".equals(method) || "deleteOnExit".equals(method);
        }
        if ("java.nio.file.Files".equals(owner)) {
            return "delete".equals(method) || "deleteIfExists".equals(method);
        }
        if ("org.apache.commons.io.FileUtils".equals(owner)) {
            return "forceDelete".equals(method) || "deleteDirectory".equals(method)
                    || "deleteQuietly".equals(method);
        }
        return false;
    }

    /**
     * Spring {@code MultipartFile#transferTo}——与静态 FILE_WRITE sink 对齐。
     */
    public static boolean isMultipartFileWriteSink(String owner, String method) {
        if (owner == null || method == null || !"transferTo".equals(method)) {
            return false;
        }
        return "org.springframework.web.multipart.MultipartFile".equals(owner)
                || owner.endsWith(".MultipartFile")
                || owner.endsWith("MultipartFile")
                || owner.endsWith("$StandardMultipartFile")
                || owner.contains(".support.StandardMultipartFile")
                || "org.springframework.web.multipart.commons.CommonsMultipartFile".equals(owner);
    }

    static String summarizePathOrUrl(Object arg) {
        if (arg == null) {
            return "";
        }
        String text;
        if (arg instanceof CharSequence || arg instanceof java.io.File
                || arg instanceof java.nio.file.Path || arg instanceof java.net.URL
                || arg instanceof java.net.URI) {
            text = String.valueOf(arg);
        } else {
            String name = arg.getClass().getName();
            if (name.contains("HttpURLConnection") || name.contains("URLConnection")) {
                try {
                    Object url = arg.getClass().getMethod("getURL").invoke(arg);
                    text = url == null ? name : String.valueOf(url);
                } catch (Throwable ignored) {
                    text = name;
                }
            } else {
                return "";
            }
        }
        text = text.replace('\r', ' ').replace('\n', ' ').trim();
        if (text.length() > 256) {
            text = text.substring(0, 256);
        }
        return text;
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
        if (current == null || IN_AUTOMATIC_OBSERVATION.get()) return;
        Map<String, String> correlated = withCorrelation(detail);
        // 停写判定（EFFECT 软保留 + per-correlation 有界续写）统一由 EventWriter 负责。
        IN_AUTOMATIC_OBSERVATION.set(true);
        try {
            current.writeInstrumented(eventType, className, methodName, correlated);
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
            PENDING_EFFECT_ARG.remove();
        }
    }

    static boolean record(String eventType, String className, String methodName, Map<String, String> detail) {
        EventWriter current = writer;
        // 应用上报的 JDBC/HTTP helper 在绑定时须携带 request correlation，以便
        // Worker PathRun 窗口将 SQL 语句关联到产生它们的探针（H3）。
        if (current == null) return false;
        Map<String, String> correlated = withCorrelation(detail);
        return current.writeApplication(eventType, className, methodName, correlated);
    }

    private record MethodKey(String className, String methodDescriptor) {
    }

    private static final class CoverageState {
        private int depth;
        private final Map<MethodKey, BitSet> hits = new LinkedHashMap<>();
    }
}

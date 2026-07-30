package com.aq.jvmsentinel.instrumentation;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class AgentConfig {
    public static final String TRACE_DIR_PROPERTY = "veyrion.sandbox.traceDir";
    public static final String TRACE_DIR_AUTHORIZED_PROPERTY = "veyrion.sandbox.traceDir.authorized";
    public static final String COVERAGE_ENABLED_PROPERTY = "veyrion.coverage.enabled";
    public static final String WORLD_PACK_DEPENDENCY_MODE_PROPERTY = "veyrion.worldPack.dependencyMode";
    /** FORCED_REACHABILITY 白名单的二进制类型名 CSV（服务端拥有）。 */
    public static final String FORCED_GUARD_TYPE_NAMES_PROPERTY =
            "veyrion.sandbox.forcedGuardTypeNames";
    static final String TRACE_FILE_NAME = "agent-events.jsonl";

    private static final Pattern CLASS_PREFIX = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(?:[./][A-Za-z_$][A-Za-z0-9_$]*)*[./]?");
    private static final long DEFAULT_MAX_BYTES = 8L * 1024 * 1024;
    private static final long MAX_MAX_BYTES = 64L * 1024 * 1024;
    private static final int DEFAULT_MAX_EVENTS = 10_000;
    /**
     * maxEvents 合法上界。控制面 {@code SandboxLaunchCommandBuilder.AGENT_MAX_EVENTS}
     * 必须与此同步；越界时 {@link #parse} fail-closed，premain 不会启动应用。
     *
     * <p>500_000 ≈ 200 探针 × 2500 事件/探针，且约 48MiB JSONL（~96B/事件）仍落在
     * {@link #MAX_MAX_BYTES} 内；沙箱轨迹 tmpfs 为 maxTrace+32MiB headroom（上限 96MiB）。
     * 更大探针计划仍共享进程级池，靠 {@code EventWriter} per-correlation 软分片与耗尽后有界续写兜底。</p>
     */
    public static final int MAX_MAX_EVENTS = 500_000;
    /** maxEvents 合法下界（与控制面 {@code SandboxLaunchCommandBuilder.AGENT_MIN_EVENTS} 同步）。 */
    public static final int MIN_MAX_EVENTS = 1;
    /**
     * 永不重写这些前缀内的 call site / 分支 coverage。HTTP 面
     *（Servlet/Filter/Interceptor）仍经 {@code isHttpObservabilityType} 匹配并仅接收 HTTP advice。
     * 空 {@code classPrefix} 否则会插桩整个 fat JAR，
     * 常见于 Druid/Spring auto-config 场景的 VerifyError（StackMapTable）。
     */
    private static final List<String> BUILT_IN_EXCLUDES = List.of(
            "com/aq/jvmsentinel/instrumentation/",
            "net/bytebuddy/",
            "java/", "javax/", "jakarta/", "jdk/", "sun/", "com/sun/",
            "org/springframework/",
            "org/apache/",
            "org/hibernate/",
            "org/mybatis/",
            "com/alibaba/druid/",
            "com/alibaba/fastjson/",
            "com/alibaba/nacos/",
            "com/baomidou/",
            "com/fasterxml/",
            "com/google/",
            "io/netty/",
            "io/micrometer/",
            "ch/qos/logback/",
            "org/slf4j/",
            "org/jboss/",
            "kotlin/",
            "scala/");

    final Path traceFile;
    final long maxBytes;
    final int maxEvents;
    final String classPrefix;
    final List<String> excludedPrefixes;
    final boolean dependencyMock;
    final boolean coverageEnabled;
    /** OBSERVE_FAIL：DEPENDENCY_FAILURE 后 JDBC 失败；MOCK_CONTINUE：stub 继续。 */
    final String worldPackDependencyMode;

    private AgentConfig(Path traceFile, long maxBytes, int maxEvents, String classPrefix,
                        List<String> excludedPrefixes, boolean dependencyMock, boolean coverageEnabled,
                        String worldPackDependencyMode) {
        this.traceFile = traceFile;
        this.maxBytes = maxBytes;
        this.maxEvents = maxEvents;
        this.classPrefix = classPrefix;
        this.excludedPrefixes = excludedPrefixes;
        this.dependencyMock = dependencyMock;
        this.coverageEnabled = coverageEnabled;
        this.worldPackDependencyMode = worldPackDependencyMode;
    }

    boolean observeFailMode() {
        return "OBSERVE_FAIL".equalsIgnoreCase(worldPackDependencyMode);
    }

    static AgentConfig parse(String arguments) {
        if (!"true".equals(System.getProperty(TRACE_DIR_AUTHORIZED_PROPERTY))) {
            throw new IllegalArgumentException("sandbox trace directory is not authorized");
        }
        String configuredDirectory = System.getProperty(TRACE_DIR_PROPERTY);
        if (configuredDirectory == null || configuredDirectory.isBlank()) {
            throw new IllegalArgumentException("sandbox trace directory property is required");
        }

        Path directory = Path.of(configuredDirectory);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(directory)) {
            throw new IllegalArgumentException("sandbox trace directory must be a pre-existing non-link directory");
        }
        try {
            directory = directory.toRealPath(LinkOption.NOFOLLOW_LINKS);
        } catch (Exception exception) {
            throw new IllegalArgumentException("sandbox trace directory cannot be resolved", exception);
        }

        Map<String, String> values = parseArguments(arguments);
        long maxBytes = parseLong(values.get("maxBytes"), DEFAULT_MAX_BYTES, 256, MAX_MAX_BYTES, "maxBytes");
        int maxEvents = (int) parseLong(values.get("maxEvents"), DEFAULT_MAX_EVENTS,
                MIN_MAX_EVENTS, MAX_MAX_EVENTS, "maxEvents");
        String classPrefix = values.getOrDefault("classPrefix", "").replace('.', '/');
        if (!classPrefix.isEmpty() && (classPrefix.length() > 200 || !CLASS_PREFIX.matcher(classPrefix).matches())) {
            throw new IllegalArgumentException("invalid classPrefix");
        }
        if (!classPrefix.isEmpty() && !classPrefix.endsWith("/")) classPrefix += "/";
        List<String> excludedPrefixes = new java.util.ArrayList<>(BUILT_IN_EXCLUDES);
        String configuredExcludes = values.get("excludePrefixes");
        if (configuredExcludes != null) {
            for (String prefix : configuredExcludes.split(";", -1)) {
                String normalized = prefix.replace('.', '/');
                if (normalized.isEmpty() || normalized.length() > 200
                        || !CLASS_PREFIX.matcher(normalized).matches()) {
                    throw new IllegalArgumentException("invalid excludePrefixes");
                }
                if (!normalized.endsWith("/")) normalized += "/";
                excludedPrefixes.add(normalized);
            }
        }

        Path traceFile = directory.resolve(TRACE_FILE_NAME);
        if (Files.exists(traceFile, LinkOption.NOFOLLOW_LINKS)
                && (!Files.isRegularFile(traceFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(traceFile))) {
            throw new IllegalArgumentException("trace output must be a regular non-link file");
        }
        String worldPackMode = resolveWorldPackDependencyMode(values);
        boolean observeFail = "OBSERVE_FAIL".equalsIgnoreCase(worldPackMode);
        boolean dependencyMock = !observeFail
                && ("true".equalsIgnoreCase(values.getOrDefault("dependencyMock", "false"))
                || "true".equalsIgnoreCase(System.getProperty("veyrion.sandbox.dependencyMock", "false")));
        boolean coverageEnabled = parseBoolean(values.get(COVERAGE_ENABLED_PROPERTY),
                COVERAGE_ENABLED_PROPERTY)
                || parseBoolean(System.getProperty(COVERAGE_ENABLED_PROPERTY), COVERAGE_ENABLED_PROPERTY);
        return new AgentConfig(traceFile, maxBytes, maxEvents, classPrefix, List.copyOf(excludedPrefixes),
                dependencyMock, coverageEnabled, worldPackMode);
    }

    boolean includes(String binaryName) {
        String internalName = binaryName.replace('.', '/');
        if (!classPrefix.isEmpty() && !internalName.startsWith(classPrefix)) return false;
        for (String prefix : excludedPrefixes) {
            if (internalName.startsWith(prefix)) return false;
        }
        return true;
    }

    private static Map<String, String> parseArguments(String arguments) {
        Map<String, String> values = new HashMap<>();
        if (arguments == null || arguments.isBlank()) return values;
        if (arguments.length() > 1024) throw new IllegalArgumentException("agent arguments exceed limit");
        for (String entry : arguments.split(",", -1)) {
            int separator = entry.indexOf('=');
            if (separator <= 0 || separator == entry.length() - 1 || entry.indexOf('=', separator + 1) >= 0) {
                throw new IllegalArgumentException("malformed agent argument");
            }
            String key = entry.substring(0, separator);
            String value = entry.substring(separator + 1);
            if (!key.equals("maxBytes") && !key.equals("maxEvents") && !key.equals("classPrefix")
                    && !key.equals("excludePrefixes") && !key.equals("dependencyMock")
                    && !key.equals(COVERAGE_ENABLED_PROPERTY)
                    && !key.equals(WORLD_PACK_DEPENDENCY_MODE_PROPERTY)) {
                throw new IllegalArgumentException("unsupported agent argument: " + key);
            }
            if (values.putIfAbsent(key, value) != null) {
                throw new IllegalArgumentException("duplicate agent argument: " + key);
            }
        }
        return values;
    }

    private static boolean parseBoolean(String value, String name) {
        if (value == null) return false;
        if ("true".equalsIgnoreCase(value)) return true;
        if ("false".equalsIgnoreCase(value)) return false;
        throw new IllegalArgumentException(name + " must be true or false");
    }

    private static String resolveWorldPackDependencyMode(Map<String, String> values) {
        String fromArg = values.get(WORLD_PACK_DEPENDENCY_MODE_PROPERTY);
        if (fromArg == null || fromArg.isBlank()) {
            fromArg = System.getProperty(WORLD_PACK_DEPENDENCY_MODE_PROPERTY, "MOCK_CONTINUE");
        }
        String normalized = fromArg.trim().toUpperCase(java.util.Locale.ROOT);
        if (!normalized.equals("OBSERVE_FAIL") && !normalized.equals("MOCK_CONTINUE")) {
            throw new IllegalArgumentException(WORLD_PACK_DEPENDENCY_MODE_PROPERTY
                    + " must be OBSERVE_FAIL or MOCK_CONTINUE");
        }
        return normalized;
    }

    private static long parseLong(String value, long defaultValue, long minimum, long maximum, String name) {
        if (value == null) return defaultValue;
        try {
            long parsed = Long.parseLong(value);
            if (parsed < minimum || parsed > maximum) throw new IllegalArgumentException(name + " is outside limits");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " must be an integer", exception);
        }
    }
}

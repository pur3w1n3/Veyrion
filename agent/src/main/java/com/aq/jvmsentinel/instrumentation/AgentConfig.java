package com.aq.jvmsentinel.instrumentation;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

final class AgentConfig {
    static final String TRACE_DIR_PROPERTY = "veyrion.sandbox.traceDir";
    static final String TRACE_DIR_AUTHORIZED_PROPERTY = "veyrion.sandbox.traceDir.authorized";
    static final String COVERAGE_ENABLED_PROPERTY = "veyrion.coverage.enabled";
    static final String TRACE_FILE_NAME = "agent-events.jsonl";

    private static final Pattern CLASS_PREFIX = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(?:[./][A-Za-z_$][A-Za-z0-9_$]*)*[./]?");
    private static final long DEFAULT_MAX_BYTES = 8L * 1024 * 1024;
    private static final long MAX_MAX_BYTES = 64L * 1024 * 1024;
    private static final int DEFAULT_MAX_EVENTS = 10_000;
    private static final int MAX_MAX_EVENTS = 100_000;
    /**
     * Never rewrite call sites / branch coverage inside these prefixes. HTTP surfaces
     * (Servlet/Filter/Interceptor) still match via {@code isHttpObservabilityType} and receive
     * HTTP-only advice. Empty {@code classPrefix} otherwise instruments the whole fat JAR and
     * VerifyError (StackMapTable) commonly surfaces in Druid/Spring auto-config.
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

    private AgentConfig(Path traceFile, long maxBytes, int maxEvents, String classPrefix,
                        List<String> excludedPrefixes, boolean dependencyMock, boolean coverageEnabled) {
        this.traceFile = traceFile;
        this.maxBytes = maxBytes;
        this.maxEvents = maxEvents;
        this.classPrefix = classPrefix;
        this.excludedPrefixes = excludedPrefixes;
        this.dependencyMock = dependencyMock;
        this.coverageEnabled = coverageEnabled;
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
        int maxEvents = (int) parseLong(values.get("maxEvents"), DEFAULT_MAX_EVENTS, 1, MAX_MAX_EVENTS, "maxEvents");
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
        boolean dependencyMock = "true".equalsIgnoreCase(values.getOrDefault("dependencyMock", "false"))
                || "true".equalsIgnoreCase(System.getProperty("veyrion.sandbox.dependencyMock", "false"));
        boolean coverageEnabled = parseBoolean(values.get(COVERAGE_ENABLED_PROPERTY),
                COVERAGE_ENABLED_PROPERTY)
                || parseBoolean(System.getProperty(COVERAGE_ENABLED_PROPERTY), COVERAGE_ENABLED_PROPERTY);
        return new AgentConfig(traceFile, maxBytes, maxEvents, classPrefix, List.copyOf(excludedPrefixes),
                dependencyMock, coverageEnabled);
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
                    && !key.equals(COVERAGE_ENABLED_PROPERTY)) {
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

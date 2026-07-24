package com.aq.jvmsentinel.instrumentation;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

final class AgentConfig {
    static final String TRACE_DIR_PROPERTY = "veyrion.sandbox.traceDir";
    static final String TRACE_DIR_AUTHORIZED_PROPERTY = "veyrion.sandbox.traceDir.authorized";
    static final String TRACE_FILE_NAME = "agent-events.jsonl";

    private static final Pattern CLASS_PREFIX = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(?:[./][A-Za-z_$][A-Za-z0-9_$]*)*[./]?");
    private static final long DEFAULT_MAX_BYTES = 8L * 1024 * 1024;
    private static final long MAX_MAX_BYTES = 64L * 1024 * 1024;
    private static final int DEFAULT_MAX_EVENTS = 10_000;
    private static final int MAX_MAX_EVENTS = 100_000;

    final Path traceFile;
    final long maxBytes;
    final int maxEvents;
    final String classPrefix;

    private AgentConfig(Path traceFile, long maxBytes, int maxEvents, String classPrefix) {
        this.traceFile = traceFile;
        this.maxBytes = maxBytes;
        this.maxEvents = maxEvents;
        this.classPrefix = classPrefix;
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

        Path traceFile = directory.resolve(TRACE_FILE_NAME);
        if (Files.exists(traceFile, LinkOption.NOFOLLOW_LINKS)
                && (!Files.isRegularFile(traceFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(traceFile))) {
            throw new IllegalArgumentException("trace output must be a regular non-link file");
        }
        return new AgentConfig(traceFile, maxBytes, maxEvents, classPrefix);
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
            if (!key.equals("maxBytes") && !key.equals("maxEvents") && !key.equals("classPrefix")) {
                throw new IllegalArgumentException("unsupported agent argument: " + key);
            }
            if (values.putIfAbsent(key, value) != null) {
                throw new IllegalArgumentException("duplicate agent argument: " + key);
            }
        }
        return values;
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

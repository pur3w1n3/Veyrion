package com.aq.jvmsentinel.harness;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The complete allowed AI output for harness generation. It contains invocation data only:
 * no source code, classpath, executable, shell command, environment, or filesystem path.
 */
public record HarnessPlan(int schemaVersion, String planId, TargetMethod target, Invocation invocation) {
    public static final int SCHEMA_VERSION = 1;

    public HarnessPlan {
        if (schemaVersion != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
        planId = id(planId, "planId");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(invocation, "invocation");
    }

    public record TargetMethod(String artifactDigest, String className, String methodName,
                               String methodDescriptor) {
        public TargetMethod {
            if (artifactDigest == null || !artifactDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("artifactDigest must be a lowercase SHA-256");
            }
            if (className == null || !className.matches(
                    "[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*){0,254}")) {
                throw new IllegalArgumentException("invalid target class");
            }
            if (methodName == null || !methodName.matches("(?:[A-Za-z_$][A-Za-z0-9_$]*|<init>)")) {
                throw new IllegalArgumentException("invalid target method");
            }
            methodDescriptor = validateMethodDescriptor(methodDescriptor);
        }
    }

    public sealed interface Invocation permits HttpInvocation, JunitInvocation { }

    public record HttpInvocation(HttpMethod method, String path, Map<String, String> headers,
                                 String body) implements Invocation {
        public HttpInvocation {
            Objects.requireNonNull(method, "method");
            Objects.requireNonNull(path, "path");
            String lowerPath = path.toLowerCase(java.util.Locale.ROOT);
            if (!path.startsWith("/") || path.startsWith("//") || path.length() > 4096
                    || path.contains("..") || path.indexOf('\\') >= 0 || path.indexOf('#') >= 0
                    || lowerPath.contains("%2e") || lowerPath.contains("%2f") || lowerPath.contains("%5c")
                    || path.chars().anyMatch(c -> c < 0x20)) {
                throw new IllegalArgumentException("HTTP path must be a normalized origin-relative path");
            }
            headers = Map.copyOf(Objects.requireNonNull(headers, "headers"));
            if (headers.size() > 64) throw new IllegalArgumentException("too many HTTP headers");
            headers.forEach((name, value) -> {
                if (name == null || !name.matches("[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}")
                        || name.equalsIgnoreCase("host") || name.equalsIgnoreCase("content-length")) {
                    throw new IllegalArgumentException("invalid or controlled HTTP header");
                }
                boundedData(value, "header value", 8192);
            });
            body = body == null ? "" : boundedData(body, "body", 1024 * 1024);
        }
    }

    public record JunitInvocation(List<String> arguments) implements Invocation {
        public JunitInvocation {
            arguments = List.copyOf(Objects.requireNonNull(arguments, "arguments"));
            if (arguments.size() > 128) throw new IllegalArgumentException("too many invocation arguments");
            arguments = arguments.stream().map(value -> boundedData(value, "argument", 16_384)).toList();
        }
    }

    public enum HttpMethod {
        GET, POST, PUT, PATCH, DELETE
    }

    private static String validateMethodDescriptor(String value) {
        Objects.requireNonNull(value, "methodDescriptor");
        if (value.length() > 4096 || !value.startsWith("(") || value.indexOf(')') < 1
                || !value.matches("\\((?:\\[*(?:[BCDFIJSZ]|L[A-Za-z0-9_$/]+;))*\\)"
                + "(?:V|\\[*(?:[BCDFIJSZ]|L[A-Za-z0-9_$/]+;))")) {
            throw new IllegalArgumentException("invalid JVM method descriptor");
        }
        return value;
    }

    private static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }

    private static String boundedData(String value, String name, int maximum) {
        Objects.requireNonNull(value, name);
        if (value.length() > maximum || value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }
}

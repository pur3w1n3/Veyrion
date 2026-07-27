package com.aq.jvmsentinel.analysis.fuzz;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** Sink-category typed fuzz probe templates for DYNAMIC_VERIFICATION. */
public final class FuzzStrategyRegistry {
    private FuzzStrategyRegistry() {
    }

    public record ProbeTemplate(String name, String inputHint, String expectedSignal) {
        public ProbeTemplate {
            Objects.requireNonNull(name, "name");
            inputHint = inputHint == null ? "" : inputHint;
            expectedSignal = expectedSignal == null ? "" : expectedSignal;
        }
    }

    public record FuzzStrategy(String sinkCategory, List<ProbeTemplate> probeTemplates) {
        public FuzzStrategy {
            sinkCategory = sinkCategory == null ? "GENERIC" : sinkCategory;
            probeTemplates = List.copyOf(probeTemplates == null ? List.of() : probeTemplates);
        }
    }

    public static FuzzStrategy forSink(String category) {
        String key = category == null ? "" : category.trim().toUpperCase(Locale.ROOT);
        return switch (key) {
            case "SQL", "SQL_INJECTION" -> sqlStrategy();
            case "JNDI" -> jndiStrategy();
            case "DESERIALIZATION" -> deserializationStrategy();
            case "SSRF" -> ssrfStrategy();
            case "PATH_TRAVERSAL", "PATH", "FILE" -> pathTraversalStrategy();
            case "COMMAND", "RCE" -> commandStrategy();
            default -> genericStrategy(key.isBlank() ? "GENERIC" : key);
        };
    }

    private static FuzzStrategy sqlStrategy() {
        return new FuzzStrategy("SQL", List.of(
                new ProbeTemplate("benign", "normal_value", "200_OK"),
                new ProbeTemplate("meta_char", "'", "SQL_ERROR_OR_500"),
                new ProbeTemplate("union", "' UNION SELECT 1,2,3--", "STRUCTURE_DIFF"),
                new ProbeTemplate("error", "1 AND CONVERT(int,'a')", "SQL_ERROR_DETAIL")));
    }

    private static FuzzStrategy jndiStrategy() {
        return new FuzzStrategy("JNDI", List.of(
                new ProbeTemplate("benign", "local", "200_OK"),
                new ProbeTemplate("ldap", "${jndi:ldap://127.0.0.1/a}", "DNS_OR_CONNECT"),
                new ProbeTemplate("rmi", "${jndi:rmi://127.0.0.1/a}", "DNS_OR_CONNECT")));
    }

    private static FuzzStrategy deserializationStrategy() {
        return new FuzzStrategy("DESERIALIZATION", List.of(
                new ProbeTemplate("benign", "{}", "200_OK"),
                new ProbeTemplate("type_confuse", "{\"@type\":\"java.lang.Object\"}", "CLASS_LOAD"),
                new ProbeTemplate("gadget_hint", "serialized-bytes-placeholder", "EXCEPTION")));
    }

    private static FuzzStrategy ssrfStrategy() {
        return new FuzzStrategy("SSRF", List.of(
                new ProbeTemplate("benign", "https://example.invalid/", "200_OK"),
                new ProbeTemplate("loopback", "http://127.0.0.1/", "CONNECT_LOCAL"),
                new ProbeTemplate("metadata", "http://169.254.169.254/", "METADATA_BLOCKED")));
    }

    private static FuzzStrategy pathTraversalStrategy() {
        return new FuzzStrategy("PATH_TRAVERSAL", List.of(
                new ProbeTemplate("benign", "readme.txt", "200_OK"),
                new ProbeTemplate("dotdot", "../../etc/passwd", "FILE_READ"),
                new ProbeTemplate("encoded", "..%2F..%2Fetc%2Fpasswd", "FILE_READ")));
    }

    private static FuzzStrategy commandStrategy() {
        return new FuzzStrategy("COMMAND", List.of(
                new ProbeTemplate("benign", "echo", "200_OK"),
                new ProbeTemplate("meta", ";id", "COMMAND_SIGNAL"),
                new ProbeTemplate("pipe", "|id", "COMMAND_SIGNAL")));
    }

    private static FuzzStrategy genericStrategy(String category) {
        return new FuzzStrategy(category, List.of(
                new ProbeTemplate("benign", "normal_value", "200_OK"),
                new ProbeTemplate("meta_char", "'\"<>", "ERROR_OR_500"),
                new ProbeTemplate("long", "A".repeat(64), "LENGTH_SIGNAL")));
    }
}

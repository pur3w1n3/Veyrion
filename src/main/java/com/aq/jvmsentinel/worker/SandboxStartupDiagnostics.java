package com.aq.jvmsentinel.worker;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * P0-17：结构化沙箱启动 / 就绪失败分类。
 * 诊断为 Dynamic Diagnostics / coverage gap 的证据 — 永非 finding。
 */
public final class SandboxStartupDiagnostics {
    public enum FailureClass {
        JVM_CRASH,
        MAIN_CLASS_MISSING,
        PORT_NOT_LISTENING,
        DEPENDENCY_PORT_MISCLASSIFIED,
        DEPENDENCY_MOCK_GAP,
        DB_INIT_BLOCKED,
        AUTH_CONFIG_MISSING,
        BUDGET_EXCEEDED,
        PROBE_JVM_FAILED,
        RETAINED_SANDBOX_FAILED,
        UNKNOWN_STARTUP_FAILURE
    }

    private static final Set<Integer> DEPENDENCY_PORTS = Set.of(
            3306, 6379, 5432, 27017, 11211, 9200, 5672);

    private static final Pattern MAIN_MISSING = Pattern.compile(
            "(?i)(could not find or load main class|no main manifest attribute|main method not found)");
    private static final Pattern OOM = Pattern.compile("(?i)(OutOfMemoryError|Cannot allocate memory)");
    private static final Pattern DB_INIT = Pattern.compile(
            "(?i)(flyway|liquibase|Failed to obtain JDBC|Communications link failure|"
                    + "Connection refused.*:(3306|5432)|Unknown database)");
    private static final Pattern AUTH_CONFIG = Pattern.compile(
            "(?i)(Invalid keystore|jwt|oauth|AuthenticationConfiguration|security\\.require)");
    private static final Pattern DEPENDENCY_GAP = Pattern.compile(
            "(?i)(redis|jedis|lettuce|amqp|mongo|elasticsearch).*(refused|timeout|unavailable)");

    private SandboxStartupDiagnostics() {
    }

    public record Diagnosis(FailureClass failureClass, String code, String summary,
                            Map<String, Object> details) {
        public Diagnosis {
            Objects.requireNonNull(failureClass, "failureClass");
            code = code == null || code.isBlank() ? failureClass.name() : code;
            summary = summary == null ? "" : summary;
            details = Map.copyOf(details == null ? Map.of() : details);
        }
    }

    public static Diagnosis classify(int exitCode, String diagnosticText) {
        String text = diagnosticText == null ? "" : diagnosticText;
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("exitCode", exitCode);
        details.put("diagnosticLength", text.length());

        String lower = text.toLowerCase(Locale.ROOT);
        if (lower.contains("trace_read_failed") || lower.contains("trace block length mismatch")
                || lower.contains("trace size could not be read")
                || lower.contains("trace block is not valid base64")) {
            return new Diagnosis(FailureClass.UNKNOWN_STARTUP_FAILURE, "TRACE_READ_FAILED",
                    "Agent/probe trace could not be read from the sandbox (often a live append race)",
                    details);
        }
        if (exitCode == 70 || lower.contains("wait-http-ready")) {
            if (mentionsDependencyPort(text)) {
                return new Diagnosis(FailureClass.DEPENDENCY_PORT_MISCLASSIFIED,
                        "DEPENDENCY_PORT_MISCLASSIFIED",
                        "Dependency listener port mistaken for application HTTP port",
                        details);
            }
            return new Diagnosis(FailureClass.PORT_NOT_LISTENING, "PORT_NOT_LISTENING",
                    "Application HTTP port was not ready", details);
        }
        if (exitCode == 71) {
            return new Diagnosis(FailureClass.PROBE_JVM_FAILED, "PROBE_JVM_FAILED",
                    "Loopback probe JVM failed after HTTP readiness", details);
        }
        if (text.contains("RETAINED_SANDBOX")) {
            return new Diagnosis(FailureClass.RETAINED_SANDBOX_FAILED, "RETAINED_SANDBOX_FAILED",
                    "Retained sandbox could not run the next probe round", details);
        }
        if (MAIN_MISSING.matcher(text).find()) {
            return new Diagnosis(FailureClass.MAIN_CLASS_MISSING, "MAIN_CLASS_MISSING",
                    "Main class / manifest entry missing", details);
        }
        if (OOM.matcher(text).find() || text.contains("BUDGET") || text.contains("resource budget")) {
            return new Diagnosis(FailureClass.BUDGET_EXCEEDED, "BUDGET_EXCEEDED",
                    "Memory/disk/time budget prevented startup", details);
        }
        if (DB_INIT.matcher(text).find()) {
            return new Diagnosis(FailureClass.DB_INIT_BLOCKED, "DB_INIT_BLOCKED",
                    "Database initialization blocked application readiness", details);
        }
        if (DEPENDENCY_GAP.matcher(text).find()) {
            return new Diagnosis(FailureClass.DEPENDENCY_MOCK_GAP, "DEPENDENCY_MOCK_GAP",
                    "Dependency mock/stub gap blocked readiness", details);
        }
        if (AUTH_CONFIG.matcher(text).find()) {
            return new Diagnosis(FailureClass.AUTH_CONFIG_MISSING, "AUTH_CONFIG_MISSING",
                    "Auth/config material missing for startup", details);
        }
        if (exitCode > 128 || text.contains("SIGSEGV") || text.contains("FATAL ERROR")) {
            return new Diagnosis(FailureClass.JVM_CRASH, "JVM_CRASH",
                    "JVM crashed during sandbox startup", details);
        }
        return new Diagnosis(FailureClass.UNKNOWN_STARTUP_FAILURE, "UNKNOWN_STARTUP_FAILURE",
                "Sandbox startup failed without a more specific classifier match", details);
    }

    public static boolean isDependencyPort(int port) {
        return DEPENDENCY_PORTS.contains(port);
    }

    private static boolean mentionsDependencyPort(String text) {
        if (text == null || text.isBlank()) return false;
        for (Integer port : DEPENDENCY_PORTS) {
            if (text.contains(":" + port) || text.contains(" " + port + " ")
                    || text.contains("port=" + port) || text.contains("\"" + port + "\"")) {
                return true;
            }
        }
        return false;
    }
}

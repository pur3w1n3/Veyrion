package com.aq.jvmsentinel.worker.docker;

import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.SandboxStartupDiagnostics;

import java.util.List;

/**
 * 外部制品沙箱执行失败时的诊断文本与分类码。
 */
public final class ExternalArtifactDiagnostics {
    private ExternalArtifactDiagnostics() { }

    public static String diagnostic(String probeStdout, String probeStderr, String applicationLog) {
        String stderr = cleanDiagnostic(probeStderr);
        String stdout = cleanDiagnostic(probeStdout);
        String application = cleanDiagnostic(applicationLog);
        stderr = compactDiagnostic(stderr, 650, "probe stack");
        if (stdout.length() > 120) stdout = stdout.substring(stdout.length() - 120);
        application = compactDiagnostic(application, 650, "application log");
        String value = "probe stderr:\n" + (stderr.isBlank() ? "(empty)" : stderr)
                + "\nprobe stdout tail:\n" + (stdout.isBlank() ? "(empty)" : stdout)
                + "\napplication log tail:\n" + (application.isBlank() ? "(empty)" : application);
        return value.length() <= 1_600 ? value : value.substring(0, 1_600);
    }

    public static String exitDiagnostic(int exitCode, String detail) {
        SandboxStartupDiagnostics.Diagnosis diagnosis =
                SandboxStartupDiagnostics.classify(exitCode, detail);
        String prefix = "external artifact returned exit " + exitCode
                + " [" + diagnosis.failureClass().name() + "] " + diagnosis.summary();
        if (exitCode == 70) {
            prefix += " (loopback HTTP listen never classified as ready; application likely failed to bind"
                    + " an HTTP port under deny-all - often blocked by unavailable DB/external deps)";
        } else if (exitCode == 71) {
            prefix += " (HTTP port was ready but LoopbackHttpProbe failed; probe_jvm_status=3 means"
                    + " zero writable events, while other nonzero values indicate probe startup, plan,"
                    + " or runtime failure; the recorded status follows below)";
        }
        if (detail == null || detail.isBlank()) return prefix;
        return prefix + ": " + detail;
    }

    public static String failureCode(RuntimeException failure) {
        if (failure instanceof ExternalArtifactTaskExecutor.ExternalArtifactExecutionException external) {
            String code = external.code();
            if (code != null && !code.isBlank() && !"EXTERNAL_ARTIFACT_EXECUTION_FAILED".equals(code)) {
                return code;
            }
            SandboxStartupDiagnostics.Diagnosis diagnosis =
                    SandboxStartupDiagnostics.classify(extractExitCode(external.getMessage()),
                            external.getMessage());
            return diagnosis.code();
        }
        if (failure instanceof SecurityException || failure instanceof IllegalArgumentException) {
            return "EXTERNAL_ARTIFACT_REJECTED";
        }
        SandboxStartupDiagnostics.Diagnosis diagnosis =
                SandboxStartupDiagnostics.classify(-1, failure.getMessage());
        return diagnosis.code();
    }

    public static String failureDiagnostic(RuntimeException failure) {
        String value = failure.getMessage();
        if (value == null || value.isBlank()) return failureCode(failure);
        value = value.replaceAll("(?i)(password|passwd|secret|token|api[_-]?key)(\\s*[:=]\\s*)\\S+",
                        "$1$2[REDACTED]")
                .replaceAll("(?i)bearer\\s+[A-Za-z0-9._~+/-]{4,}", "Bearer [REDACTED]")
                .replaceAll("\\bsk-[A-Za-z0-9_-]{4,}\\b", "[REDACTED]")
                .replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ").strip();
        // 将显式执行码并入分类种子，避免 PROBE_EVENT_* 被误标为 UNKNOWN_STARTUP_FAILURE。
        String classifySeed = value;
        if (failure instanceof ExternalArtifactTaskExecutor.ExternalArtifactExecutionException external
                && external.code() != null && !external.code().isBlank()) {
            classifySeed = external.code() + " " + value;
        }
        SandboxStartupDiagnostics.Diagnosis diagnosis =
                SandboxStartupDiagnostics.classify(extractExitCode(value), classifySeed);
        String classified = "[" + diagnosis.failureClass().name() + "] " + diagnosis.summary()
                + " | " + value;
        return classified.length() <= 2048 ? classified : classified.substring(0, 2048);
    }

    private static String cleanDiagnostic(String value) {
        return (value == null ? "" : value)
                .replaceAll("[\\p{Cntrl}&&[^\\r\\n\\t]]", "?").strip();
    }

    private static String compactDiagnostic(String value, int limit, String label) {
        if (value == null || value.length() <= limit) return value == null ? "" : value;
        int anchor = diagnosticAnchor(value);
        if (anchor < 0) return value.substring(value.length() - limit);
        int start = Math.max(0, anchor - 160);
        int end = Math.min(value.length(), start + limit);
        String slice = value.substring(start, end);
        if (start > 0) slice = "...[" + label + " omitted before]...\n" + slice;
        if (end < value.length()) slice = slice + "\n...[" + label + " omitted after]...";
        return slice.length() <= limit ? slice : slice.substring(0, limit);
    }

    private static int diagnosticAnchor(String value) {
        int best = -1;
        for (String marker : List.of("Exception in thread", "Caused by", "ERROR", "java.lang.")) {
            int index = value.indexOf(marker);
            if (index >= 0 && (best < 0 || index < best)) best = index;
        }
        return best;
    }

    private static int extractExitCode(String message) {
        if (message == null) return -1;
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("exit (\\d{1,3})")
                .matcher(message);
        if (matcher.find()) {
            try {
                return Integer.parseInt(matcher.group(1));
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return -1;
    }
}

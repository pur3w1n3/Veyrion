package com.aq.jvmsentinel.ai.prompt;

/** Prompt/诊断文本的有界脱敏。 */
public final class AiPromptSanitizer {
    private AiPromptSanitizer() {
    }

    public static String sanitizeSummary(String value) {
        String sanitized = value == null ? "" : value.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ")
                .replaceAll("(?i)bearer\\s+[A-Za-z0-9._~+/-]{8,}", "Bearer [REDACTED]")
                .replaceAll("(?i)(api[_ -]?key\\s*[:=]\\s*)\\S+", "$1[REDACTED]")
                .replaceAll("\\bsk-[A-Za-z0-9_-]{8,}\\b", "[REDACTED]")
                .replaceAll("(?i)\\bVERIFIED\\b", "UNVERIFIED_MODEL_CLAIM");
        return sanitized.length() <= 16_384 ? sanitized : sanitized.substring(0, 16_384);
    }

    public static String sanitizeDiagnostic(String value) {
        String sanitized = sanitizeSummary(value).replaceAll("\\s+", " ").trim();
        if (sanitized.isBlank()) return "AI_JOB_FAILED";
        return sanitized.length() <= 1024 ? sanitized : sanitized.substring(0, 1024);
    }
}

package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * AI 撰写的 auth-bypass 可行性 PoC。AUTH_ANALYSIS / triage 评判并撰写
 * payload；服务端校验 schema/bounds；DYNAMIC_VERIFICATION 执行并
 * 追踪 outcome。单独永不升级 verification status。
 */
public record AuthBypassCandidate(
        String entryRef,
        String techniqueId,
        IdentityTrack track,
        String rationale,
        List<String> evidenceRefs,
        double confidence,
        /** loopback probe 的 token / header 材料（AI 撰写；可为 JWT）。 */
        String authorizationHeader,
        /**
         * 可选次要 auth-channel 材料（wire 名 {@code bladeAuthHeader} 为
         * 兼容保留；语义为 {@code secondaryAuthorizationHeader}）。空表示
         * 仅 Authorization，除非 probe 层从 harvest hint 双写。
         */
        String bladeAuthHeader,
        String query,
        String bodyHint
) {
    public static final int MAX_RATIONALE = 512;
    public static final int MAX_EVIDENCE_REFS = 8;
    public static final int MAX_CANDIDATES = 24;
    public static final int MAX_AUTH_HEADER = 2048;
    public static final int MAX_QUERY = 256;
    public static final int MAX_BODY_HINT = 1024;
    private static final Set<String> DESTRUCTIVE = Set.of(
            "drop ", "truncate ", "rm -rf", "runtime.exec", "processbuilder",
            "memshell", "memory shell", "/bin/sh", "powershell", "cmd.exe");

    public AuthBypassCandidate {
        entryRef = normalizeEntryRef(entryRef);
        techniqueId = normalizeTechniqueId(techniqueId);
        track = track == null ? IdentityTrack.BYPASS_CANDIDATE : track;
        rationale = sanitizeText(rationale, MAX_RATIONALE);
        evidenceRefs = sanitizeEvidenceRefs(evidenceRefs);
        if (Double.isNaN(confidence) || confidence < 0.0 || confidence > 1.0) {
            confidence = 0.3;
        }
        authorizationHeader = normalizeAuthMaterial(authorizationHeader);
        bladeAuthHeader = normalizeAuthMaterial(bladeAuthHeader);
        query = normalizeQuery(query);
        bodyHint = sanitizeText(bodyHint, MAX_BODY_HINT);
        rejectDestructive(rationale + " " + authorizationHeader + " " + bladeAuthHeader
                + " " + query + " " + bodyHint);
    }

    public static AuthBypassCandidate of(
            String entryRef,
            String techniqueId,
            IdentityTrack track,
            String rationale,
            List<String> evidenceRefs,
            double confidence,
            String authorizationHeader,
            String bladeAuthHeader,
            String query,
            String bodyHint) {
        return new AuthBypassCandidate(entryRef, techniqueId, track, rationale, evidenceRefs,
                confidence, authorizationHeader, bladeAuthHeader, query, bodyHint);
    }

    /** 模型提供了 probe 可用的 auth 材料（不仅是 label）时为 true。 */
    public boolean hasAuthMaterial() {
        return authorizationHeader != null && !authorizationHeader.isBlank();
    }

    /** schema-gate AI auth 材料，不构造完整 candidate。 */
    public static void validateAuthMaterialOnly(String authorizationHeader) {
        normalizeAuthMaterial(authorizationHeader);
        rejectDestructive(authorizationHeader == null ? "" : authorizationHeader);
    }

    /** Probe 层 token body：若模型包含则剥离 leading Bearer scheme。 */
    public String probeAuthToken() {
        if (!hasAuthMaterial()) return "";
        String value = authorizationHeader.trim();
        if (value.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return value.substring(7).trim();
        }
        return value;
    }

    /** {@link #bladeAuthHeader()} 的通用别名。 */
    public String secondaryAuthorizationHeader() {
        return bladeAuthHeader == null ? "" : bladeAuthHeader;
    }

    public String probeBladeAuth() {
        return probeSecondaryAuth();
    }

    /** Probe 层次要 channel token body。 */
    public String probeSecondaryAuth() {
        if (bladeAuthHeader != null && !bladeAuthHeader.isBlank()) {
            String value = bladeAuthHeader.trim();
            if (value.regionMatches(true, 0, "Bearer ", 0, 7)) {
                return value.substring(7).trim();
            }
            return value;
        }
        return probeAuthToken();
    }

    private static String normalizeEntryRef(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("entryRef is required");
        }
        String trimmed = value.trim();
        if (trimmed.matches("[A-Za-z0-9._:-]{1,240}") && !trimmed.startsWith("entry:")) {
            trimmed = "entry:" + trimmed;
        }
        if (!trimmed.matches("entry:[A-Za-z0-9._:-]{1,240}")) {
            throw new IllegalArgumentException("entryRef must be entry:<scanEntryId>");
        }
        return trimmed;
    }

    private static String normalizeTechniqueId(String value) {
        if (value == null || value.isBlank()) return "CUSTOM_POC";
        String trimmed = value.trim().toUpperCase(Locale.ROOT);
        if (!trimmed.matches("[A-Z][A-Z0-9_]{1,63}")) {
            throw new IllegalArgumentException("techniqueId is invalid");
        }
        return trimmed;
    }

    private static String normalizeAuthMaterial(String value) {
        if (value == null) return "";
        String text = value.replaceAll("[\\p{Cntrl}]", "");
        if (text.length() > MAX_AUTH_HEADER) {
            throw new IllegalArgumentException("authorization material exceeds bound");
        }
        // 允许 JWT / base64url / Bearer / 常见 header token charset。
        if (!text.isEmpty() && !text.matches("[\\x20-\\x7E]{1," + MAX_AUTH_HEADER + "}")) {
            throw new IllegalArgumentException("authorization material charset rejected");
        }
        return text;
    }

    private static String normalizeQuery(String value) {
        if (value == null || value.isBlank()) return "";
        String text = value.trim();
        if (text.length() > MAX_QUERY) {
            throw new IllegalArgumentException("query exceeds bound");
        }
        if (!text.matches("[A-Za-z0-9_=&%./{}:-]{1," + MAX_QUERY + "}")) {
            throw new IllegalArgumentException("query charset rejected");
        }
        return text;
    }

    private static String sanitizeText(String value, int max) {
        String text = value == null ? "" : value.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ").trim();
        if (text.length() > max) text = text.substring(0, max);
        return text.replaceAll("(?i)\\bVERIFIED\\b", "HYPOTHESIS");
    }

    private static List<String> sanitizeEvidenceRefs(List<String> values) {
        if (values == null || values.isEmpty()) return List.of();
        return values.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(ref -> ref.matches("[A-Za-z0-9._:-]{1,256}"))
                .limit(MAX_EVIDENCE_REFS)
                .toList();
    }

    private static void rejectDestructive(String blob) {
        String lower = blob == null ? "" : blob.toLowerCase(Locale.ROOT);
        for (String token : DESTRUCTIVE) {
            if (lower.contains(token)) {
                throw new IllegalArgumentException("destructive payload rejected");
            }
        }
    }
}

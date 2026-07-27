package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * AI-authored auth-bypass feasibility PoC. AUTH_ANALYSIS / triage judges and authors
 * the payload; the server validates schema/bounds; DYNAMIC_VERIFICATION executes and
 * traces outcomes. Never alone upgrades verification status.
 */
public record AuthBypassCandidate(
        String entryRef,
        String techniqueId,
        IdentityTrack track,
        String rationale,
        List<String> evidenceRefs,
        double confidence,
        /** Token / header material for loopback probe (AI-authored; may be JWT). */
        String authorizationHeader,
        /**
         * Optional secondary auth-channel material (wire name {@code bladeAuthHeader} kept for
         * compatibility; semantically {@code secondaryAuthorizationHeader}). Empty means
         * Authorization-only unless the probe layer dual-writes from harvest hints.
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

    /** True when the model supplied probe-usable auth material (not only a label). */
    public boolean hasAuthMaterial() {
        return authorizationHeader != null && !authorizationHeader.isBlank();
    }

    /** Schema-gate AI auth material without constructing a full candidate. */
    public static void validateAuthMaterialOnly(String authorizationHeader) {
        normalizeAuthMaterial(authorizationHeader);
        rejectDestructive(authorizationHeader == null ? "" : authorizationHeader);
    }

    /** Probe-layer token body: strips a leading Bearer scheme if the model included it. */
    public String probeAuthToken() {
        if (!hasAuthMaterial()) return "";
        String value = authorizationHeader.trim();
        if (value.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return value.substring(7).trim();
        }
        return value;
    }

    /** Generic alias for {@link #bladeAuthHeader()}. */
    public String secondaryAuthorizationHeader() {
        return bladeAuthHeader == null ? "" : bladeAuthHeader;
    }

    public String probeBladeAuth() {
        return probeSecondaryAuth();
    }

    /** Probe-layer secondary-channel token body. */
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
        // Allow JWT / base64url / Bearer / common header token charset.
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

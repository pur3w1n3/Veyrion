package com.aq.jvmsentinel.analysis.identity;

import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * 从 authorized artifact harvest 的平台 owned synthetic identity 材料。
 * Provenance 为 MOCK / RULE_GENERATED / FACT（JAR 内 config）；永非 operator credential。
 *
 * <p>Channel selection is material-driven: JWT signing keys mint Bearer tokens; Cookie-channel
 * cipher / session 材料产生 Cookie header。无 silent fallback 到 commercial
 * framework default（任意 JAR），rememberMe cipher key 永不用作 JWT secret。
 */
public final class SyntheticIdentityService {

    /**
     * Fallback marker when AES mint fails；优先 {@link RememberMePayloadMinter}。
     */
    public static final String COOKIE_MATERIAL_MARKER = "veyrion-cipher-key-harvested";

    public record SyntheticIdentity(
            IdentityTrack track,
            String authorizationHeader,
            String provenance,
            String precondition,
            boolean available,
            String cookieHeader
    ) {
        public SyntheticIdentity {
            authorizationHeader = authorizationHeader == null ? "" : authorizationHeader;
            provenance = provenance == null ? "MOCK" : provenance;
            precondition = precondition == null ? "" : precondition;
            cookieHeader = cookieHeader == null ? "" : cookieHeader;
        }

        public SyntheticIdentity(
                IdentityTrack track,
                String authorizationHeader,
                String provenance,
                String precondition,
                boolean available) {
            this(track, authorizationHeader, provenance, precondition, available, "");
        }

        public static SyntheticIdentity unavailable(IdentityTrack track, String reason) {
            return new SyntheticIdentity(track, "", "MOCK", reason, false, "");
        }
    }

    public record MaterialBundle(
            Optional<String> jwtSecret,
            String secretProvenance,
            List<String> notes,
            boolean multiHeaderAuthSurface,
            boolean preferSecondaryAuthHeader,
            String secondaryAuthHeaderName,
            List<IdentityMaterial> identityMaterials
    ) {
        public MaterialBundle {
            jwtSecret = jwtSecret == null ? Optional.empty() : jwtSecret;
            secretProvenance = secretProvenance == null ? "NONE" : secretProvenance;
            notes = List.copyOf(notes == null ? List.of() : notes);
            secondaryAuthHeaderName = secondaryAuthHeaderName == null ? "" : secondaryAuthHeaderName;
            identityMaterials = List.copyOf(identityMaterials == null ? List.of() : identityMaterials);
        }

        public MaterialBundle(Optional<String> jwtSecret, String secretProvenance, List<String> notes) {
            this(jwtSecret, secretProvenance, notes, false, false, "", List.of());
        }

        public MaterialBundle(
                Optional<String> jwtSecret,
                String secretProvenance,
                List<String> notes,
                boolean multiHeaderAuthSurface,
                boolean preferSecondaryAuthHeader) {
            this(jwtSecret, secretProvenance, notes, multiHeaderAuthSurface,
                    preferSecondaryAuthHeader, preferSecondaryAuthHeader ? "Blade-Auth" : "", List.of());
        }

        public MaterialBundle(
                Optional<String> jwtSecret,
                String secretProvenance,
                List<String> notes,
                boolean multiHeaderAuthSurface,
                boolean preferSecondaryAuthHeader,
                String secondaryAuthHeaderName) {
            this(jwtSecret, secretProvenance, notes, multiHeaderAuthSurface,
                    preferSecondaryAuthHeader, secondaryAuthHeaderName, List.of());
        }

        public Optional<IdentityMaterial> cookieChannelMaterial() {
            for (IdentityMaterial material : identityMaterials) {
                if (material.channel() == AuthChannel.COOKIE
                        && (material.kind() == IdentityMaterialKind.CIPHER_KEY
                        || material.kind() == IdentityMaterialKind.SESSION_COOKIE)) {
                    return Optional.of(material);
                }
            }
            return Optional.empty();
        }

        /** @deprecated Prefer {@link #multiHeaderAuthSurface()}. */
        @Deprecated
        public boolean bladeSurface() {
            return multiHeaderAuthSurface;
        }

        /** @deprecated Prefer {@link #preferSecondaryAuthHeader()}. */
        @Deprecated
        public boolean preferBladeAuthHeader() {
            return preferSecondaryAuthHeader;
        }
    }

    public MaterialBundle harvest(Path artifactPath) {
        List<String> notes = new ArrayList<>();
        Optional<String> secret = Optional.empty();
        String provenance = "NONE";
        boolean multiHeader = false;
        String secondaryHeader = "";
        List<IdentityMaterial> materials = List.of();
        if (artifactPath != null && Files.isRegularFile(artifactPath)) {
            AuthCodeQueryService.AuthCodeQueryResult code =
                    new AuthCodeQueryService().query(artifactPath, "", 20);
            multiHeader = code.multiHeaderAuthSurface();
            secondaryHeader = code.secondaryAuthHeaderName();
            materials = code.identityMaterials();
            if (code.mintSecret().isPresent()) {
                secret = code.mintSecret();
                String candidateClass = code.secretCandidates().isEmpty()
                        ? "RULE_GENERATED"
                        : code.secretCandidates().get(0).classification();
                provenance = "FACT".equals(candidateClass) ? "FACT" : "RULE_GENERATED";
                notes.add("harvested sign-key via code_query ("
                        + code.preferredSignKeyProvenance() + "; classification="
                        + candidateClass + ")");
            } else {
                notes.add("no mintable JWT secret harvested from artifact"
                        + (multiHeader ? " (multi-header auth surface present)" : ""));
            }
            if (materials.stream().anyMatch(m -> m.channel() == AuthChannel.COOKIE)) {
                notes.add("cookie-channel identity material harvested (rememberMe/cipher)");
            }
        } else {
            notes.add("no artifact path; HS256 mint unavailable");
        }
        boolean preferSecondary = multiHeader && !secondaryHeader.isBlank();
        return new MaterialBundle(secret, provenance, List.copyOf(notes),
                multiHeader, preferSecondary, secondaryHeader, materials);
    }

    public SyntheticIdentity synthesize(IdentityTrack track, MaterialBundle materials) {
        if (track == IdentityTrack.UNAUTH) {
            return new SyntheticIdentity(track, "", "MOCK", "no credentials", true, "");
        }
        if (materials == null) {
            return SyntheticIdentity.unavailable(track,
                    "IDENTITY_UNAVAILABLE: no signing material harvested from artifact");
        }
        if (materials.jwtSecret().isPresent()) {
            String role = switch (track) {
                case ADMIN, BYPASS_CANDIDATE -> "administrator";
                case USER -> "user";
                case UNAUTH -> "anonymous";
            };
            String token = mintHs256Token(materials.jwtSecret().get(), role, track);
            String precondition = "synthetic " + track.name() + " JWT via " + materials.secretProvenance()
                    + "; " + String.join("; ", materials.notes());
            return new SyntheticIdentity(track, token, materials.secretProvenance(),
                    precondition, true, "");
        }
        Optional<IdentityMaterial> cookie = materials.cookieChannelMaterial();
        if (cookie.isPresent()) {
            IdentityMaterial material = cookie.get();
            String cookieName = material.name().isBlank() ? "rememberMe" : material.name();
            String key = material.value().orElse("");
            String minted = key.isBlank() ? "" : RememberMePayloadMinter.cookieHeader(cookieName, key);
            String cookieHeader = minted.isBlank()
                    ? cookieName + "=" + COOKIE_MATERIAL_MARKER
                    : minted;
            String provenance = material.valueProvenance().isBlank()
                    ? "RULE_GENERATED" : material.valueProvenance();
            String mintNote = minted.isBlank()
                    ? "rememberMe payload mint failed; marker cookie only"
                    : "rememberMe AES payload minted for sandbox deserialization observation";
            String precondition = "synthetic " + track.name() + " Cookie channel via " + provenance
                    + "; cipher/session material harvested; " + mintNote + "; "
                    + String.join("; ", materials.notes());
            return new SyntheticIdentity(track, "", provenance, precondition, true, cookieHeader);
        }
        return SyntheticIdentity.unavailable(track,
                "IDENTITY_UNAVAILABLE: no signing or cookie material harvested from artifact");
    }

    /**
     * AI PoC 未
     * 提供 authorizationHeader 时，已知 technique label 的 fallback materialization。存在时优先 AI 撰写 PoC 材料。
     */
    public SyntheticIdentity synthesizeTechnique(AuthBypassTechnique technique, MaterialBundle materials) {
        Objects.requireNonNull(technique, "technique");
        IdentityTrack track = technique.defaultTrack();
        return switch (technique) {
            case MISSING_AUTH -> new SyntheticIdentity(track, "", "MOCK",
                    "MISSING_AUTH: no Authorization header", true, "");
            // Probe 层前缀 "Authorization: bearer "；单空格产生近乎空 token。
            case EMPTY_BEARER -> new SyntheticIdentity(track, " ", "RULE_GENERATED",
                    "EMPTY_BEARER: blank bearer token", true, "");
            case DEFAULT_SECRET_HS256, LOGOUT_TOKEN -> {
                SyntheticIdentity minted = synthesize(IdentityTrack.BYPASS_CANDIDATE, materials);
                if (!minted.available() || minted.authorizationHeader().isBlank()) {
                    yield minted.available()
                            ? SyntheticIdentity.unavailable(track,
                            "IDENTITY_UNAVAILABLE: DEFAULT_SECRET_HS256 requires JWT signing material")
                            : minted;
                }
                yield new SyntheticIdentity(track, minted.authorizationHeader(), minted.provenance(),
                        technique.name() + "; " + minted.precondition(), true, "");
            }
            case ALG_NONE -> new SyntheticIdentity(track,
                    mintAlgNoneToken("administrator", track),
                    "RULE_GENERATED",
                    "ALG_NONE: unsigned JWT hypothesis (MOCK)", true, "");
            case ROLE_CONFUSION -> {
                if (materials == null || materials.jwtSecret().isEmpty()) {
                    yield SyntheticIdentity.unavailable(track,
                            "IDENTITY_UNAVAILABLE: no signing material for ROLE_CONFUSION");
                }
                String token = mintHs256Token(materials.jwtSecret().get(), "administrator", track);
                yield new SyntheticIdentity(track, token, materials.secretProvenance(),
                        "ROLE_CONFUSION: USER track carrying administrator claim; "
                                + materials.secretProvenance(), true, "");
            }
            case CUSTOM_POC -> SyntheticIdentity.unavailable(track,
                    "CUSTOM_POC requires AI-authored authorizationHeader");
        };
    }

    public Map<IdentityTrack, SyntheticIdentity> defaultTracks(Path artifactPath, boolean highValue) {
        MaterialBundle materials = harvest(artifactPath);
        Map<IdentityTrack, SyntheticIdentity> out = new LinkedHashMap<>();
        out.put(IdentityTrack.UNAUTH, synthesize(IdentityTrack.UNAUTH, materials));
        SyntheticIdentity admin = synthesize(IdentityTrack.ADMIN, materials);
        if (highValue) {
            out.put(IdentityTrack.USER, synthesize(IdentityTrack.USER, materials));
            out.put(IdentityTrack.ADMIN, admin);
            out.put(IdentityTrack.BYPASS_CANDIDATE, synthesize(IdentityTrack.BYPASS_CANDIDATE, materials));
        } else if (admin.available()) {
            out.put(IdentityTrack.ADMIN, admin);
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(out));
    }

    /**
     * 带 generic enterprise-ish claim（sub/role/exp）的最小 HS256 JWT。
     * Framework 特定 claim shape 属于 AI 撰写 PoC 或 adapter hint —
     * 非 hardcode 为 platform mint 叙事。
     */
    static String mintHs256Token(String secret, String role, IdentityTrack track) {
        String header = b64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        long now = System.currentTimeMillis() / 1000L;
        String account = "admin".equals(role) || "administrator".equals(role)
                ? "admin" : "veyrion-" + track.name().toLowerCase(Locale.ROOT);
        String roleName = "administrator".equals(role) || "admin".equals(role)
                ? "administrator" : role;
        String payload = b64Url("{"
                + "\"sub\":\"" + account + "\","
                + "\"account\":\"" + account + "\","
                + "\"user_name\":\"" + account + "\","
                + "\"role\":\"" + roleName + "\","
                + "\"role_name\":\"" + roleName + "\","
                + "\"authorities\":[\"" + roleName + "\"],"
                + "\"token_type\":\"access_token\","
                + "\"iat\":" + now + ","
                + "\"nbf\":" + now + ","
                + "\"exp\":" + (now + 3600) + ","
                + "\"mock\":true"
                + "}");
        String signingInput = header + "." + payload;
        String sig = b64Url(hmacSha256(secret.getBytes(StandardCharsets.UTF_8),
                signingInput.getBytes(StandardCharsets.UTF_8)));
        return signingInput + "." + sig;
    }

    /** Unsigned JWT used only for ALG_NONE hypothesis probes (RULE_GENERATED). */
    static String mintAlgNoneToken(String role, IdentityTrack track) {
        String header = b64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String account = "administrator".equals(role) || "admin".equals(role)
                ? "admin" : "veyrion-" + track.name().toLowerCase(Locale.ROOT);
        String payload = b64Url("{\"sub\":\"" + account + "\",\"role\":\"administrator\","
                + "\"role_name\":\"administrator\",\"account\":\"" + account
                + "\",\"user_name\":\"" + account
                + "\",\"token_type\":\"access_token\",\"mock\":true,\"algNone\":true}");
        return header + "." + payload + ".";
    }

    /**
     * 次要 auth-channel 值：scheme + token（probe 层不 auto-prefix
     * 次要 header 名）。Wire/API 仍可通过 {@link #bladeAuthHeaderValue} 调用。
     */
    public static String secondaryAuthHeaderValue(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) return "";
        String token = rawToken.trim();
        if (token.regionMatches(true, 0, "bearer ", 0, 7)) {
            return "bearer " + token.substring(7).trim();
        }
        return "bearer " + token;
    }

    /** @deprecated Use {@link #secondaryAuthHeaderValue}. */
    @Deprecated
    public static String bladeAuthHeaderValue(String rawToken) {
        return secondaryAuthHeaderValue(rawToken);
    }

    private static String b64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    /** Compact HMAC-SHA256 via javax.crypto when available; falls back to XOR digest. */
    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception fallback) {
            byte[] out = new byte[32];
            for (int i = 0; i < data.length; i++) {
                out[i % out.length] ^= (byte) (data[i] ^ key[i % key.length]);
            }
            return out;
        }
    }
}

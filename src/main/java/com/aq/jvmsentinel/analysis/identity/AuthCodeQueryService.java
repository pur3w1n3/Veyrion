package com.aq.jvmsentinel.analysis.identity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Bounded, load-free auth-surface query over a registered JAR/WAR.
 * Returns FACT-shaped observations for AI tools; never executes classes,
 * never opens network, and never elevates verification status.
 */
public final class AuthCodeQueryService {
    public static final String BLADE_DEFAULT_SIGN_KEY =
            "bladexisapowerfulmicroservicearchitectureupgradedandoptimizedfromacommercialproject";
    public static final String BLADE_LEGACY_ZERO_KEY = "00000000000000000000000000000000";

    private static final Pattern SKIP_URL = Pattern.compile(
            "(?i)(?:blade\\.)?secure\\.(?:skip[-_]?url|exclude[-_]?url|ignore[-_]?url)s?\\s*[=:]\\s*(.+)");
    private static final Pattern JWT_KEY_LINE = Pattern.compile(
            "(?i)(?:jwt[_\\-.]?(?:secret|sign(?:ing)?[_\\-.]?key|key)|blade[_\\-.]?token[_\\-.]?sign[_\\-.]?key)"
                    + "\\s*[=:]\\s*[\"']?([^\\s\"'#]+)");
    private static final List<String> AUTH_CLASS_HINTS = List.of(
            "org/springblade/core/secure",
            "org/springblade/core/jwt",
            "org/springblade/modules/auth",
            "SecureUtil",
            "JwtUtil",
            "JwtProperties",
            "TokenUtil",
            "BladeTokenEndPoint",
            "SecureRegistry");

    public record AuthCodeFact(
            String id,
            String category,
            String summary,
            String sourcePath,
            Map<String, String> attributes
    ) {
        public AuthCodeFact {
            id = Objects.requireNonNull(id, "id");
            category = Objects.requireNonNull(category, "category");
            summary = summary == null ? "" : summary;
            sourcePath = sourcePath == null ? "" : sourcePath;
            attributes = Map.copyOf(attributes == null ? Map.of() : attributes);
        }
    }

    public record AuthCodeQueryResult(
            boolean bladeSurface,
            boolean jwtDefaultKeyMatched,
            String preferredSignKeyProvenance,
            String preferredHeaderChannel,
            List<String> recommendedTechniques,
            List<AuthCodeFact> facts
    ) {
        public AuthCodeQueryResult {
            preferredSignKeyProvenance = preferredSignKeyProvenance == null ? "" : preferredSignKeyProvenance;
            preferredHeaderChannel = preferredHeaderChannel == null ? "Authorization" : preferredHeaderChannel;
            recommendedTechniques = List.copyOf(recommendedTechniques == null ? List.of() : recommendedTechniques);
            facts = List.copyOf(facts == null ? List.of() : facts);
        }
    }

    public AuthCodeQueryResult query(Path artifactPath, String query, int limit) {
        int capped = Math.max(1, Math.min(50, limit));
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT);
        List<AuthCodeFact> facts = new ArrayList<>();
        boolean bladeSurface = false;
        boolean jwtDefaultKeyMatched = false;
        String keyProvenance = "NONE";
        Set<String> skipUrls = new LinkedHashSet<>();
        Set<String> authClasses = new LinkedHashSet<>();

        if (artifactPath != null && Files.isRegularFile(artifactPath)) {
            try {
                ScanAccumulator acc = scanArtifact(artifactPath);
                bladeSurface = acc.bladeSurface;
                jwtDefaultKeyMatched = acc.jwtDefaultKeyMatched;
                keyProvenance = acc.keyProvenance;
                skipUrls.addAll(acc.skipUrls);
                authClasses.addAll(acc.authClasses);
            } catch (IOException ignored) {
                facts.add(new AuthCodeFact(
                        "auth-code:scan-failed",
                        "ERROR",
                        "bounded archive scan failed; auth code facts unavailable",
                        "",
                        Map.of("failure", "IOException")));
            }
        } else {
            facts.add(new AuthCodeFact(
                    "auth-code:no-artifact",
                    "ERROR",
                    "no registered artifact path available for code_query",
                    "",
                    Map.of()));
        }

        if (bladeSurface) {
            facts.add(new AuthCodeFact(
                    "auth-code:blade-surface",
                    "FRAMEWORK",
                    "SpringBlade secure/jwt/auth classes or routes observed in artifact",
                    "",
                    Map.of("framework", "SpringBlade",
                            "preferredAuthHeader", "Blade-Auth",
                            "jwtAlg", "HS256")));
        }
        if (jwtDefaultKeyMatched) {
            facts.add(new AuthCodeFact(
                    "auth-code:jwt-default-key",
                    "JWT_MATERIAL",
                    "Known Blade JWT sign-key material matched in config or class constants "
                            + "(use DEFAULT_SECRET_HS256; ALG_NONE is low-value for Blade SecureUtil)",
                    "",
                    Map.of("matched", "BLADE_DEFAULT_SIGN_KEY",
                            "provenance", keyProvenance,
                            "secretRedacted", "true")));
        }
        int skipIndex = 0;
        for (String skip : skipUrls) {
            if (facts.size() >= capped) break;
            facts.add(new AuthCodeFact(
                    "auth-code:skip-url-" + (++skipIndex),
                    "SKIP_URL",
                    "Auth skip/exclude URL pattern from configuration",
                    "",
                    Map.of("pattern", truncate(skip, 240))));
        }
        int classIndex = 0;
        for (String classPath : authClasses) {
            if (facts.size() >= capped) break;
            facts.add(new AuthCodeFact(
                    "auth-code:class-" + (++classIndex),
                    "AUTH_CLASS",
                    "Auth-related class entry observed",
                    classPath,
                    Map.of("entry", classPath)));
        }

        List<AuthCodeFact> filtered = new ArrayList<>();
        for (AuthCodeFact fact : facts) {
            if (filtered.size() >= capped) break;
            if (needle.isBlank() || matches(fact, needle)) {
                filtered.add(fact);
            }
        }

        List<String> techniques = new ArrayList<>();
        if (jwtDefaultKeyMatched || bladeSurface) {
            techniques.add("DEFAULT_SECRET_HS256");
            techniques.add("MISSING_AUTH");
            techniques.add("EMPTY_BEARER");
        } else {
            techniques.add("MISSING_AUTH");
            techniques.add("ALG_NONE");
            techniques.add("EMPTY_BEARER");
        }
        return new AuthCodeQueryResult(
                bladeSurface,
                jwtDefaultKeyMatched,
                keyProvenance,
                bladeSurface ? "Blade-Auth" : "Authorization",
                techniques,
                filtered);
    }

    private static boolean matches(AuthCodeFact fact, String needle) {
        String blob = (fact.id() + " " + fact.category() + " " + fact.summary()
                + " " + fact.sourcePath() + " " + fact.attributes()).toLowerCase(Locale.ROOT);
        return blob.contains(needle);
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static final class ScanAccumulator {
        boolean bladeSurface;
        boolean jwtDefaultKeyMatched;
        String keyProvenance = "NONE";
        final Set<String> skipUrls = new LinkedHashSet<>();
        final Set<String> authClasses = new LinkedHashSet<>();
    }

    private static ScanAccumulator scanArtifact(Path jar) throws IOException {
        ScanAccumulator acc = new ScanAccumulator();
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(jar))) {
            ZipEntry entry;
            int scanned = 0;
            while ((entry = zip.getNextEntry()) != null && scanned < 800) {
                if (entry.isDirectory()) continue;
                String name = entry.getName();
                String lower = name.toLowerCase(Locale.ROOT);
                if (looksAuthClass(lower)) {
                    acc.bladeSurface = true;
                    if (acc.authClasses.size() < 40) {
                        acc.authClasses.add(truncate(name, 240));
                    }
                }
                if (!(lower.endsWith(".yml") || lower.endsWith(".yaml") || lower.endsWith(".properties")
                        || lower.endsWith(".json") || lower.endsWith(".xml") || lower.endsWith(".class"))) {
                    continue;
                }
                if (entry.getSize() > 256 * 1024) continue;
                scanned++;
                byte[] bytes = readLimited(zip, 64 * 1024);
                if (lower.endsWith(".class")) {
                    String latin = new String(bytes, StandardCharsets.ISO_8859_1);
                    if (latin.contains(BLADE_DEFAULT_SIGN_KEY)) {
                        acc.jwtDefaultKeyMatched = true;
                        acc.bladeSurface = true;
                        acc.keyProvenance = "CLASS_CONSTANT:" + truncate(name, 160);
                    } else if (latin.contains(BLADE_LEGACY_ZERO_KEY) && !acc.jwtDefaultKeyMatched) {
                        acc.jwtDefaultKeyMatched = true;
                        acc.keyProvenance = "CLASS_CONSTANT_ZERO_KEY:" + truncate(name, 160);
                    }
                    continue;
                }
                String text = new String(bytes, StandardCharsets.UTF_8);
                if (text.contains("blade") || text.contains("bladex") || text.contains("springblade")) {
                    acc.bladeSurface = true;
                }
                if (text.contains(BLADE_DEFAULT_SIGN_KEY)) {
                    acc.jwtDefaultKeyMatched = true;
                    acc.bladeSurface = true;
                    acc.keyProvenance = "CONFIG_OR_RESOURCE:" + truncate(name, 160);
                }
                Matcher skip = SKIP_URL.matcher(text);
                while (skip.find() && acc.skipUrls.size() < 24) {
                    acc.skipUrls.add(skip.group(1).trim());
                }
                Matcher keyLine = JWT_KEY_LINE.matcher(text);
                if (keyLine.find() && !acc.jwtDefaultKeyMatched) {
                    String value = keyLine.group(1).trim();
                    if (BLADE_DEFAULT_SIGN_KEY.equals(value) || BLADE_LEGACY_ZERO_KEY.equals(value)) {
                        acc.jwtDefaultKeyMatched = true;
                        acc.keyProvenance = "CONFIG_KEY:" + truncate(name, 160);
                    } else if (value.length() >= 8) {
                        // Do not return raw custom secrets to the model; only note presence.
                        acc.keyProvenance = "CONFIG_KEY_PRESENT_REDACTED:" + truncate(name, 160);
                    }
                }
            }
        }
        return acc;
    }

    private static boolean looksAuthClass(String lowerPath) {
        for (String hint : AUTH_CLASS_HINTS) {
            if (lowerPath.contains(hint.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
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

    /** Convenience map for tool JSON (no raw secrets). */
    public static Map<String, Object> toToolMap(AuthCodeQueryResult result) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("bladeSurface", result.bladeSurface());
        root.put("jwtDefaultKeyMatched", result.jwtDefaultKeyMatched());
        root.put("preferredSignKeyProvenance", result.preferredSignKeyProvenance());
        root.put("preferredHeaderChannel", result.preferredHeaderChannel());
        root.put("recommendedTechniques", result.recommendedTechniques());
        root.put("classification", "FACT");
        root.put("verificationStatus", "STATIC_INFERRED");
        List<Map<String, Object>> facts = new ArrayList<>();
        for (AuthCodeFact fact : result.facts()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", fact.id());
            item.put("category", fact.category());
            item.put("summary", fact.summary());
            item.put("sourcePath", fact.sourcePath());
            item.put("attributes", fact.attributes());
            facts.add(item);
        }
        root.put("facts", facts);
        return root;
    }
}

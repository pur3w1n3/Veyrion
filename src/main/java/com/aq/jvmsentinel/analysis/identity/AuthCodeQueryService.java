package com.aq.jvmsentinel.analysis.identity;

import com.aq.jvmsentinel.analysis.framework.FrameworkAdapter;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.analysis.framework.SpringBladeAdapter;

import java.io.ByteArrayInputStream;
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
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Bounded, load-free auth-surface query over a registered JAR/WAR.
 * Returns FACT-shaped observations for AI tools; never executes classes,
 * never opens network, and never elevates verification status.
 *
 * <p>Core harvest uses generic JWT/secret property patterns and auth filter/annotation
 * signals. Optional {@link com.aq.jvmsentinel.analysis.framework.FrameworkAdapter}
 * dictionaries contribute known-weak-key HINTs for in-artifact matching only — never
 * silent mint sources for a general platform.
 */
public final class AuthCodeQueryService {
    /**
     * @deprecated Detection dictionary moved to {@link SpringBladeAdapter#WELL_KNOWN_COMMERCIAL_SIGN_KEY};
     * kept as a fixture/compat alias — not a core mint source.
     */
    @Deprecated
    public static final String WELL_KNOWN_BLADE_COMMERCIAL_SIGN_KEY =
            SpringBladeAdapter.WELL_KNOWN_COMMERCIAL_SIGN_KEY;
    /**
     * @deprecated Detection dictionary moved to {@link SpringBladeAdapter#WELL_KNOWN_LEGACY_ZERO_KEY}.
     */
    @Deprecated
    public static final String WELL_KNOWN_BLADE_LEGACY_ZERO_KEY =
            SpringBladeAdapter.WELL_KNOWN_LEGACY_ZERO_KEY;

    /** @deprecated Use {@link #WELL_KNOWN_BLADE_COMMERCIAL_SIGN_KEY}. */
    @Deprecated
    public static final String BLADE_DEFAULT_SIGN_KEY = WELL_KNOWN_BLADE_COMMERCIAL_SIGN_KEY;
    /** @deprecated Use {@link #WELL_KNOWN_BLADE_LEGACY_ZERO_KEY}. */
    @Deprecated
    public static final String BLADE_LEGACY_ZERO_KEY = WELL_KNOWN_BLADE_LEGACY_ZERO_KEY;

    private static final Pattern SKIP_URL = Pattern.compile(
            "(?i)(?:[a-z0-9._-]+\\.)?secure\\.(?:skip[-_]?url|exclude[-_]?url|ignore[-_]?url)s?\\s*[=:]\\s*(.+)");
    private static final Pattern JWT_KEY_LINE = Pattern.compile(
            "(?i)(?:jwt[_\\-.]?(?:secret|sign(?:ing)?[_\\-.]?key|key)"
                    + "|token[_\\-.]?sign[_\\-.]?key"
                    + "|[a-z0-9._-]*token[_\\-.]?sign[_\\-.]?key"
                    + "|spring\\.security\\.oauth2\\.resourceserver\\.jwt\\.secret[-_]?key)"
                    + "\\s*[=:]\\s*[\"']?([^\\s\"'#]+)");
    private static final Pattern PRE_AUTH = Pattern.compile(
            "(?i)@PreAuth|hasRole\\s*\\(|hasAnyRole\\s*\\(|PreAuthorize|RolesAllowed|Secured\\s*\\(");
    private static final Pattern TOKEN_FILTER = Pattern.compile(
            "(?i)TokenFilter|JwtAuth|JwtAuthentication|BearerToken|"
                    + "SecureInterceptor|AuthFilter|OncePerRequestFilter");
    /** Generic JVM auth class-name fragments (framework-agnostic). */
    private static final List<String> GENERIC_AUTH_CLASS_HINTS = List.of(
            "SecureUtil",
            "JwtUtil",
            "JwtProperties",
            "TokenUtil",
            "SecureRegistry",
            "TokenFilter",
            "JwtAuth",
            "BearerToken",
            "JwtAuthenticationFilter",
            "UsernamePasswordAuthenticationFilter");

    public record WellKnownKey(String alias, String value, String usage) {
        public static final String USAGE_JWT_SIGNING = "JWT_SIGNING";
        public static final String USAGE_REMEMBER_ME_CIPHER = "REMEMBER_ME_CIPHER";

        public WellKnownKey(String alias, String value) {
            this(alias, value, USAGE_JWT_SIGNING);
        }

        public WellKnownKey {
            alias = Objects.requireNonNull(alias, "alias");
            value = Objects.requireNonNull(value, "value");
            usage = usage == null || usage.isBlank() ? USAGE_JWT_SIGNING : usage.trim();
        }

        public int keyLen() {
            return value.length();
        }

        public boolean jwtSigning() {
            return USAGE_JWT_SIGNING.equals(usage);
        }

        public boolean rememberMeCipher() {
            return USAGE_REMEMBER_ME_CIPHER.equals(usage);
        }
    }

    /**
     * Redacted candidate for AI / tool output. Never carries raw secret bytes.
     *
     * @param classification FACT when value was present in artifact config/class;
     *                       RULE_GENERATED when alias matched a well-known dictionary
     *                       entry found in the artifact; HINT for adapter-only notes
     */
    public record SecretCandidateHint(
            String alias,
            String provenance,
            String classification,
            int keyLen,
            boolean mintable
    ) {
        public SecretCandidateHint {
            alias = alias == null ? "" : alias;
            provenance = provenance == null ? "" : provenance;
            classification = classification == null ? "HINT" : classification;
        }
    }

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
            boolean multiHeaderAuthSurface,
            boolean jwtSecretMaterialFound,
            String preferredSignKeyProvenance,
            String preferredHeaderChannel,
            String secondaryAuthHeaderName,
            List<String> recommendedTechniques,
            List<AuthCodeFact> facts,
            List<SecretCandidateHint> secretCandidates,
            Optional<String> mintSecret,
            List<IdentityMaterial> identityMaterials
    ) {
        public AuthCodeQueryResult {
            preferredSignKeyProvenance = preferredSignKeyProvenance == null ? "" : preferredSignKeyProvenance;
            preferredHeaderChannel = preferredHeaderChannel == null ? "Authorization" : preferredHeaderChannel;
            secondaryAuthHeaderName = secondaryAuthHeaderName == null ? "" : secondaryAuthHeaderName;
            recommendedTechniques = List.copyOf(recommendedTechniques == null ? List.of() : recommendedTechniques);
            facts = List.copyOf(facts == null ? List.of() : facts);
            secretCandidates = List.copyOf(secretCandidates == null ? List.of() : secretCandidates);
            mintSecret = mintSecret == null ? Optional.empty() : mintSecret;
            identityMaterials = List.copyOf(identityMaterials == null ? List.of() : identityMaterials);
        }

        /**
         * Compact constructor for callers that omit secondary header name / materials.
         */
        public AuthCodeQueryResult(
                boolean multiHeaderAuthSurface,
                boolean jwtSecretMaterialFound,
                String preferredSignKeyProvenance,
                String preferredHeaderChannel,
                List<String> recommendedTechniques,
                List<AuthCodeFact> facts,
                List<SecretCandidateHint> secretCandidates,
                Optional<String> mintSecret) {
            this(multiHeaderAuthSurface, jwtSecretMaterialFound, preferredSignKeyProvenance,
                    preferredHeaderChannel,
                    "Authorization".equals(preferredHeaderChannel) ? "" : preferredHeaderChannel,
                    recommendedTechniques, facts, secretCandidates, mintSecret, List.of());
        }

        public AuthCodeQueryResult(
                boolean multiHeaderAuthSurface,
                boolean jwtSecretMaterialFound,
                String preferredSignKeyProvenance,
                String preferredHeaderChannel,
                String secondaryAuthHeaderName,
                List<String> recommendedTechniques,
                List<AuthCodeFact> facts,
                List<SecretCandidateHint> secretCandidates,
                Optional<String> mintSecret) {
            this(multiHeaderAuthSurface, jwtSecretMaterialFound, preferredSignKeyProvenance,
                    preferredHeaderChannel, secondaryAuthHeaderName, recommendedTechniques, facts,
                    secretCandidates, mintSecret, List.of());
        }

        /** @deprecated Prefer {@link #multiHeaderAuthSurface()}; adapter-local naming. */
        @Deprecated
        public boolean bladeSurface() {
            return multiHeaderAuthSurface;
        }

        /** @deprecated Prefer {@link #jwtSecretMaterialFound()}. */
        @Deprecated
        public boolean jwtDefaultKeyMatched() {
            return jwtSecretMaterialFound;
        }
    }

    /**
     * Adapter-owned well-known key HINTs for FRAMEWORK_ADAPTER_CONTEXT (not FACT).
     * @deprecated Prefer {@link FrameworkAdapterRegistry#wellKnownSecretDictionaries()}.
     */
    @Deprecated
    public static List<WellKnownKey> wellKnownBladeKeyHints() {
        return FrameworkAdapterRegistry.wellKnownSecretDictionaries();
    }

    public AuthCodeQueryResult query(Path artifactPath, String query, int limit) {
        int capped = Math.max(1, Math.min(50, limit));
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT);
        List<AuthCodeFact> facts = new ArrayList<>();
        boolean multiHeaderSurface = false;
        boolean secretFound = false;
        String keyProvenance = "NONE";
        String keyAlias = "";
        Optional<String> mintSecret = Optional.empty();
        List<SecretCandidateHint> candidates = new ArrayList<>();
        Set<String> skipUrls = new LinkedHashSet<>();
        Set<String> authClasses = new LinkedHashSet<>();
        boolean preAuthSeen = false;
        boolean tokenFilterSeen = false;
        String secondaryHeader = "";

        List<IdentityMaterial> materials = new ArrayList<>();
        if (artifactPath != null && Files.isRegularFile(artifactPath)) {
            try {
                ScanAccumulator acc = scanArtifact(artifactPath);
                multiHeaderSurface = acc.multiHeaderAuthSurface;
                secretFound = acc.mintSecret.isPresent();
                keyProvenance = acc.keyProvenance;
                keyAlias = acc.keyAlias;
                mintSecret = acc.mintSecret;
                skipUrls.addAll(acc.skipUrls);
                authClasses.addAll(acc.authClasses);
                preAuthSeen = acc.preAuthSeen;
                tokenFilterSeen = acc.tokenFilterSeen;
                secondaryHeader = acc.secondaryAuthHeaderName;
                materials.addAll(acc.identityMaterials);
                if (secretFound) {
                    String classification = keyProvenance.startsWith("CONFIG_KEY:")
                            || keyProvenance.startsWith("CONFIG_OR_RESOURCE:")
                            ? "FACT" : "RULE_GENERATED";
                    if (keyAlias.startsWith("WELL_KNOWN_")) {
                        classification = "RULE_GENERATED";
                    } else if (keyAlias.equals("CUSTOM_CONFIG")
                            || keyAlias.equals("CUSTOM_CLASS_CONSTANT")) {
                        classification = "FACT";
                    }
                    candidates.add(new SecretCandidateHint(
                            keyAlias.isBlank() ? "HARVESTED" : keyAlias,
                            keyProvenance,
                            classification,
                            mintSecret.map(String::length).orElse(0),
                            true));
                    materials.add(new IdentityMaterial(
                            IdentityMaterialKind.SIGNING_KEY,
                            AuthChannel.HEADER,
                            "Authorization",
                            classification,
                            keyAlias.isBlank() ? "HARVESTED" : keyAlias,
                            mintSecret,
                            List.of(),
                            keyProvenance));
                    materials.add(new IdentityMaterial(
                            IdentityMaterialKind.BEARER_TOKEN,
                            AuthChannel.HEADER,
                            "Authorization",
                            "RULE_GENERATED",
                            keyAlias.isBlank() ? "HARVESTED" : keyAlias,
                            Optional.empty(),
                            List.of(),
                            keyProvenance));
                } else if (acc.configKeyPresentRedacted) {
                    candidates.add(new SecretCandidateHint(
                            "CUSTOM_REDACTED",
                            acc.keyProvenance,
                            "FACT",
                            0,
                            false));
                }
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

        if (secondaryHeader.isBlank() && multiHeaderSurface) {
            secondaryHeader = FrameworkAdapterRegistry.secondaryAuthHeaderName(
                    artifactPath, List.of());
        }
        if (multiHeaderSurface) {
            Map<String, String> attrs = new LinkedHashMap<>();
            attrs.put("multiHeaderAuth", "true");
            if (!secondaryHeader.isBlank()) {
                attrs.put("preferredAuthHeader", secondaryHeader);
                attrs.put("secondaryAuthHeaderName", secondaryHeader);
            }
            attrs.put("jwtAlg", "HS256");
            attrs.put("note", "framework-adapter HINT only until code_query harvests sign-key");
            facts.add(new AuthCodeFact(
                    "auth-code:multi-header-auth-surface",
                    "FRAMEWORK",
                    "Multi-header / framework auth surface signals observed (adapter HINT)",
                    "",
                    attrs));
        }
        if (secretFound) {
            facts.add(new AuthCodeFact(
                    "auth-code:jwt-secret-material",
                    "JWT_MATERIAL",
                    "JWT sign-key material harvested from artifact (mintable; cite this evidence; "
                            + "do not assume a global hardcoded key is FACT)",
                    "",
                    Map.of("matched", keyAlias.isBlank() ? "HARVESTED" : keyAlias,
                            "provenance", keyProvenance,
                            "secretRedacted", "true",
                            "classification", candidates.isEmpty()
                                    ? "RULE_GENERATED" : candidates.get(0).classification())));
        } else if (multiHeaderSurface) {
            facts.add(new AuthCodeFact(
                    "auth-code:jwt-secret-absent",
                    "JWT_MATERIAL",
                    "Auth surface seen but no mintable sign-key harvested from artifact; "
                            + "prefer MISSING_AUTH / EMPTY_BEARER / ALG_NONE; use adapter well-known "
                            + "aliases only as HINT via FRAMEWORK_ADAPTER_CONTEXT after code_query",
                    "",
                    Map.of("mintable", "false")));
        }
        boolean cipherMaterial = materials.stream()
                .anyMatch(m -> m.kind() == IdentityMaterialKind.CIPHER_KEY);
        if (cipherMaterial) {
            IdentityMaterial cipher = materials.stream()
                    .filter(m -> m.kind() == IdentityMaterialKind.CIPHER_KEY)
                    .findFirst()
                    .orElseThrow();
            facts.add(new AuthCodeFact(
                    "auth-code:remember-me-cipher-material",
                    "COOKIE_MATERIAL",
                    "RememberMe / cookie cipher-key material harvested from artifact "
                            + "(not a JWT signing secret; Cookie channel only)",
                    cipher.sourcePath(),
                    Map.of("matched", cipher.alias().isBlank() ? "HARVESTED" : cipher.alias(),
                            "channel", AuthChannel.COOKIE.name(),
                            "cookieName", cipher.name().isBlank() ? "rememberMe" : cipher.name(),
                            "secretRedacted", "true",
                            "classification", cipher.valueProvenance())));
        }
        if (preAuthSeen) {
            facts.add(new AuthCodeFact(
                    "auth-code:preauth-signal",
                    "AUTH_ANNOTATION",
                    "@PreAuth / PreAuthorize / RolesAllowed / hasRole signals observed in resources",
                    "",
                    Map.of("signal", "PRE_AUTH")));
        }
        if (tokenFilterSeen) {
            facts.add(new AuthCodeFact(
                    "auth-code:token-filter-signal",
                    "AUTH_FILTER",
                    "Token/JWT filter or Secure interceptor class names observed",
                    "",
                    Map.of("signal", "TOKEN_FILTER")));
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
            if ("ERROR".equals(fact.category()) || needle.isBlank() || matches(fact, needle)) {
                filtered.add(fact);
            }
        }

        List<String> techniques = new ArrayList<>();
        if (cipherMaterial) {
            // Cookie-channel rememberMe cipher material — not JWT; AI may use CUSTOM_POC/Cookie.
            techniques.add("REMEMBER_ME_COOKIE");
            techniques.add("CUSTOM_POC");
        }
        if (secretFound) {
            techniques.add("DEFAULT_SECRET_HS256");
            techniques.add("MISSING_AUTH");
            techniques.add("EMPTY_BEARER");
        } else if (multiHeaderSurface || preAuthSeen || tokenFilterSeen) {
            techniques.add("MISSING_AUTH");
            techniques.add("EMPTY_BEARER");
            techniques.add("ALG_NONE");
        } else if (!cipherMaterial) {
            techniques.add("MISSING_AUTH");
            techniques.add("ALG_NONE");
            techniques.add("EMPTY_BEARER");
        } else {
            techniques.add("MISSING_AUTH");
        }
        String preferredChannel = !secondaryHeader.isBlank() && multiHeaderSurface
                ? secondaryHeader : "Authorization";
        return new AuthCodeQueryResult(
                multiHeaderSurface,
                secretFound,
                keyProvenance,
                preferredChannel,
                secondaryHeader,
                techniques,
                filtered,
                candidates,
                mintSecret,
                materials);
    }

    /** Channel-agnostic identity materials harvested from the authorized artifact. */
    public List<IdentityMaterial> harvestMaterials(Path artifactPath) {
        return query(artifactPath, "", 50).identityMaterials();
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
        boolean multiHeaderAuthSurface;
        String secondaryAuthHeaderName = "";
        String keyProvenance = "NONE";
        String keyAlias = "";
        Optional<String> mintSecret = Optional.empty();
        boolean configKeyPresentRedacted;
        boolean preAuthSeen;
        boolean tokenFilterSeen;
        final Set<String> skipUrls = new LinkedHashSet<>();
        final Set<String> authClasses = new LinkedHashSet<>();
        final List<IdentityMaterial> identityMaterials = new ArrayList<>();
    }

    private static final int MAX_NESTED_JWT_LIBS = 24;
    private static final int MAX_NESTED_JWT_LIB_BYTES = 6 * 1024 * 1024;

    private static ScanAccumulator scanArtifact(Path jar) throws IOException {
        ScanAccumulator acc = new ScanAccumulator();
        List<WellKnownKey> jwtDictionary = FrameworkAdapterRegistry.wellKnownJwtSigningDictionaries();
        Set<String> adapterAuthPaths = FrameworkAdapterRegistry.authClassPathSignals();
        String secondaryHint = FrameworkAdapterRegistry.secondaryAuthHeaderName(jar, List.of());
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(jar))) {
            ZipEntry entry;
            int scanned = 0;
            int nestedLibs = 0;
            while ((entry = zip.getNextEntry()) != null && scanned < 2_400) {
                if (entry.isDirectory()) continue;
                String name = entry.getName();
                String lower = name.toLowerCase(Locale.ROOT);
                if (isNestedJar(lower)) {
                    if (nestedLibs < MAX_NESTED_JWT_LIBS && isJwtAuthNestedJar(lower)
                            && acc.mintSecret.isEmpty()) {
                        nestedLibs++;
                        byte[] nested = readLimited(zip, MAX_NESTED_JWT_LIB_BYTES);
                        scanNestedJarForJwt(nested, name, acc, jwtDictionary, adapterAuthPaths,
                                secondaryHint);
                    }
                    continue;
                }
                if (looksAuthClass(lower, adapterAuthPaths)) {
                    if (matchesAdapterAuthPath(lower, adapterAuthPaths) || looksMultiHeaderHint(lower)) {
                        acc.multiHeaderAuthSurface = true;
                        markSecondaryHeader(acc, lower, secondaryHint);
                    }
                    if (acc.authClasses.size() < 40) {
                        acc.authClasses.add(truncate(name, 240));
                    }
                }
                if (!(lower.endsWith(".yml") || lower.endsWith(".yaml") || lower.endsWith(".properties")
                        || lower.endsWith(".json") || lower.endsWith(".xml") || lower.endsWith(".class")
                        || lower.endsWith(".java"))) {
                    continue;
                }
                if (entry.getSize() > 256 * 1024) continue;
                scanned++;
                byte[] bytes = readLimited(zip, 64 * 1024);
                ingestAuthBytes(name, lower, bytes, acc, jwtDictionary, adapterAuthPaths, secondaryHint);
            }
        }
        List<RememberMeCipherHarvester.Hit> cipherHits = RememberMeCipherHarvester.scan(jar);
        acc.identityMaterials.addAll(RememberMeCipherHarvester.toMaterials(cipherHits));
        return acc;
    }

    private static void scanNestedJarForJwt(
            byte[] nestedJar,
            String nestName,
            ScanAccumulator acc,
            List<WellKnownKey> jwtDictionary,
            Set<String> adapterAuthPaths,
            String secondaryHint) {
        if (nestedJar == null || nestedJar.length == 0 || !acc.mintSecret.isEmpty()) {
            return;
        }
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(nestedJar))) {
            ZipEntry entry;
            int counted = 0;
            while ((entry = zip.getNextEntry()) != null && counted < 500) {
                if (entry.isDirectory()) continue;
                String name = nestName + "!" + entry.getName();
                String lower = name.toLowerCase(Locale.ROOT);
                if (!(lower.endsWith(".class") || lower.endsWith(".yml") || lower.endsWith(".yaml")
                        || lower.endsWith(".properties"))) {
                    continue;
                }
                counted++;
                byte[] bytes = readLimited(zip, 64 * 1024);
                ingestAuthBytes(name, lower, bytes, acc, jwtDictionary, adapterAuthPaths, secondaryHint);
                if (acc.mintSecret.isPresent()) {
                    return;
                }
            }
        } catch (IOException ignored) {
            // Nested optional.
        }
    }

    private static void ingestAuthBytes(
            String name,
            String lower,
            byte[] bytes,
            ScanAccumulator acc,
            List<WellKnownKey> jwtDictionary,
            Set<String> adapterAuthPaths,
            String secondaryHint) {
        if (bytes == null || bytes.length == 0) return;
        if (lower.endsWith(".class") || lower.endsWith(".java")) {
            String latin = new String(bytes, StandardCharsets.ISO_8859_1);
            if (PRE_AUTH.matcher(latin).find()) {
                acc.preAuthSeen = true;
            }
            if (TOKEN_FILTER.matcher(latin).find()
                    || lower.contains("tokeninterceptor")
                    || lower.contains("authinterceptor")) {
                acc.tokenFilterSeen = true;
            }
            if (acc.mintSecret.isEmpty()) {
                for (WellKnownKey known : jwtDictionary) {
                    if (latin.contains(known.value())) {
                        acc.mintSecret = Optional.of(known.value());
                        acc.keyAlias = known.alias();
                        acc.keyProvenance = "CLASS_CONSTANT:" + truncate(name, 160);
                        if (matchesAdapterAuthPath(lower, adapterAuthPaths)
                                || looksMultiHeaderHint(lower)
                                || looksMultiHeaderHint(latin.toLowerCase(Locale.ROOT))) {
                            acc.multiHeaderAuthSurface = true;
                            markSecondaryHeader(acc, lower, secondaryHint);
                        }
                        break;
                    }
                }
            }
            return;
        }
        String text = new String(bytes, StandardCharsets.UTF_8);
        String textLower = text.toLowerCase(Locale.ROOT);
        if (looksMultiHeaderHint(textLower) || matchesAdapterAuthPath(textLower, adapterAuthPaths)) {
            acc.multiHeaderAuthSurface = true;
            markSecondaryHeader(acc, textLower, secondaryHint);
        }
        if (PRE_AUTH.matcher(text).find()) {
            acc.preAuthSeen = true;
        }
        if (TOKEN_FILTER.matcher(text).find()) {
            acc.tokenFilterSeen = true;
        }
        if (acc.mintSecret.isEmpty()) {
            for (WellKnownKey known : jwtDictionary) {
                if (text.contains(known.value())) {
                    acc.mintSecret = Optional.of(known.value());
                    acc.keyAlias = known.alias();
                    acc.keyProvenance = "CONFIG_OR_RESOURCE:" + truncate(name, 160);
                    if (looksMultiHeaderHint(textLower)) {
                        acc.multiHeaderAuthSurface = true;
                        markSecondaryHeader(acc, textLower, secondaryHint);
                    }
                    break;
                }
            }
        }
        Matcher skip = SKIP_URL.matcher(text);
        while (skip.find() && acc.skipUrls.size() < 24) {
            acc.skipUrls.add(skip.group(1).trim());
        }
        Matcher keyLine = JWT_KEY_LINE.matcher(text);
        if (keyLine.find() && acc.mintSecret.isEmpty()) {
            String value = keyLine.group(1).trim();
            Optional<WellKnownKey> known = matchWellKnown(value, jwtDictionary);
            if (known.isPresent()) {
                acc.mintSecret = Optional.of(known.get().value());
                acc.keyAlias = known.get().alias();
                acc.keyProvenance = "CONFIG_KEY:" + truncate(name, 160);
                if (looksMultiHeaderHint(textLower)) {
                    acc.multiHeaderAuthSurface = true;
                    markSecondaryHeader(acc, textLower, secondaryHint);
                }
            } else if (value.length() >= 8 && value.length() <= 256
                    && looksPlausibleSecret(value)
                    && !isKnownRememberMeCipher(value)) {
                acc.mintSecret = Optional.of(value);
                acc.keyAlias = "CUSTOM_CONFIG";
                acc.keyProvenance = "CONFIG_KEY:" + truncate(name, 160);
            } else if (value.length() >= 8) {
                acc.configKeyPresentRedacted = true;
                acc.keyProvenance = "CONFIG_KEY_PRESENT_REDACTED:" + truncate(name, 160);
            }
        }
    }

    private static boolean isNestedJar(String lowerPath) {
        return (lowerPath.startsWith("boot-inf/lib/") || lowerPath.startsWith("web-inf/lib/"))
                && lowerPath.endsWith(".jar");
    }

    private static boolean isJwtAuthNestedJar(String lowerPath) {
        String file = lowerPath;
        int slash = lowerPath.lastIndexOf('/');
        if (slash >= 0) {
            file = lowerPath.substring(slash + 1);
        }
        return file.contains("blade-starter-jwt")
                || file.contains("blade-core-secure")
                || file.contains("blade-core-tool")
                || file.contains("jjwt")
                || file.contains("nimbus-jose")
                || file.contains("java-jwt");
    }

    private static boolean isKnownRememberMeCipher(String value) {
        if (value == null) return false;
        for (WellKnownKey known : RememberMeCipherHarvester.dictionary()) {
            if (known.value().equals(value)) return true;
        }
        return false;
    }

    private static void markSecondaryHeader(
            ScanAccumulator acc, String evidenceLower, String filenameHint) {
        if (acc.secondaryAuthHeaderName != null && !acc.secondaryAuthHeaderName.isBlank()) {
            return;
        }
        for (FrameworkAdapter adapter : FrameworkAdapterRegistry.all()) {
            String name = adapter.secondaryAuthHeaderName();
            if (name == null || name.isBlank()) continue;
            if (matchesAdapterAuthPath(evidenceLower, adapter.authClassPathSignals())
                    || adapter.preferSecondaryAuthHeader(null)) {
                // Prefer adapters whose path signals appear in this evidence blob.
                if (matchesAdapterAuthPath(evidenceLower, adapter.authClassPathSignals())
                        || looksMultiHeaderHint(evidenceLower)) {
                    acc.secondaryAuthHeaderName = name.trim();
                    return;
                }
            }
        }
        if (filenameHint != null && !filenameHint.isBlank()) {
            acc.secondaryAuthHeaderName = filenameHint.trim();
        }
    }

    private static Optional<WellKnownKey> matchWellKnown(String value, List<WellKnownKey> dictionary) {
        for (WellKnownKey known : dictionary) {
            if (known.value().equals(value)) {
                return Optional.of(known);
            }
        }
        return Optional.empty();
    }

    private static boolean looksPlausibleSecret(String value) {
        if (value == null || value.length() < 8) return false;
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.startsWith("${") || lower.contains("changeme") || lower.equals("null")) {
            return false;
        }
        return value.chars().allMatch(ch -> ch >= 0x20 && ch < 0x7f);
    }

    private static boolean looksAuthClass(String lowerPath, Set<String> adapterPaths) {
        for (String hint : GENERIC_AUTH_CLASS_HINTS) {
            if (lowerPath.contains(hint.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return matchesAdapterAuthPath(lowerPath, adapterPaths);
    }

    private static boolean matchesAdapterAuthPath(String lowerPath, Set<String> adapterPaths) {
        if (adapterPaths == null) return false;
        for (String hint : adapterPaths) {
            if (lowerPath.contains(hint.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    /** Heuristic for dual-channel auth surfaces (header names / package markers in resources). */
    private static boolean looksMultiHeaderHint(String lower) {
        if (lower == null || lower.isBlank()) return false;
        return lower.contains("blade-auth")
                || lower.contains("x-access-token")
                || lower.contains("secondary-auth")
                || lower.contains("org/springblade")
                || lower.contains("org.springblade");
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
        boolean cookieMaterial = result.facts().stream()
                .anyMatch(f -> "COOKIE_MATERIAL".equals(f.category()));
        boolean cipherKeyMaterial = result.identityMaterials().stream()
                .anyMatch(m -> m.kind() == IdentityMaterialKind.CIPHER_KEY);
        root.put("multiHeaderAuthSurface", result.multiHeaderAuthSurface());
        root.put("bladeSurface", result.multiHeaderAuthSurface()); // deprecated wire alias
        root.put("jwtSecretMaterialFound", result.jwtSecretMaterialFound());
        root.put("jwtDefaultKeyMatched", result.jwtSecretMaterialFound()); // compat alias
        root.put("rememberMeCipherMaterialFound", cipherKeyMaterial || cookieMaterial);
        root.put("cookieMaterialFound", cookieMaterial);
        root.put("preferredSignKeyProvenance", result.preferredSignKeyProvenance());
        root.put("preferredHeaderChannel", result.preferredHeaderChannel());
        root.put("secondaryAuthHeaderName", result.secondaryAuthHeaderName());
        root.put("recommendedTechniques", result.recommendedTechniques());
        root.put("classification", "FACT");
        root.put("verificationStatus", "STATIC_INFERRED");
        root.put("note", "Adapter well-known keys are HINT/detection only; mint only when "
                + "jwtSecretMaterialFound=true with evidenceRefs from this query. "
                + "When rememberMeCipherMaterialFound/COOKIE_MATERIAL is present, cite that FACT "
                + "(and scan HARDCODED_REMEMBER_ME_CIPHER_KEY hypotheses) instead of guessing "
                + "kPH+/dictionary cipher keys; METHOD_VIEW SLICE_EMPTY does not mean cipher-key "
                + "was missed. bladeSurface is a deprecated alias of multiHeaderAuthSurface.");
        List<Map<String, Object>> candidateMaps = new ArrayList<>();
        for (SecretCandidateHint candidate : result.secretCandidates()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("alias", candidate.alias());
            item.put("provenance", candidate.provenance());
            item.put("classification", candidate.classification());
            item.put("keyLen", candidate.keyLen());
            item.put("mintable", candidate.mintable());
            item.put("secretRedacted", true);
            candidateMaps.add(item);
        }
        root.put("secretCandidates", candidateMaps);
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
        List<Map<String, Object>> materialMaps = new ArrayList<>();
        for (IdentityMaterial material : result.identityMaterials()) {
            if (material.kind() != IdentityMaterialKind.CIPHER_KEY
                    && material.kind() != IdentityMaterialKind.SESSION_COOKIE) {
                continue;
            }
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("kind", material.kind().name());
            item.put("channel", material.channel().name());
            item.put("name", material.name());
            item.put("alias", material.alias());
            item.put("classification", material.valueProvenance());
            item.put("hasValue", material.hasValue());
            item.put("secretRedacted", true);
            item.put("sourcePath", material.sourcePath());
            materialMaps.add(item);
        }
        root.put("identityMaterials", materialMaps);
        return root;
    }
}

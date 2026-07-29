package com.aq.jvmsentinel.analysis.identity;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.analysis.detector.DetectorContext;
import com.aq.jvmsentinel.analysis.detector.HardcodedRememberMeCipherDetector;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * RememberMe cipher-key detection + Cookie-channel identity materials (acceptance only).
 * Fixture mirrors kvf {@code ShiroConfig#setCipherKey(Base64.decode("2AvVhdsgUs0FSA3SDFAdag=="))}.
 */
public final class IdentityMaterialAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path jar = fixtureShiroConfigJar();
        Path customJar = fixtureCustomCipherKeyJar();
        try {
            cipherKeyDetectorSurfacesNonFastjsonHypothesis(jar);
            harvestCookieMaterials(jar);
            synthesizeCookieChannelWithoutJwt(jar);
            probePlanEncodesCookieHeader(jar);
            cipherKeyIsNotJwtMintSecret(jar);
            customKeyDetectedViaSetCipherKeyNotDictionary(customJar);
            dictionaryAloneWithoutSetCipherKeyIsIgnored(customJar);
        } finally {
            Files.deleteIfExists(jar);
            Files.deleteIfExists(customJar);
        }
        System.out.println("IdentityMaterialAcceptanceTest: PASS");
    }

    private static Path fixtureShiroConfigJar() throws Exception {
        Path jar = Files.createTempFile("veyrion-shiro-cipher-", ".jar");
        // Latin-1 blob containing the same class-constant strings present in kvf ShiroConfig.class
        // Separate Utf8-like constants (NUL between) — mirrors real .class constant-pool layout.
        String latin = "Lorg/apache/shiro/web/mgt/CookieRememberMeManager;\0"
                + "setCipherKey\0"
                + "\"2AvVhdsgUs0FSA3SDFAdag==\"\0"
                + "Base64.decode";
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry("BOOT-INF/classes/com/example/ShiroConfig.class"));
            jos.write(latin.getBytes(StandardCharsets.ISO_8859_1));
            jos.closeEntry();
        }
        return jar;
    }

    /** Non-dictionary Base64 key — must still be harvested because setCipherKey is present. */
    private static Path fixtureCustomCipherKeyJar() throws Exception {
        Path jar = Files.createTempFile("veyrion-custom-cipher-", ".jar");
        String latin = "Lorg/apache/shiro/web/mgt/CookieRememberMeManager;\0"
                + "setCipherKey\0"
                + "\"AbCdEfGhIjKlMnOpQrStUv==\"\0"
                + "Base64.decode";
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry("BOOT-INF/classes/com/example/CustomShiroConfig.class"));
            jos.write(latin.getBytes(StandardCharsets.ISO_8859_1));
            jos.closeEntry();
            // Dictionary string alone in another class must NOT create a hit without setCipherKey.
            jos.putNextEntry(new JarEntry("BOOT-INF/classes/com/example/Unrelated.class"));
            jos.write(("noise " + RememberMeCipherHarvester.WELL_KNOWN_SHIRO_DEFAULT_CIPHER_KEY)
                    .getBytes(StandardCharsets.ISO_8859_1));
            jos.closeEntry();
        }
        return jar;
    }

    private static void cipherKeyDetectorSurfacesNonFastjsonHypothesis(Path jar) {
        HardcodedRememberMeCipherDetector detector = new HardcodedRememberMeCipherDetector();
        DetectorContext ctx = new DetectorContext(
                "scan-identity-material",
                ArtifactUniverse.empty(),
                new StaticFactSnapshot(StaticFactSnapshot.LEGACY_INCOMPLETE, List.of(), null),
                List.of(),
                List.of(),
                List.of(),
                Map.of(),
                List.of(),
                jar);
        List<SecurityHypothesis> hyps = detector.analyze(ctx);
        check(!hyps.isEmpty(), "cipher detector produces hypotheses");
        boolean hardcoded = hyps.stream().anyMatch(h ->
                HardcodedRememberMeCipherDetector.PROP_HARDCODED_CIPHER.equals(h.securityProperty()));
        check(hardcoded, "HARDCODED_REMEMBER_ME_CIPHER_KEY present");
        boolean notFastjson = hyps.stream().noneMatch(h ->
                (h.source() != null && h.source().toLowerCase().contains("fastjson"))
                        || (h.effect() != null && h.effect().toLowerCase().contains("fastjson"))
                        || (h.securityProperty() != null
                        && h.securityProperty().toLowerCase().contains("fastjson")));
        check(notFastjson, "cipher hypotheses are not Fastjson-labeled");
        boolean altKey = hyps.stream().anyMatch(h ->
                h.source() != null && h.source().contains("WELL_KNOWN_REMEMBER_ME_CIPHER_ALT"));
        check(altKey, "kvf alt cipher key alias labeled when matched");
    }

    private static void harvestCookieMaterials(Path jar) {
        List<IdentityMaterial> materials = new AuthCodeQueryService().harvestMaterials(jar);
        check(materials.stream().anyMatch(m -> m.kind() == IdentityMaterialKind.CIPHER_KEY
                        && m.channel() == AuthChannel.COOKIE
                        && m.hasValue()
                        && RememberMeCipherHarvester.WELL_KNOWN_SHIRO_ALT_CIPHER_KEY.equals(m.value().orElse(""))),
                "CIPHER_KEY Cookie material harvested with kvf key");
        check(materials.stream().anyMatch(m -> m.channel() == AuthChannel.COOKIE
                        && "rememberMe".equals(m.name())),
                "rememberMe cookie name when manager+setCipherKey co-located");
    }

    private static void customKeyDetectedViaSetCipherKeyNotDictionary(Path jar) {
        List<RememberMeCipherHarvester.Hit> hits = RememberMeCipherHarvester.scan(jar);
        check(hits.stream().anyMatch(h -> h.setCipherKeyPresent()
                        && "AbCdEfGhIjKlMnOpQrStUv==".equals(h.keyValue())
                        && "CUSTOM_CIPHER_KEY".equals(h.alias())),
                "custom Base64 next to setCipherKey harvested without dictionary");
        List<SecurityHypothesis> hyps = new HardcodedRememberMeCipherDetector().analyze(
                new DetectorContext(
                        "scan-custom-cipher",
                        ArtifactUniverse.empty(),
                        new StaticFactSnapshot(StaticFactSnapshot.LEGACY_INCOMPLETE, List.of(), null),
                        List.of(), List.of(), List.of(), Map.of(), List.of(), jar));
        check(hyps.stream().anyMatch(h ->
                        HardcodedRememberMeCipherDetector.PROP_HARDCODED_CIPHER.equals(h.securityProperty())
                                && h.source().contains("CUSTOM_CIPHER_KEY")),
                "detector surfaces CUSTOM_CIPHER_KEY");
    }

    private static void dictionaryAloneWithoutSetCipherKeyIsIgnored(Path jar) {
        List<RememberMeCipherHarvester.Hit> hits = RememberMeCipherHarvester.scan(jar);
        check(hits.stream().noneMatch(h ->
                        RememberMeCipherHarvester.WELL_KNOWN_SHIRO_DEFAULT_CIPHER_KEY.equals(h.keyValue())),
                "dictionary key without setCipherKey must not produce a hit");
    }

    private static void synthesizeCookieChannelWithoutJwt(Path jar) {
        SyntheticIdentityService.MaterialBundle bundle =
                new SyntheticIdentityService().harvest(jar);
        check(bundle.jwtSecret().isEmpty(), "rememberMe cipher must not become JWT mint secret");
        SyntheticIdentityService.SyntheticIdentity admin =
                new SyntheticIdentityService().synthesize(IdentityTrack.ADMIN, bundle);
        check(admin.available(), "ADMIN available via Cookie channel without JWT");
        check(admin.authorizationHeader().isBlank(), "no fake Bearer when only Cookie material");
        check(admin.cookieHeader().startsWith("rememberMe="), "Cookie header present for ADMIN");
        check(admin.cookieHeader().contains(SyntheticIdentityService.COOKIE_MATERIAL_MARKER),
                "honest marker cookie (payload not minted)");
    }

    private static void probePlanEncodesCookieHeader(Path jar) {
        SyntheticIdentityService.SyntheticIdentity admin =
                new SyntheticIdentityService().synthesize(
                        IdentityTrack.ADMIN, new SyntheticIdentityService().harvest(jar));
        ExternalArtifactTaskExecutor.ProbeTarget target = new ExternalArtifactTaskExecutor.ProbeTarget(
                "GET", "/admin/users", "", "ADMIN", "", "", "", admin.cookieHeader());
        String encoded = new String(ExternalArtifactTaskExecutor.encodeProbePlan(List.of(target)),
                StandardCharsets.UTF_8);
        check(encoded.contains(admin.cookieHeader()), "probe plan TSV carries Cookie column");
        String[] parts = encoded.trim().split("\t", -1);
        check(parts.length == 8, "probe plan line has cookie as 8th column");
        check(parts[7].equals(admin.cookieHeader()), "cookie column matches");
    }

    private static void cipherKeyIsNotJwtMintSecret(Path jar) {
        AuthCodeQueryService.AuthCodeQueryResult result =
                new AuthCodeQueryService().query(jar, "", 20);
        check(result.mintSecret().isEmpty(), "cipher key must not populate mintSecret");
        check(result.facts().stream().anyMatch(f -> "COOKIE_MATERIAL".equals(f.category())),
                "COOKIE_MATERIAL fact emitted");
        check(result.facts().stream().noneMatch(f ->
                        "JWT_MATERIAL".equals(f.category())
                                && f.summary().toLowerCase().contains("mintable")
                                && f.attributes().getOrDefault("matched", "")
                                .contains("REMEMBER_ME")),
                "cipher alias not classified as mintable JWT");
    }

    private static void check(boolean condition, String message) {
        AcceptanceAssertions.record();
        if (!condition) throw new AssertionError(message);
    }
}

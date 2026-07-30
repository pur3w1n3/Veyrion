package com.aq.jvmsentinel.analysis.identity;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.analysis.detector.DetectorContext;
import com.aq.jvmsentinel.analysis.detector.HardcodedJwtSignKeyDetector;
import com.aq.jvmsentinel.analysis.detector.HardcodedRememberMeCipherDetector;
import com.aq.jvmsentinel.analysis.framework.SpringBladeAdapter;
import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.control.ApiDtos;
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
 * 说明：RememberMe cipher-key detection + Cookie-channel identity 材料（仅 acceptance）。
 * Fixture 镜像 kvf {@code ShiroConfig#setCipherKey(Base64.decode("2AvVhdsgUs0FSA3SDFAdag=="))}。
 */
public final class IdentityMaterialAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path jar = fixtureShiroConfigJar();
        Path customJar = fixtureCustomCipherKeyJar();
        Path bladeJwtJar = fixtureBladeJwtNestedJar();
        try {
            cipherKeyDetectorSurfacesNonFastjsonHypothesis(jar);
            harvestCookieMaterials(jar);
            synthesizeCookieChannelWithoutJwt(jar);
            probePlanEncodesCookieHeader(jar);
            cipherKeyIsNotJwtMintSecret(jar);
            rememberMeTechniqueHintWhenCipherHarvested(jar);
            cipherHypProjectsToStaticInferredFinding(jar);
            customKeyDetectedViaSetCipherKeyNotDictionary(customJar);
            dictionaryAloneWithoutSetCipherKeyIsIgnored(customJar);
            nestedBladeJwtDefaultKeyHarvestedAndProjected(bladeJwtJar);
        } finally {
            Files.deleteIfExists(jar);
            Files.deleteIfExists(customJar);
            Files.deleteIfExists(bladeJwtJar);
        }
        System.out.println("IdentityMaterialAcceptanceTest: PASS");
    }

    private static Path fixtureShiroConfigJar() throws Exception {
        Path jar = Files.createTempFile("veyrion-shiro-cipher-", ".jar");
        // 含 kvf ShiroConfig.class 中相同 class-constant 字符串的 Latin-1 blob
        // 分离 Utf8-like constant（NUL 间隔）— 镜像真实 .class constant-pool layout。
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
            // 另一 class 中仅 dictionary 字符串无 setCipherKey 不得产生 hit。
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
        String cookieValue = admin.cookieHeader().substring("rememberMe=".length());
        check(!cookieValue.isBlank()
                        && !cookieValue.equals(SyntheticIdentityService.COOKIE_MATERIAL_MARKER),
                "rememberMe AES payload minted for sandbox observation");
        check(admin.precondition().contains("rememberMe AES payload minted")
                        || admin.precondition().contains("minted"),
                "precondition notes rememberMe mint");
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
        Map<String, Object> toolMap = AuthCodeQueryService.toToolMap(result);
        check(Boolean.TRUE.equals(toolMap.get("rememberMeCipherMaterialFound")),
                "tool summary exposes rememberMeCipherMaterialFound");
        check(Boolean.TRUE.equals(toolMap.get("cookieMaterialFound")),
                "tool summary exposes cookieMaterialFound");
    }

    private static void rememberMeTechniqueHintWhenCipherHarvested(Path jar) {
        AuthCodeQueryService.AuthCodeQueryResult result =
                new AuthCodeQueryService().query(jar, "", 20);
        check(result.recommendedTechniques().contains("REMEMBER_ME_COOKIE"),
                "cipher material adds REMEMBER_ME_COOKIE technique hint");
        check(result.recommendedTechniques().contains("CUSTOM_POC"),
                "cipher material keeps CUSTOM_POC for Cookie-channel PoC");
    }

    /**
     * 验收：rememberMe cipher hyp 成为带 STATIC_INFERRED + hypothesisId 的 finding
     * (UI/report must not look sink-only when hyp-rmc exists).
     */
    private static void cipherHypProjectsToStaticInferredFinding(Path jar) {
        HardcodedRememberMeCipherDetector detector = new HardcodedRememberMeCipherDetector();
        List<SecurityHypothesis> hyps = detector.analyze(new DetectorContext(
                "scan-ee80407e1f95449d",
                ArtifactUniverse.empty(),
                new StaticFactSnapshot(StaticFactSnapshot.LEGACY_INCOMPLETE, List.of(), null),
                List.of(), List.of(), List.of(), Map.of(), List.of(), jar));
        check(hyps.stream().anyMatch(h ->
                        HardcodedRememberMeCipherDetector.PROP_HARDCODED_CIPHER.equals(h.securityProperty())),
                "detector hyp present before finding projection");
        List<ApiDtos.FindingDto> findings = SecurityHypothesisProjector.mergeFindingsWithDetectorHypotheses(
                "project-rmc", "digest-rmc", "scan-ee80407e1f95449d",
                List.of(), hyps, List.of());
        ApiDtos.FindingDto cipherFinding = findings.stream()
                .filter(f -> HardcodedRememberMeCipherDetector.PROP_HARDCODED_CIPHER
                        .equals(f.securityProperty()))
                .findFirst()
                .orElse(null);
        check(cipherFinding != null, "HARDCODED_REMEMBER_ME_CIPHER_KEY projects to finding");
        check(ApiDtos.STATIC_INFERRED.equals(cipherFinding.verificationStatus()),
                "finding verificationStatus is STATIC_INFERRED");
        check(cipherFinding.hypothesisId() != null && !cipherFinding.hypothesisId().isBlank(),
                "finding binds hypothesisId");
        check(cipherFinding.hypothesisId().startsWith("hyp-rmc-"),
                "finding hypothesisId links hyp-rmc");
        check(!"DYNAMIC_CONFIRMED".equals(cipherFinding.verificationStatus())
                        && !"VERIFIED".equals(cipherFinding.verificationStatus()),
                "projection must not elevate DYNAMIC_CONFIRMED/VERIFIED");
        check(findings.stream().anyMatch(f ->
                        HardcodedRememberMeCipherDetector.PROP_UNSAFE_DESER_SURFACE
                                .equals(f.securityProperty())
                                && f.hypothesisId() != null
                                && f.hypothesisId().startsWith("hyp-rmc-")
                                && ApiDtos.STATIC_INFERRED.equals(f.verificationStatus())),
                "companion UNSAFE_DESERIALIZATION_SURFACE from rememberMe also projects STATIC_INFERRED");
        // 通用 deser-config hyp（非 rememberMe detector）不得经此 path 投影。
        SecurityHypothesis genericDeser = new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION,
                "hyp-deser-scan-x-1",
                "scan-ee80407e1f95449d",
                HardcodedRememberMeCipherDetector.PROP_UNSAFE_DESER_SURFACE,
                com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily.TYPESTATE,
                com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle.CANDIDATE,
                "deserialization-config/0.1.0",
                List.of(), List.of(), List.of(),
                "com.example.Load#readObject",
                "deserialize-api");
        check(!SecurityHypothesisProjector.isHighSignalDetectorHypothesis(genericDeser),
                "generic UNSAFE_DESERIALIZATION_SURFACE is not high-signal for this projector");
    }

    /**
     * 说明：Blade JwtProperties default sign-key 在 nested blade-starter-jwt；仅 outer scan 会遗漏
     * (scan-c6b91763704c4aed: empty bladeAuthHeader / AUTH_CHALLENGE on FORCED).
     */
    private static Path fixtureBladeJwtNestedJar() throws Exception {
        Path jar = Files.createTempFile("veyrion-blade-jwt-", ".jar");
        Path nested = Files.createTempFile("blade-starter-jwt-", ".jar");
        String latin = "Lorg/springblade/core/jwt/props/JwtProperties;\0"
                + SpringBladeAdapter.WELL_KNOWN_COMMERCIAL_SIGN_KEY + "\0"
                + "blade.token";
        try (JarOutputStream nestedJos = new JarOutputStream(Files.newOutputStream(nested))) {
            nestedJos.putNextEntry(new JarEntry(
                    "org/springblade/core/jwt/props/JwtProperties.class"));
            nestedJos.write(latin.getBytes(StandardCharsets.ISO_8859_1));
            nestedJos.closeEntry();
        }
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry("BOOT-INF/classes/application.yml"));
            jos.write("blade:\n  token:\n    state: false\n".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("BOOT-INF/lib/blade-starter-jwt-3.0.0.RELEASE.jar"));
            jos.write(Files.readAllBytes(nested));
            jos.closeEntry();
        } finally {
            Files.deleteIfExists(nested);
        }
        return jar;
    }

    private static void nestedBladeJwtDefaultKeyHarvestedAndProjected(Path jar) {
        AuthCodeQueryService.AuthCodeQueryResult result =
                new AuthCodeQueryService().query(jar, "", 20);
        check(result.mintSecret().isPresent(), "nested blade-starter-jwt default key is mintable");
        check(result.jwtSecretMaterialFound(), "jwtSecretMaterialFound after nested harvest");
        check(result.preferredSignKeyProvenance().contains("CLASS_CONSTANT"),
                "provenance cites nested class constant");

        HardcodedJwtSignKeyDetector detector = new HardcodedJwtSignKeyDetector();
        List<SecurityHypothesis> hyps = detector.analyze(new DetectorContext(
                "scan-blade-jwt",
                ArtifactUniverse.empty(),
                new StaticFactSnapshot(StaticFactSnapshot.LEGACY_INCOMPLETE, List.of(), null),
                List.of(), List.of(), List.of(), Map.of(), List.of(), jar));
        check(hyps.stream().anyMatch(h ->
                        HardcodedJwtSignKeyDetector.PROP_HARDCODED_JWT_SIGN_KEY
                                .equals(h.securityProperty())),
                "HARDCODED_JWT_SIGN_KEY hyp from nested JwtProperties");
        List<ApiDtos.FindingDto> findings = SecurityHypothesisProjector.mergeFindingsWithDetectorHypotheses(
                "project-jwt", "digest-jwt", "scan-blade-jwt", List.of(), hyps, List.of());
        ApiDtos.FindingDto jwtFinding = findings.stream()
                .filter(f -> HardcodedJwtSignKeyDetector.PROP_HARDCODED_JWT_SIGN_KEY
                        .equals(f.securityProperty()))
                .findFirst()
                .orElse(null);
        check(jwtFinding != null, "JWT default key projects to finding");
        check(ApiDtos.STATIC_INFERRED.equals(jwtFinding.verificationStatus()),
                "JWT finding remains STATIC_INFERRED");
        check(jwtFinding.title().contains("JWT"), "JWT finding title mentions JWT");
        check(!"VERIFIED".equals(jwtFinding.verificationStatus())
                        && !"DYNAMIC_CONFIRMED".equals(jwtFinding.verificationStatus()),
                "JWT projection must not elevate VERIFIED/DYNAMIC_CONFIRMED");
    }

    private static void check(boolean condition, String message) {
        AcceptanceAssertions.record();
        if (!condition) throw new AssertionError(message);
    }
}

package com.aq.jvmsentinel.analysis.identity;

import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * Synthetic identity harvest/mint rules: no silent commercial Blade key fallback
 * (acceptance only; not VERIFIED).
 */
public final class SyntheticIdentityAcceptanceTest {
    public static void main(String[] args) throws Exception {
        noArtifactNoHs256Mint();
        secretLessTechniquesAlwaysAvailable();
        harvestCustomConfigSecret();
        System.out.println("SyntheticIdentityAcceptanceTest: PASS");
    }

    private static void noArtifactNoHs256Mint() {
        SyntheticIdentityService.MaterialBundle materials =
                new SyntheticIdentityService().harvest(null);
        check(materials.jwtSecret().isEmpty(), "null artifact yields no jwtSecret");
        SyntheticIdentityService.SyntheticIdentity admin =
                new SyntheticIdentityService().synthesize(IdentityTrack.ADMIN, materials);
        check(!admin.available(), "ADMIN unavailable without harvested secret");
    }

    private static void secretLessTechniquesAlwaysAvailable() {
        SyntheticIdentityService.MaterialBundle empty =
                new SyntheticIdentityService.MaterialBundle(
                        java.util.Optional.empty(), "NONE", java.util.List.of("no secret"),
                        false, false);
        SyntheticIdentityService identity = new SyntheticIdentityService();
        check(identity.synthesizeTechnique(AuthBypassTechnique.MISSING_AUTH, empty).available(),
                "MISSING_AUTH available");
        check(identity.synthesizeTechnique(AuthBypassTechnique.EMPTY_BEARER, empty).available(),
                "EMPTY_BEARER available");
        check(identity.synthesizeTechnique(AuthBypassTechnique.ALG_NONE, empty).available(),
                "ALG_NONE available");
        check(!identity.synthesizeTechnique(AuthBypassTechnique.DEFAULT_SECRET_HS256, empty).available(),
                "DEFAULT_SECRET_HS256 unavailable without secret");
    }

    private static void harvestCustomConfigSecret() throws Exception {
        Path jar = Files.createTempFile("synth-custom-key-", ".jar");
        try {
            try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
                jos.putNextEntry(new JarEntry("BOOT-INF/classes/application.properties"));
                jos.write("blade.token.sign-key=custom-fixture-secret-value-32b\n"
                        .getBytes(StandardCharsets.UTF_8));
                jos.closeEntry();
            }
            SyntheticIdentityService.MaterialBundle materials =
                    new SyntheticIdentityService().harvest(jar);
            check(materials.jwtSecret().isPresent(), "custom config secret harvested");
            check("custom-fixture-secret-value-32b".equals(materials.jwtSecret().get()),
                    "harvested custom secret value");
            check("FACT".equals(materials.secretProvenance())
                            || "RULE_GENERATED".equals(materials.secretProvenance()),
                    "custom config provenance is FACT or RULE_GENERATED");
            SyntheticIdentityService.SyntheticIdentity minted =
                    new SyntheticIdentityService().synthesizeTechnique(
                            AuthBypassTechnique.DEFAULT_SECRET_HS256, materials);
            check(minted.available() && minted.authorizationHeader().contains("."),
                    "mints HS256 from custom harvested secret");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.analysis.framework.SpringBladeAdapter;
import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * AUTH code_query harvest + 仅当制品中发现 key 才种子 DEFAULT_SECRET_HS256
 * （仅验收；非 VERIFIED / 生产）。
 */
public final class AuthCodeQueryAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        codeQueryHarvestsAdapterDictionaryKeyFromArtifact();
        codeQueryMultiHeaderSurfaceWithoutKeyDoesNotMint();
        codeQueryHarvestsGenericJwtSecretProperty();
        seedPrefersDefaultSecretHs256WithSecondaryAuthWhenHarvested();
        seedWithoutHarvestedKeySkipsDefaultSecret();
        harvestMarksMultiHeaderSurface();
        harvestWithoutKeyLeavesSecretEmpty();
        authRoleAllowlistsCodeQuery();
        System.out.println("AuthCodeQueryAcceptanceTest: PASS");
    }

    private static void codeQueryHarvestsAdapterDictionaryKeyFromArtifact() throws Exception {
        Path jar = Files.createTempFile("multi-header-auth-code-", ".jar");
        try {
            writeMultiHeaderJarWithKnownKey(jar);
            AuthCodeQueryService.AuthCodeQueryResult result =
                    new AuthCodeQueryService().query(jar, "jwt", 20);
            check(result.multiHeaderAuthSurface(), "multi-header auth surface detected");
            check(result.bladeSurface(), "deprecated bladeSurface alias still true");
            check(result.jwtSecretMaterialFound(), "sign-key material harvested");
            check("Blade-Auth".equals(result.preferredHeaderChannel())
                            || "Blade-Auth".equals(result.secondaryAuthHeaderName()),
                    "adapter secondary header preferred when multi-header surface");
            check(result.recommendedTechniques().contains("DEFAULT_SECRET_HS256"),
                    "recommend DEFAULT_SECRET_HS256 when mintable");
            check(!result.secretCandidates().isEmpty(), "secretCandidates present");
            check(result.secretCandidates().get(0).mintable(), "candidate mintable");
            String toolJson = JSON.writeValueAsString(AuthCodeQueryService.toToolMap(result));
            check(!toolJson.contains(SpringBladeAdapter.WELL_KNOWN_COMMERCIAL_SIGN_KEY),
                    "tool map must not leak raw sign-key");
            check(toolJson.contains("secretCandidates"), "tool map exposes secretCandidates");
            check(toolJson.contains("multiHeaderAuthSurface"), "tool map uses generic surface field");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void codeQueryMultiHeaderSurfaceWithoutKeyDoesNotMint() throws Exception {
        Path jar = Files.createTempFile("multi-header-auth-nokey-", ".jar");
        try {
            writeMultiHeaderJarWithoutKey(jar);
            AuthCodeQueryService.AuthCodeQueryResult result =
                    new AuthCodeQueryService().query(jar, "", 20);
            check(result.multiHeaderAuthSurface(), "multi-header surface without key still detected");
            check(!result.jwtSecretMaterialFound(), "no mintable secret without key bytes");
            check(result.mintSecret().isEmpty(), "mintSecret empty");
            check(!result.recommendedTechniques().contains("DEFAULT_SECRET_HS256"),
                    "do not recommend DEFAULT_SECRET_HS256 without harvest");
            check(result.recommendedTechniques().contains("MISSING_AUTH"),
                    "recommend MISSING_AUTH without secret");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void codeQueryHarvestsGenericJwtSecretProperty() throws Exception {
        Path jar = Files.createTempFile("generic-jwt-secret-", ".jar");
        try {
            try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
                jos.putNextEntry(new JarEntry("BOOT-INF/classes/application.properties"));
                jos.write("jwt.secret=generic-fixture-secret-value-32bytes\n"
                        .getBytes(StandardCharsets.UTF_8));
                jos.closeEntry();
            }
            AuthCodeQueryService.AuthCodeQueryResult result =
                    new AuthCodeQueryService().query(jar, "jwt", 10);
            check(result.jwtSecretMaterialFound(), "generic jwt.secret harvested");
            check(result.mintSecret().isPresent()
                            && "generic-fixture-secret-value-32bytes".equals(result.mintSecret().get()),
                    "mint secret is custom config value");
            check("Authorization".equals(result.preferredHeaderChannel()),
                    "generic JAR prefers Authorization without multi-header surface");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void seedPrefersDefaultSecretHs256WithSecondaryAuthWhenHarvested() throws Exception {
        Path jar = Files.createTempFile("multi-header-auth-seed-", ".jar");
        try {
            writeMultiHeaderJarWithKnownKey(jar);
            ApiDtos.ScanDto scan = multiHeaderScan();
            List<AuthBypassCandidate> drafts =
                    AuthBypassFeasibility.seedRuleGeneratedDrafts(scan, jar);
            check(!drafts.isEmpty(), "seeded drafts non-empty");
            boolean hasDefault = drafts.stream()
                    .anyMatch(c -> AuthBypassTechnique.DEFAULT_SECRET_HS256.name()
                            .equals(c.techniqueId()));
            check(hasDefault, "DEFAULT_SECRET_HS256 seeded when harvested");
            AuthBypassCandidate hs = drafts.stream()
                    .filter(c -> AuthBypassTechnique.DEFAULT_SECRET_HS256.name().equals(c.techniqueId()))
                    .findFirst().orElseThrow();
            check(hs.hasAuthMaterial(), "HS256 draft has Authorization");
            check(hs.secondaryAuthorizationHeader() != null
                            && hs.secondaryAuthorizationHeader().toLowerCase().startsWith("bearer "),
                    "HS256 draft dual-writes secondary auth with bearer scheme");
            check(hs.entryRef().equals("entry:entry-ann-18")
                            || hs.entryRef().equals("entry:entry-ann-255"),
                    "seed prefers high-value auth entries");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void seedWithoutHarvestedKeySkipsDefaultSecret() throws Exception {
        Path jar = Files.createTempFile("multi-header-auth-seed-nokey-", ".jar");
        try {
            writeMultiHeaderJarWithoutKey(jar);
            List<AuthBypassCandidate> drafts =
                    AuthBypassFeasibility.seedRuleGeneratedDrafts(multiHeaderScan(), jar);
            check(!drafts.isEmpty(), "seed still produces secret-less techniques");
            boolean hasDefault = drafts.stream()
                    .anyMatch(c -> AuthBypassTechnique.DEFAULT_SECRET_HS256.name()
                            .equals(c.techniqueId()));
            check(!hasDefault, "DEFAULT_SECRET_HS256 not seeded without harvest");
            boolean hasMissing = drafts.stream()
                    .anyMatch(c -> AuthBypassTechnique.MISSING_AUTH.name().equals(c.techniqueId()));
            check(hasMissing, "MISSING_AUTH seeded without harvest");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void harvestMarksMultiHeaderSurface() throws Exception {
        Path jar = Files.createTempFile("multi-header-auth-mat-", ".jar");
        try {
            writeMultiHeaderJarWithKnownKey(jar);
            SyntheticIdentityService.MaterialBundle materials =
                    new SyntheticIdentityService().harvest(jar);
            check(materials.preferSecondaryAuthHeader() || materials.multiHeaderAuthSurface(),
                    "harvest marks multi-header auth surface");
            check(materials.jwtSecret().isPresent()
                            && SpringBladeAdapter.WELL_KNOWN_COMMERCIAL_SIGN_KEY
                            .equals(materials.jwtSecret().get()),
                    "harvest uses key found in artifact (adapter dictionary match)");
            check(!"MOCK".equals(materials.secretProvenance()),
                    "harvest provenance is not silent MOCK default");
            String token = new SyntheticIdentityService()
                    .synthesizeTechnique(AuthBypassTechnique.DEFAULT_SECRET_HS256, materials)
                    .authorizationHeader();
            check(token != null && token.contains("."), "DEFAULT_SECRET_HS256 mints JWT after harvest");
            check(SyntheticIdentityService.secondaryAuthHeaderValue(token).startsWith("bearer "),
                    "secondaryAuthHeaderValue prefixes bearer");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void harvestWithoutKeyLeavesSecretEmpty() throws Exception {
        Path jar = Files.createTempFile("multi-header-auth-empty-", ".jar");
        try {
            writeMultiHeaderJarWithoutKey(jar);
            SyntheticIdentityService.MaterialBundle materials =
                    new SyntheticIdentityService().harvest(jar);
            check(materials.multiHeaderAuthSurface(), "multi-header surface without key");
            check(materials.jwtSecret().isEmpty(), "no silent commercial-key fallback");
            SyntheticIdentityService.SyntheticIdentity hs =
                    new SyntheticIdentityService().synthesizeTechnique(
                            AuthBypassTechnique.DEFAULT_SECRET_HS256, materials);
            check(!hs.available(), "DEFAULT_SECRET_HS256 unavailable without harvest");
            check(hs.precondition().contains("IDENTITY_UNAVAILABLE"),
                    "IDENTITY_UNAVAILABLE when no signing material");
            SyntheticIdentityService.SyntheticIdentity missing =
                    new SyntheticIdentityService().synthesizeTechnique(
                            AuthBypassTechnique.MISSING_AUTH, materials);
            check(missing.available(), "MISSING_AUTH still available without secret");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void authRoleAllowlistsCodeQuery() throws Exception {
        AiToolRegistry registry = new AiToolRegistry(new ToolDataSource() {
            @Override
            public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                                String query, int limit) {
                return List.of();
            }

            @Override
            public List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String query, int limit) {
                ObjectNode node = JSON.createObjectNode();
                node.put("multiHeaderAuthSurface", true);
                node.put("bladeSurface", true); // deprecated alias
                node.put("jwtSecretMaterialFound", false);
                node.put("classification", "FACT");
                return List.of(new FactRecord(scope, "code_query:auth-summary", node));
            }

            @Override
            public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
                return Optional.empty();
            }
        });
        ToolExecutionContext.Scope scope = new ToolExecutionContext.Scope("ws", "proj");
        ToolExecutionContext ctx = ToolExecutionContext.bind(
                scope, "p1", "j1", AgentRole.AUTH_ANALYSIS,
                new ToolExecutionContext.Budget(4, 4096, 8, 64 * 1024, Instant.MAX));
        check(ctx.allowedTools().contains("code_query"), "AUTH_ANALYSIS allowlists code_query");
        ObjectNode args = JSON.createObjectNode();
        args.put("query", "jwt");
        args.put("limit", 5);
        ToolResult result = registry.execute(
                new ToolCall(CanonicalToolContracts.SCHEMA_VERSION, "c1", "code_query", args), ctx);
        check(result.status() == ToolStatus.SUCCESS,
                "code_query executes for AUTH status=" + result.status()
                        + " err=" + result.errorCode());
        check(!result.outputs().isEmpty(), "code_query returns FACT outputs");
    }

    private static ApiDtos.ScanDto multiHeaderScan() {
        String now = "2026-07-26T00:00:00Z";
        String digest = "a".repeat(64);
        ApiDtos.EntryDto deploy = new ApiDtos.EntryDto(
                1, "p", digest, "scan-x",
                "entry-ann-18", "HTTP", "POST", "/blade-flow/manager/deploy-upload",
                "org.springblade.flow.engine.controller.FlowManagerController",
                "FlowManagerController", List.of(),
                List.of("PreAuth(hasRole('administrator'))"),
                "STATIC_INFERRED", 0.95, 0,
                List.of("evidence-ann-18", "evidence-perm-18"));
        ApiDtos.EntryDto token = new ApiDtos.EntryDto(
                1, "p", digest, "scan-x",
                "entry-ann-255", "HTTP", "POST", "/blade-auth/oauth/token",
                "org.springblade.modules.auth.endpoint.BladeTokenEndPoint",
                "BladeTokenEndPoint", List.of(), List.of(),
                "STATIC_INFERRED", 0.95, 0, List.of("evidence-ann-255"));
        ApiDtos.SinkDto jwt = new ApiDtos.SinkDto(
                1, "p", digest, "scan-x",
                "sink-jwt-1", "JWT", "JwtUtil", "org.example.security.JwtUtil",
                "STATIC_INFERRED", 0.8, List.of());
        return new ApiDtos.ScanDto(
                1, "p", digest, "scan-x",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of(), List.of(deploy, token), List.of(), List.of(jwt),
                List.of(), List.of());
    }

    private static void writeMultiHeaderJarWithKnownKey(Path jar) throws Exception {
        ByteArrayOutputStream classBytes = new ByteArrayOutputStream();
        classBytes.write(new byte[] {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE});
        classBytes.write(SpringBladeAdapter.WELL_KNOWN_COMMERCIAL_SIGN_KEY
                .getBytes(StandardCharsets.UTF_8));
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry(
                    "BOOT-INF/classes/org/springblade/core/jwt/props/JwtProperties.class"));
            jos.write(classBytes.toByteArray());
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("BOOT-INF/classes/application.yml"));
            jos.write(("secure:\n  skip-url:\n    - /api/auth/oauth/token\n")
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
    }

    private static void writeMultiHeaderJarWithoutKey(Path jar) throws Exception {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry(
                    "BOOT-INF/classes/org/springblade/core/secure/utils/SecureUtil.class"));
            jos.write(new byte[] {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0x00, 0x01});
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("BOOT-INF/classes/application.yml"));
            jos.write(("secure:\n  skip-url:\n    - /api/auth/oauth/token\n"
                    + "spring:\n  application:\n    name: demo\n")
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

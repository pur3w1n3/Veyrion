package com.aq.jvmsentinel.ai;

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
 * AUTH code_query + Blade DEFAULT_SECRET_HS256 dual-header seed closed loop
 * (acceptance only; not VERIFIED / production).
 */
public final class AuthCodeQueryAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        codeQueryFindsBladeDefaultKey();
        seedPrefersDefaultSecretHs256WithBladeAuth();
        harvestMarksBladeSurface();
        authRoleAllowlistsCodeQuery();
        System.out.println("AuthCodeQueryAcceptanceTest: PASS");
    }

    private static void codeQueryFindsBladeDefaultKey() throws Exception {
        Path jar = Files.createTempFile("blade-auth-code-", ".jar");
        try {
            writeBladeJar(jar);
            AuthCodeQueryService.AuthCodeQueryResult result =
                    new AuthCodeQueryService().query(jar, "jwt", 20);
            check(result.bladeSurface(), "blade surface detected");
            check(result.jwtDefaultKeyMatched(), "default sign-key matched");
            check("Blade-Auth".equals(result.preferredHeaderChannel()), "prefer Blade-Auth");
            check(result.recommendedTechniques().contains("DEFAULT_SECRET_HS256"),
                    "recommend DEFAULT_SECRET_HS256");
            check(!JSON.writeValueAsString(AuthCodeQueryService.toToolMap(result))
                            .contains(AuthCodeQueryService.BLADE_DEFAULT_SIGN_KEY),
                    "tool map must not leak raw sign-key");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void seedPrefersDefaultSecretHs256WithBladeAuth() throws Exception {
        Path jar = Files.createTempFile("blade-auth-seed-", ".jar");
        try {
            writeBladeJar(jar);
            ApiDtos.ScanDto scan = bladeScan();
            List<AuthBypassCandidate> drafts =
                    AuthBypassFeasibility.seedRuleGeneratedDrafts(scan, jar);
            check(!drafts.isEmpty(), "seeded drafts non-empty");
            boolean hasDefault = drafts.stream()
                    .anyMatch(c -> AuthBypassTechnique.DEFAULT_SECRET_HS256.name()
                            .equals(c.techniqueId()));
            check(hasDefault, "DEFAULT_SECRET_HS256 seeded for Blade");
            boolean hasAlgNone = drafts.stream()
                    .anyMatch(c -> AuthBypassTechnique.ALG_NONE.name().equals(c.techniqueId()));
            check(!hasAlgNone, "ALG_NONE not preferred on Blade surface");
            AuthBypassCandidate hs = drafts.stream()
                    .filter(c -> AuthBypassTechnique.DEFAULT_SECRET_HS256.name().equals(c.techniqueId()))
                    .findFirst().orElseThrow();
            check(hs.hasAuthMaterial(), "HS256 draft has Authorization");
            check(hs.bladeAuthHeader() != null && hs.bladeAuthHeader().toLowerCase().startsWith("bearer "),
                    "HS256 draft dual-writes Blade-Auth with bearer scheme");
            check(hs.entryRef().equals("entry:entry-ann-18")
                            || hs.entryRef().equals("entry:entry-ann-255"),
                    "seed prefers Blade high-value entries");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static void harvestMarksBladeSurface() throws Exception {
        Path jar = Files.createTempFile("blade-auth-mat-", ".jar");
        try {
            writeBladeJar(jar);
            SyntheticIdentityService.MaterialBundle materials =
                    new SyntheticIdentityService().harvest(jar);
            check(materials.preferBladeAuthHeader() || materials.bladeSurface(),
                    "harvest marks Blade surface");
            check(materials.jwtSecret().isPresent()
                            && AuthCodeQueryService.BLADE_DEFAULT_SIGN_KEY.equals(materials.jwtSecret().get()),
                    "harvest prefers Blade default sign-key");
            String token = new SyntheticIdentityService()
                    .synthesizeTechnique(AuthBypassTechnique.DEFAULT_SECRET_HS256, materials)
                    .authorizationHeader();
            check(token != null && token.contains("."), "DEFAULT_SECRET_HS256 mints JWT");
            check(SyntheticIdentityService.bladeAuthHeaderValue(token).startsWith("bearer "),
                    "bladeAuthHeaderValue prefixes bearer");
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
                node.put("bladeSurface", true);
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

    private static ApiDtos.ScanDto bladeScan() {
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
                "sink-jwt-1", "JWT", "JwtUtil", "org.springblade.core.jwt.JwtUtil",
                "STATIC_INFERRED", 0.8, List.of());
        return new ApiDtos.ScanDto(
                1, "p", digest, "scan-x",
                "COMPLETED", "STATIC_INFERRED", "MOCK", now, now,
                List.of(), List.of(deploy, token), List.of(), List.of(jwt),
                List.of(), List.of());
    }

    private static void writeBladeJar(Path jar) throws Exception {
        ByteArrayOutputStream classBytes = new ByteArrayOutputStream();
        // Minimal fake "class" that embeds the known Blade sign-key string constant.
        classBytes.write(new byte[] {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE});
        classBytes.write(AuthCodeQueryService.BLADE_DEFAULT_SIGN_KEY.getBytes(StandardCharsets.UTF_8));
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry(
                    "BOOT-INF/classes/org/springblade/core/jwt/props/JwtProperties.class"));
            jos.write(classBytes.toByteArray());
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("BOOT-INF/classes/application.yml"));
            jos.write(("blade:\n  secure:\n    skip-url:\n      - /blade-auth/oauth/token\n")
                    .getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

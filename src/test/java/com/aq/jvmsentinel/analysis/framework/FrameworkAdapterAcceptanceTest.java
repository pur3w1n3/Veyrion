package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.BranchConstraintHarvester;
import com.aq.jvmsentinel.analysis.CoverageGapProjector;
import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.analysis.pack.BladeJwtCredentialPack;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.model.ParameterConstraint;
import com.aq.jvmsentinel.model.ParameterSpec;
import com.aq.jvmsentinel.model.StaticContrastRow;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** MVP-2 acceptance: FrameworkAdapter injection, constraint harvest, coverage gaps. */
public final class FrameworkAdapterAcceptanceTest {
    public static void main(String[] args) {
        testOnlyAdapterInjectable();
        bladeSuggestJwtSecretAligned();
        constraintHarvest();
        coverageGapFromStaticOnly();
        System.out.println("FrameworkAdapterAcceptanceTest: PASS");
    }

    private static void bladeSuggestJwtSecretAligned() {
        SpringBladeAdapter adapter = new SpringBladeAdapter();
        String suggested = adapter.suggestJwtSecret(null).orElse("");
        check(AuthCodeQueryService.BLADE_DEFAULT_SIGN_KEY.equals(suggested),
                "SpringBladeAdapter suggestJwtSecret matches AuthCodeQueryService default");
        check(BladeJwtCredentialPack.DEFAULT_SECRET.equals(suggested),
                "SpringBladeAdapter suggestJwtSecret matches BladeJwtCredentialPack");
        check(!suggested.contains("upgradedversion")
                        || suggested.equals(AuthCodeQueryService.BLADE_DEFAULT_SIGN_KEY),
                "SpringBladeAdapter must not use truncated historical Blade key typo");
    }

    private static void testOnlyAdapterInjectable() {
        AtomicBoolean matched = new AtomicBoolean(false);
        FrameworkAdapter testAdapter = new FrameworkAdapter() {
            @Override public String id() { return "test-only"; }
            @Override public boolean matches(Path artifactPath, List<String> routes) {
                matched.set(true);
                return routes != null && routes.contains("/test-only");
            }
            @Override public Set<String> highValueRouteSignals() { return Set.of("test-only"); }
            @Override public Set<String> highValueClassSignals() { return Set.of("testonly"); }
            @Override public boolean preferBladeAuthHeader(
                    com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService.MaterialBundle materials) {
                return false;
            }
            @Override public Optional<String> suggestJwtSecret(Path artifactPath) {
                return Optional.of("test-secret");
            }
            @Override public List<com.aq.jvmsentinel.model.AuthBypassTechnique> defaultBypassTechniques() {
                return List.of();
            }
        };
        FrameworkAdapterRegistry.registerForTests(testAdapter);
        try {
            List<FrameworkAdapter> matchedAdapters =
                    FrameworkAdapterRegistry.matching(null, List.of("/test-only"));
            check(matched.get(), "test adapter matches() invoked");
            check(matchedAdapters.stream().anyMatch(a -> "test-only".equals(a.id())),
                    "test-only adapter injectable without production code edits");
            check(FrameworkAdapterRegistry.containsHighValueSignal("/api/test-only/x"),
                    "injected high-value route signal visible");
        } finally {
            FrameworkAdapterRegistry.unregisterForTests(testAdapter);
        }
        check(FrameworkAdapterRegistry.matching(null, List.of("/blade-auth/login"))
                        .stream().anyMatch(a -> "spring-blade".equals(a.id())),
                "SpringBladeAdapter still matches blade routes");
    }

    private static void constraintHarvest() {
        List<ParameterSpec> specs = BranchConstraintHarvester.harvest(
                List.of("name=role, type=string"),
                List.of("if (role.equals(\"ADMIN\")) {", "role.length() < 32"));
        check(!specs.isEmpty(), "harvester emits ParameterSpec");
        ParameterSpec role = specs.get(0);
        check(role.constraints().stream().anyMatch(c ->
                        c.type() == ParameterConstraint.ConstraintType.EQUALS
                                && "ADMIN".equals(c.literal())),
                "equals literal harvested");
        check(role.constraints().stream().anyMatch(c ->
                        c.type() == ParameterConstraint.ConstraintType.MAX_LEN),
                "maxLen harvested");
    }

    private static void coverageGapFromStaticOnly() {
        StaticContrastRow row = new StaticContrastRow(
                "row-1", "sink-sql", "SQL", "Repo#find",
                List.of("entry:entry-1"), "tp-001", "UNAUTH",
                ContrastStatus.STATIC_ONLY, List.of(), "STATIC_ONLY", false);
        List<CoverageGapProjector.CoverageGap> gaps = CoverageGapProjector.project(
                List.of(), List.of(row), List.of(new ApiDtos.EntryDto(
                        ApiDtos.SCHEMA_VERSION, "p", "d", "s", "entry-1", "HTTP", "GET",
                        "/api/user", "UserController", "user",
                        List.of("name=userId"), List.of("ROLE=ADMIN"),
                        "STATIC_INFERRED", 0.9, 0, List.of())));
        check(!gaps.isEmpty(), "STATIC_ONLY row projects a CoverageGap");
        check("tp-001".equals(gaps.get(0).taintPathId()), "taintPathId preserved");
        check(gaps.get(0).suggestedTrack() != null && !gaps.get(0).suggestedTrack().isBlank(),
                "suggestedTrack present");
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}

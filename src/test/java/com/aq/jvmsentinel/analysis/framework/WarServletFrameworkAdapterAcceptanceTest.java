package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.model.RunProfile;

import java.nio.file.Path;
import java.util.List;

/**
 * P2 SCAFFOLDING: WarFrameworkAdapter + ServletFrameworkAdapter via SPI;
 * neutral fact contract (WAR dynamic stays disabled; adapters emit HINT only).
 */
public final class WarServletFrameworkAdapterAcceptanceTest {
    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        registeredViaSpi();
        warMatchesAndDynamicDisabled();
        servletMatchesWarAndServletRoutes();
        neutralHintContract();
        System.out.println("WarServletFrameworkAdapterAcceptanceTest: PASS");
    }

    private static void registeredViaSpi() {
        List<FrameworkAdapter> all = FrameworkAdapterRegistry.all();
        check(all.stream().anyMatch(a -> "servlet".equals(a.id())),
                "ServletFrameworkAdapter registered in SPI registry");
        check(all.stream().anyMatch(a -> "war".equals(a.id())),
                "WarFrameworkAdapter registered in SPI registry");
        check(all.stream().anyMatch(a -> "spring-mvc".equals(a.id())),
                "SpringMvcAdapter baseline still present");
    }

    private static void warMatchesAndDynamicDisabled() {
        Path war = Path.of("fixtures", "sample-app.war");
        List<FrameworkAdapter> matched = FrameworkAdapterRegistry.matching(war, List.of("/index.jsp"));
        check(matched.stream().anyMatch(a -> "war".equals(a.id())),
                "WarFrameworkAdapter matches .war path");
        check(matched.stream().anyMatch(a -> "servlet".equals(a.id())),
                "ServletFrameworkAdapter also matches .war path");

        check(RunProfile.MODE_WAR_DYNAMIC_DISABLED.equals(
                        WarFrameworkAdapter.dynamicPolicyFact(true)),
                "profile-present WAR still WAR_DYNAMIC_DISABLED");
        check(RunProfile.MODE_NO_RUN_PROFILE.equals(
                        WarFrameworkAdapter.dynamicPolicyFact(false)),
                "profile-absent WAR is NO_RUN_PROFILE");
        check(!RunProfile.forArtifact(
                        com.aq.jvmsentinel.model.ArtifactType.WAR, false, true)
                        .allowsTrustedDockerDynamic(),
                "WAR never allows TRUSTED_DOCKER dynamic");
    }

    private static void servletMatchesWarAndServletRoutes() {
        ServletFrameworkAdapter servlet = new ServletFrameworkAdapter();
        check(servlet.matches(null, List.of("/servlet/admin")),
                "ServletFrameworkAdapter matches servlet route");
        check(servlet.matches(Path.of("app.war"), List.of()),
                "ServletFrameworkAdapter matches war filename");
        check(!servlet.matches(null, List.of("/api/orders")),
                "ServletFrameworkAdapter does not match plain Spring route");
    }

    private static void neutralHintContract() {
        WarFrameworkAdapter war = new WarFrameworkAdapter();
        ServletFrameworkAdapter servlet = new ServletFrameworkAdapter();
        check(war.suggestJwtSecret(null).isEmpty(),
                "War adapter does not invent JWT secrets");
        check(servlet.suggestJwtSecret(null).isEmpty(),
                "Servlet adapter does not invent JWT secrets");
        check(war.jwtSecretHintNotes().stream().allMatch(n -> n.contains("HINT")),
                "War notes labeled HINT");
        check(servlet.jwtSecretHintNotes().stream().allMatch(n -> n.contains("HINT")),
                "Servlet notes labeled HINT");
        check(war.jwtSecretHintNotes().stream().noneMatch(n -> n.contains("VERIFIED")),
                "War notes do not claim VERIFIED");
        check(servlet.jwtSecretHintNotes().stream().noneMatch(n -> n.contains("VERIFIED")),
                "Servlet notes do not claim VERIFIED");
        check(!war.preferSecondaryAuthHeader(null),
                "War adapter does not force secondary auth channel");
        check(!servlet.preferSecondaryAuthHeader(null),
                "Servlet adapter does not force secondary auth channel");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        AcceptanceAssertions.record();
    }
}

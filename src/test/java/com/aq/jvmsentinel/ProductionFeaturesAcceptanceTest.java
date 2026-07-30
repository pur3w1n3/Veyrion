package com.aq.jvmsentinel;

import com.aq.jvmsentinel.domain.security.ProductionFeatures;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 说明：P2 scaffolding：production session/CSRF/SSO/tenancy/retention 保持 DISABLED。
 */
public final class ProductionFeaturesAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        flagsRemainDisabled();
        requireDisabledSucceeds();
        adrProposedPresent();

        System.out.println("ProductionFeaturesAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void flagsRemainDisabled() {
        check(ProductionFeatures.DISABLED, "ProductionFeatures.DISABLED is true");
        check(!ProductionFeatures.SESSION_AUTH, "SESSION_AUTH disabled");
        check(!ProductionFeatures.CSRF_PROTECTION, "CSRF_PROTECTION disabled");
        check(!ProductionFeatures.SSO_OIDC, "SSO_OIDC disabled");
        check(!ProductionFeatures.MULTI_TENANT_ISOLATION, "MULTI_TENANT_ISOLATION disabled");
        check(!ProductionFeatures.DATA_RETENTION_POLICY, "DATA_RETENTION_POLICY disabled");
        check(!ProductionFeatures.productionSessionStackEnabled(),
                "production session stack not enabled");
    }

    private static void requireDisabledSucceeds() {
        ProductionFeatures.requireDisabled();
        check(true, "requireDisabled passes while scaffolding");
    }

    private static void adrProposedPresent() throws Exception {
        Path adr = SchemaContractAcceptanceTest.projectRoot()
                .resolve("docs/adr/0003-production-session-deferred.md");
        check(Files.isRegularFile(adr), "ADR-0003 file exists");
        String text = Files.readString(adr, StandardCharsets.UTF_8);
        check(text.contains("Status: `PROPOSED`") || text.contains("Status: PROPOSED"),
                "ADR-0003 remains PROPOSED");
        check(text.contains("CSRF") && text.contains("SSO") && text.contains("多租户"),
                "ADR-0003 covers session/CSRF/SSO/tenancy scope");
        Path index = SchemaContractAcceptanceTest.projectRoot().resolve("docs/adr/README.md");
        String indexText = Files.readString(index, StandardCharsets.UTF_8);
        check(indexText.contains("0003"), "ADR index lists 0003");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

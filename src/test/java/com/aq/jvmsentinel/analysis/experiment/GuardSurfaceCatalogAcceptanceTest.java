package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.analysis.GuardSurfaceBytecodeProbe;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.ForcedGuardKind;
import com.aq.jvmsentinel.domain.pathdebug.GuardSurface;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/** Static GuardSurface catalog drives FORCED allowlist / forcedGuardRefs. */
public final class GuardSurfaceCatalogAcceptanceTest {
    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        Path jar = Files.createTempFile("guard-surface-", ".jar");
        try {
            writeFixtureJar(jar);
            GuardSurfaceCatalog.HarvestResult harvest = GuardSurfaceCatalog.harvestDetailed(jar);
            List<GuardSurface> surfaces = harvest.surfaces();
            check(!surfaces.isEmpty(), "catalog harvests guard surfaces");
            boolean login = surfaces.stream().anyMatch(s ->
                    s.ref().equals("GUARD:AUTH:LoginFilter")
                            && s.typeNames().contains("com.example.app.LoginFilter")
                            && s.kind() == ForcedGuardKind.AUTH
                            && s.decisionShape() == GuardSurface.DecisionShape.ACCESS_CONTROL);
            check(login, "LoginFilter emitted as ACCESS_CONTROL GuardSurface");
            boolean shiro = surfaces.stream().anyMatch(s ->
                    s.typeNames().stream().anyMatch(t ->
                            t.contains("org.apache.shiro.web.filter.authc.UserFilter"))
                            && s.decisionShape() == GuardSurface.DecisionShape.ACCESS_CONTROL);
            check(shiro, "nested shiro-web UserFilter harvested as ACCESS_CONTROL");
            boolean bladeInterceptor = surfaces.stream().anyMatch(s ->
                    s.ref().equals("GUARD:AUTH:TokenInterceptor")
                            && s.typeNames().contains(
                            "org.springblade.core.secure.interceptor.TokenInterceptor")
                            && s.decisionShape() == GuardSurface.DecisionShape.INTERCEPTOR);
            check(bladeInterceptor, "nested blade-core-secure TokenInterceptor harvested");
            boolean saToken = surfaces.stream().anyMatch(s ->
                    s.ref().equals("GUARD:AUTH:SaInterceptor")
                            && s.typeNames().contains("cn.dev33.satoken.interceptor.SaInterceptor")
                            && s.decisionShape() == GuardSurface.DecisionShape.INTERCEPTOR);
            check(saToken, "nested sa-token-spring-boot SaInterceptor harvested");
            boolean saFilter = surfaces.stream().anyMatch(s ->
                    s.typeNames().contains("cn.dev33.satoken.filter.SaServletFilter")
                            && s.decisionShape() == GuardSurface.DecisionShape.FILTER_CHAIN);
            check(saFilter, "SaServletFilter harvested as FILTER_CHAIN");
            boolean noXss = surfaces.stream().noneMatch(s ->
                    s.typeNames().stream().anyMatch(t -> t.toLowerCase().contains("xss")));
            check(noXss, "XSSFilter excluded");
            boolean noSql = surfaces.stream().noneMatch(s ->
                    s.typeNames().stream().anyMatch(t -> t.toLowerCase().contains("sqlfilter")));
            check(noSql, "SQLFilter excluded");
            boolean noContainer = surfaces.stream().noneMatch(s ->
                    s.typeNames().stream().anyMatch(t ->
                            t.endsWith("AbstractShiroFilter")));
            check(noContainer, "AbstractShiroFilter excluded");

            List<String> refs = GuardSurfaceCatalog.guardRefs(surfaces);
            check(refs.contains("GUARD:AUTH:LoginFilter"), "guardRefs includes LoginFilter");
            String prop = GuardSurfaceCatalog.formatTypeNamesProperty(
                    GuardSurfaceCatalog.typeNames(surfaces));
            check(prop.contains("com.example.app.LoginFilter"), "typeNames property includes LoginFilter");
            check(prop.length() <= GuardSurfaceCatalog.MAX_TYPE_NAMES_PROPERTY_CHARS,
                    "typeNames property bounded");

            ApiDtos.EntryDto entry = new ApiDtos.EntryDto(
                    ApiDtos.SCHEMA_VERSION, "local", "digest-guard", "scan-guard",
                    "entry-1", "HTTP", "GET", "/api/demo", "DemoController", "app",
                    List.of("name=query"), List.of(), ApiDtos.STATIC_INFERRED, 0.8, 100,
                    List.of("evidence-entry-1"));
            List<PostureExperimentCompiler.CompiledPostureExperiment> compiled =
                    PostureExperimentCompiler.compileAll(
                            List.of(entry), "scan-guard",
                            List.of(), List.of(), refs, List.of(),
                            List.of(), 16);
            boolean forcedWithRefs = compiled.stream().anyMatch(plan ->
                    plan.posture().postureKind() == RuntimePostureKind.FORCED_REACHABILITY
                            && !plan.posture().forcedGuardRefs().isEmpty()
                            && plan.posture().forcedGuardRefs().contains("GUARD:AUTH:LoginFilter"));
            check(forcedWithRefs, "FORCED plans carry catalog forcedGuardRefs");

            List<PostureExperimentCompiler.CompiledPostureExperiment> emptyHints =
                    PostureExperimentCompiler.compileAll(
                            List.of(entry), "scan-guard-empty",
                            List.of(), List.of(), List.of(), List.of(),
                            List.of(), 16);
            boolean emptyForcedRefs = emptyHints.stream()
                    .filter(plan -> plan.posture().postureKind()
                            == RuntimePostureKind.FORCED_REACHABILITY)
                    .allMatch(plan -> plan.posture().forcedGuardRefs().isEmpty());
            check(emptyForcedRefs, "empty guardHints still yield FORCED with empty refs");

            ExternalArtifactTaskExecutor.ForcedGuardAllowlist allowlist =
                    ExternalArtifactTaskExecutor.forcedGuardAllowlist(jar);
            check(allowlist.typeNamesCsv().contains("LoginFilter"),
                    "executor property carries LoginFilter");
            check(allowlist.typeNamesCsv().contains("SaInterceptor"),
                    "executor property carries SaInterceptor");

            // Truncation visibility: when more type names than MAX, gap is recorded.
            List<String> many = new ArrayList<>();
            for (int i = 0; i < GuardSurfaceCatalog.MAX_TYPE_NAMES + 5; i++) {
                many.add("com.example.guards.AuthFilter" + i);
            }
            GuardSurfaceCatalog.TypeNamesProperty truncated =
                    GuardSurfaceCatalog.formatTypeNamesPropertyDetailed(many);
            check(truncated.truncated(), "formatTypeNamesPropertyDetailed marks truncation");
            check(GuardSurfaceCatalog.GAP_CATALOG_TRUNCATED.equals(truncated.gapCode()),
                    "truncation gap code is GUARD_CATALOG_TRUNCATED");

            // Bytecode probe gate: sanitizers not probe-worthy.
            check(!GuardSurfaceBytecodeProbe.looksProbeWorthy("com.example.XssFilter"),
                    "XssFilter not bytecode-probe-worthy");
            check(GuardSurfaceBytecodeProbe.looksProbeWorthy("com.example.CustomAuthWallFilter"),
                    "CustomAuthWallFilter is probe-worthy by name shape");
        } finally {
            Files.deleteIfExists(jar);
        }
        System.out.println("GuardSurfaceCatalogAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static void writeFixtureJar(Path jar) throws IOException {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            putEmptyClass(jos, "BOOT-INF/classes/com/example/app/LoginFilter.class");
            putEmptyClass(jos, "BOOT-INF/classes/com/example/app/XssFilter.class");
            putEmptyClass(jos, "BOOT-INF/classes/com/example/app/SQLFilter.class");
            putEmptyClass(jos, "BOOT-INF/classes/com/example/app/CharacterEncodingFilter.class");
            jos.putNextEntry(new JarEntry("BOOT-INF/lib/shiro-web-1.13.0.jar"));
            jos.write(nestedShiroJar());
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("BOOT-INF/lib/blade-core-secure-3.0.0.RELEASE.jar"));
            jos.write(nestedBladeSecureJar());
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("BOOT-INF/lib/sa-token-spring-boot-starter-1.37.0.jar"));
            jos.write(nestedSaTokenJar());
            jos.closeEntry();
        }
    }

    private static byte[] nestedShiroJar() throws IOException {
        Path tmp = Files.createTempFile("nested-shiro-", ".jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(tmp))) {
            putEmptyClass(jos, "org/apache/shiro/web/filter/authc/UserFilter.class");
            putEmptyClass(jos, "org/apache/shiro/web/servlet/AbstractShiroFilter.class");
        }
        byte[] bytes = Files.readAllBytes(tmp);
        Files.deleteIfExists(tmp);
        return bytes;
    }

    private static byte[] nestedBladeSecureJar() throws IOException {
        Path tmp = Files.createTempFile("nested-blade-secure-", ".jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(tmp))) {
            putEmptyClass(jos,
                    "org/springblade/core/secure/interceptor/TokenInterceptor.class");
            putEmptyClass(jos,
                    "org/springblade/core/secure/interceptor/AuthInterceptor.class");
        }
        byte[] bytes = Files.readAllBytes(tmp);
        Files.deleteIfExists(tmp);
        return bytes;
    }

    private static byte[] nestedSaTokenJar() throws IOException {
        Path tmp = Files.createTempFile("nested-sa-token-", ".jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(tmp))) {
            putEmptyClass(jos, "cn/dev33/satoken/interceptor/SaInterceptor.class");
            putEmptyClass(jos, "cn/dev33/satoken/filter/SaServletFilter.class");
        }
        byte[] bytes = Files.readAllBytes(tmp);
        Files.deleteIfExists(tmp);
        return bytes;
    }

    private static void putEmptyClass(JarOutputStream jos, String name) throws IOException {
        jos.putNextEntry(new JarEntry(name));
        jos.write(new byte[] {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE});
        jos.closeEntry();
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        AcceptanceAssertions.record();
    }
}

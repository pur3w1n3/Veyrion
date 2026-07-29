package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.ForcedGuardKind;
import com.aq.jvmsentinel.domain.pathdebug.GuardSurface;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
            List<GuardSurface> surfaces = GuardSurfaceCatalog.harvest(jar);
            check(!surfaces.isEmpty(), "catalog harvests guard surfaces");
            boolean login = surfaces.stream().anyMatch(s ->
                    s.ref().equals("GUARD:AUTH:LoginFilter")
                            && s.typeNames().contains("com.example.app.LoginFilter")
                            && s.kind() == ForcedGuardKind.AUTH);
            check(login, "LoginFilter emitted as GUARD:AUTH:LoginFilter");
            boolean shiro = surfaces.stream().anyMatch(s ->
                    s.typeNames().stream().anyMatch(t ->
                            t.contains("org.apache.shiro.web.filter.authc.UserFilter")));
            check(shiro, "nested shiro-web UserFilter harvested");
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

            String executorProp = ExternalArtifactTaskExecutor.forcedGuardTypeNamesProperty(jar);
            check(executorProp.contains("LoginFilter"), "executor property carries LoginFilter");
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

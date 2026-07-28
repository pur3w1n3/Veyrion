package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.detector.DangerousConfigDetector;
import com.aq.jvmsentinel.analysis.detector.DependencyVersionDetector;
import com.aq.jvmsentinel.analysis.detector.DeserializationConfigDetector;
import com.aq.jvmsentinel.analysis.detector.DetectorContext;
import com.aq.jvmsentinel.analysis.detector.DetectorIds;
import com.aq.jvmsentinel.analysis.detector.DetectorRecallGate;
import com.aq.jvmsentinel.analysis.detector.DetectorRegistry;
import com.aq.jvmsentinel.analysis.detector.GuardConsistencyDetector;
import com.aq.jvmsentinel.analysis.detector.HypothesisMerge;
import com.aq.jvmsentinel.analysis.detector.OwnershipIdorDetector;
import com.aq.jvmsentinel.analysis.detector.ResourceLifecycleDetector;
import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.domain.universe.UniverseScope;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P1-05: non-taint detector skeleton — positive/negative fixtures, merge with projector,
 * no sink-none AUTH representation, AcceptanceTestRunner gate.
 */
public final class NonTaintDetectorAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        verifyBaselineSkeleton();
        verifyUnitDetectors();
        verifyMutationHoldoutRecallGates();
        verifyMergeDedupe();
        Path root = Files.createTempDirectory("non-taint-detector");
        try {
            verifyLivePositive(root);
            verifyLiveNegative(root);
            System.out.println("NonTaintDetectorAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            deleteTree(root);
        }
    }

    private static void verifyBaselineSkeleton() throws Exception {
        try (InputStream in = NonTaintDetectorAcceptanceTest.class.getClassLoader()
                .getResourceAsStream("baselines/p1-05-non-taint-detectors.json")) {
            check(in != null, "p1-05 baseline present");
            JsonNode baseline = JSON.readTree(in);
            check("p1-05-non-taint-detectors".equals(baseline.path("baselineId").asText()),
                    "baseline id");
            check(baseline.path("expectedDetectorIds").isArray()
                            && baseline.path("expectedDetectorIds").size() >= 3,
                    "baseline lists detector ids");
            check(baseline.path("honesty").path("aiNotInBaseJudgment").asBoolean(false),
                    "baseline forbids AI in base judgment");
            check(baseline.path("recallGate").path("requiredProperties").isArray()
                            && baseline.path("recallGate").path("requiredProperties").size() >= 3,
                    "baseline recallGate lists required properties");
            check(baseline.path("recallGate").path("failWhenDetectorRemoved").isArray()
                            && baseline.path("recallGate").path("failWhenDetectorRemoved").size() >= 3,
                    "baseline documents remove-detector fail set");
        }
        try (InputStream mutation = NonTaintDetectorAcceptanceTest.class.getClassLoader()
                .getResourceAsStream("baselines/p1-05-mutation-non-taint.json");
             InputStream holdout = NonTaintDetectorAcceptanceTest.class.getClassLoader()
                     .getResourceAsStream("baselines/p1-05-holdout-non-taint.json")) {
            check(mutation != null, "p1-05 mutation baseline present");
            check(holdout != null, "p1-05 holdout baseline present");
            JsonNode mut = JSON.readTree(mutation);
            JsonNode hold = JSON.readTree(holdout);
            check("mutation".equals(mut.path("kind").asText()), "mutation kind");
            check("holdout".equals(hold.path("kind").asText()), "holdout kind");
            check(!mut.path("metrics").path("stub").asBoolean(true),
                    "mutation metrics not stub");
            check(!hold.path("metrics").path("stub").asBoolean(true),
                    "holdout metrics not stub");
        }
    }

    private static void verifyMutationHoldoutRecallGates() {
        DetectorContext mutationCtx = mutationContext();
        DetectorContext holdoutCtx = holdoutContext();
        DetectorRegistry full = DetectorRegistry.defaults();

        Set<String> mutationExpected = Set.of(
                GuardConsistencyDetector.PROPERTY,
                OwnershipIdorDetector.PROPERTY,
                DangerousConfigDetector.PROP_JWT_ALG_NONE);
        DetectorRecallGate.Result mutationPass =
                DetectorRecallGate.evaluate(full, mutationCtx, mutationExpected);
        check(mutationPass.passed(), "mutation recall gate passes with full registry");

        Set<String> holdoutExpected = Set.of(
                GuardConsistencyDetector.PROPERTY,
                OwnershipIdorDetector.PROPERTY,
                DangerousConfigDetector.PROP_SENSITIVE_CONFIG);
        DetectorRecallGate.Result holdoutPass =
                DetectorRecallGate.evaluate(full, holdoutCtx, holdoutExpected);
        check(holdoutPass.passed(), "holdout recall gate passes with full registry");

        // Independent remove-detector → fail proofs for the first-batch trio.
        assertRemoveFails(full, mutationCtx, DetectorIds.GUARD_CONSISTENCY,
                Set.of(GuardConsistencyDetector.PROPERTY), "mutation/guard");
        assertRemoveFails(full, mutationCtx, DetectorIds.OWNERSHIP_IDOR,
                Set.of(OwnershipIdorDetector.PROPERTY), "mutation/idor");
        assertRemoveFails(full, mutationCtx, DetectorIds.DANGEROUS_CONFIG,
                Set.of(DangerousConfigDetector.PROP_JWT_ALG_NONE), "mutation/config");
        assertRemoveFails(full, holdoutCtx, DetectorIds.GUARD_CONSISTENCY,
                Set.of(GuardConsistencyDetector.PROPERTY), "holdout/guard");
        assertRemoveFails(full, holdoutCtx, DetectorIds.OWNERSHIP_IDOR,
                Set.of(OwnershipIdorDetector.PROPERTY), "holdout/idor");
        assertRemoveFails(full, holdoutCtx, DetectorIds.DANGEROUS_CONFIG,
                Set.of(DangerousConfigDetector.PROP_SENSITIVE_CONFIG), "holdout/config");
    }

    private static void assertRemoveFails(DetectorRegistry full,
                                          DetectorContext context,
                                          String detectorId,
                                          Set<String> expected,
                                          String label) {
        DetectorRegistry stripped = DetectorRecallGate.without(full, detectorId);
        check(stripped.detectors().stream().noneMatch(d -> detectorId.equals(d.id())),
                label + ": detector removed from registry");
        DetectorRecallGate.Result failed = DetectorRecallGate.evaluate(stripped, context, expected);
        check(!failed.passed(), label + ": recall gate fails after detector removal");
        check(!failed.missingProperties().isEmpty(), label + ": missing properties reported");
    }

    private static DetectorContext mutationContext() {
        ApiDtos.EntryDto secured = entry("m1", "com.example.Mut", "GET", "/admin",
                List.of(), List.of("Secured(ROLE_ADMIN)"));
        ApiDtos.EntryDto open = entry("m2", "com.example.Mut", "GET", "/public",
                List.of(), List.of());
        ApiDtos.EntryDto account = entry("m3", "com.example.Mut", "GET", "/accounts/{accountId}",
                List.of("position=0,kind=PathVariable,name=accountId"), List.of());
        return ctx(List.of(secured, open, account), List.of(), List.of(), Map.of(),
                List.of("JWT_ALG = none", "server.port=8080"));
    }

    private static DetectorContext holdoutContext() {
        ApiDtos.EntryDto roles = entry("h1", "com.example.Hold", "GET", "/secure",
                List.of(), List.of("RolesAllowed(ADMIN)"));
        ApiDtos.EntryDto open = entry("h2", "com.example.Hold", "GET", "/anon",
                List.of(), List.of());
        ApiDtos.EntryDto order = entry("h3", "com.example.Hold", "GET", "/orders/{orderId}",
                List.of("position=0,kind=PathVariable,name=orderId"), List.of());
        return ctx(List.of(roles, open, order), List.of(), List.of(), Map.of(),
                List.of(
                        "spring.datasource.password=<redacted>",
                        "blade.jwt.sign-key=<redacted>",
                        "server.port=8080"));
    }

    private static void verifyUnitDetectors() {
        verifyGuardConsistency();
        verifyOwnershipIdor();
        verifyDangerousConfig();
        verifySkeletonDetectors();
    }

    private static void verifyGuardConsistency() {
        ApiDtos.EntryDto guarded = entry("e1", "com.example.Mixed", "GET", "/admin",
                List.of(), List.of("PreAuthorize(hasRole('ADMIN'))"));
        ApiDtos.EntryDto open = entry("e2", "com.example.Mixed", "GET", "/open",
                List.of(), List.of());
        List<SecurityHypothesis> positive = new GuardConsistencyDetector().analyze(ctx(
                List.of(guarded, open), List.of(), List.of(), Map.of(), List.of()));
        check(positive.stream().anyMatch(h -> GuardConsistencyDetector.PROPERTY.equals(h.securityProperty())),
                "GuardConsistency positive: mixed guards");
        check(positive.stream().noneMatch(h -> "sink-none".equals(h.effect()) || "sink-none".equals(h.source())),
                "GuardConsistency positive: not sink-none");

        ApiDtos.EntryDto allGuardedA = entry("e3", "com.example.Safe", "GET", "/a",
                List.of(), List.of("PreAuthorize(hasRole('ADMIN'))"));
        ApiDtos.EntryDto allGuardedB = entry("e4", "com.example.Safe", "GET", "/b",
                List.of(), List.of("Secured(ROLE_USER)"));
        List<SecurityHypothesis> negative = new GuardConsistencyDetector().analyze(ctx(
                List.of(allGuardedA, allGuardedB), List.of(), List.of(), Map.of(), List.of()));
        check(negative.isEmpty(), "GuardConsistency negative: consistent guards");
    }

    private static void verifyOwnershipIdor() {
        ApiDtos.EntryDto gap = entry("e1", "com.example.UserApi", "GET", "/users/{userId}",
                List.of("position=0,kind=PathVariable,name=userId"), List.of());
        List<SecurityHypothesis> positive = new OwnershipIdorDetector().analyze(ctx(
                List.of(gap), List.of(), List.of(), Map.of(), List.of()));
        check(positive.stream().anyMatch(h -> OwnershipIdorDetector.PROPERTY.equals(h.securityProperty())),
                "OwnershipIdor positive: object id without ownership");

        ApiDtos.EntryDto owned = entry("e2", "com.example.UserApi", "GET", "/users/{userId}",
                List.of("position=0,kind=PathVariable,name=userId"),
                List.of("PreAuthorize(#userId == authentication.name)"));
        List<SecurityHypothesis> negative = new OwnershipIdorDetector().analyze(ctx(
                List.of(owned), List.of(), List.of(), Map.of(), List.of()));
        check(negative.isEmpty(), "OwnershipIdor negative: ownership expression present");
    }

    private static void verifyDangerousConfig() {
        List<SecurityHypothesis> positive = new DangerousConfigDetector().analyze(ctx(
                List.of(), List.of(), List.of(), Map.of(),
                List.of(
                        "jwt.algorithm=none",
                        "spring.datasource.password=<redacted>",
                        "blade.jwt.sign-key=<redacted>"
                )));
        check(positive.stream().anyMatch(h -> DangerousConfigDetector.PROP_JWT_ALG_NONE.equals(h.securityProperty())),
                "DangerousConfig positive: jwt alg none");
        check(positive.stream().anyMatch(h -> DangerousConfigDetector.PROP_SENSITIVE_CONFIG.equals(h.securityProperty())),
                "DangerousConfig positive: sensitive config material");
        check(positive.stream().anyMatch(h -> DangerousConfigDetector.PROP_JWT_SECRET_CONFIG.equals(h.securityProperty())),
                "DangerousConfig positive: jwt secret config");

        List<SecurityHypothesis> negative = new DangerousConfigDetector().analyze(ctx(
                List.of(), List.of(), List.of(), Map.of(),
                List.of("server.port=8080", "spring.application.name=demo")));
        check(negative.isEmpty(), "DangerousConfig negative: benign config");
    }

    private static void verifySkeletonDetectors() {
        ApiDtos.SinkDto deser = new ApiDtos.SinkDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "s", "sink-1", "DESERIALIZATION",
                "com.example.Load#read -> java.io.ObjectInputStream#readObject",
                "bytecode-invoke", ApiDtos.STATIC_INFERRED, 0.9, List.of("ev-1"));
        check(!new DeserializationConfigDetector().analyze(ctx(
                List.of(), List.of(deser), List.of(), Map.of(), List.of())).isEmpty(),
                "DeserializationConfig positive");
        check(new DeserializationConfigDetector().analyze(ctx(
                List.of(), List.of(), List.of(), Map.of(), List.of())).isEmpty(),
                "DeserializationConfig negative");

        ArtifactUniverse risky = new ArtifactUniverse(
                ArtifactUniverse.SCHEMA_VERSION,
                List.of(),
                List.of(new ArtifactUniverse.DependencySummary(
                        "commons-collections-3.2.1.jar", "abc", UniverseScope.THIRD_PARTY,
                        10L, false, "nested")),
                List.of(), List.of(), List.of(), false, List.of());
        DetectorContext riskyCtx = new DetectorContext(
                "scan-dep", risky, new StaticFactSnapshot(StaticFactSnapshot.COMPLETE, List.of(), null),
                List.of(), List.of(), List.of(), Map.of(), List.of());
        check(!new DependencyVersionDetector().analyze(riskyCtx).isEmpty(),
                "DependencyVersion positive");
        check(new DependencyVersionDetector().analyze(ctx(
                List.of(), List.of(), List.of(), Map.of(), List.of())).isEmpty(),
                "DependencyVersion negative");

        ApiDtos.SinkDto file = new ApiDtos.SinkDto(
                ApiDtos.SCHEMA_VERSION, "p", "d", "s", "sink-f", "FILE_READ",
                "com.example.R#open -> java.io.FileInputStream#<init>",
                "bytecode", ApiDtos.STATIC_INFERRED, 0.8, List.of());
        check(!new ResourceLifecycleDetector().analyze(ctx(
                List.of(), List.of(file), List.of(), Map.of(), List.of())).isEmpty(),
                "ResourceLifecycle positive via FILE_READ sink");
    }

    private static void verifyMergeDedupe() {
        SecurityHypothesis projected = new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION, "hyp-gc-1", "scan-m", "AUTH_GAP",
                HypothesisFamily.GUARD_COVERAGE, HypothesisLifecycle.CANDIDATE,
                SecurityHypothesisProjector.DETECTOR_VERSION, List.of("e1"), List.of(), List.of(),
                "/open", "missing-auth-guard");
        SecurityHypothesis duplicate = new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION, "hyp-gc-dup", "scan-m", "AUTH_GAP",
                HypothesisFamily.GUARD_COVERAGE, HypothesisLifecycle.CANDIDATE,
                "guard-consistency/0.1.0", List.of("e1"), List.of(), List.of(),
                "/open", "missing-auth-guard");
        SecurityHypothesis fresh = new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION, "hyp-idor-1", "scan-m",
                OwnershipIdorDetector.PROPERTY, HypothesisFamily.GUARD_COVERAGE,
                HypothesisLifecycle.CANDIDATE, "ownership-idor/0.1.0", List.of(), List.of(), List.of(),
                "com.example.UserApi GET /users/{userId}", "object-id:userId");
        List<SecurityHypothesis> merged = SecurityHypothesisProjector.mergeWithDetectors(
                List.of(projected), List.of(duplicate, fresh));
        check(merged.size() == 2, "merge keeps projector + distinct detector hyp");
        check(merged.stream().anyMatch(h -> "hyp-gc-1".equals(h.hypothesisId())),
                "merge prefers first (projector) on dedupe key");
        check(HypothesisMerge.dedupeKey(projected).equals(HypothesisMerge.dedupeKey(duplicate)),
                "dedupe key stable across producers");
    }

    private static void verifyLivePositive(Path root) throws Exception {
        Path serverRoot = Files.createDirectories(root.resolve("pos"));
        Path jar = buildPositiveJar(serverRoot.resolve("positive"));
        String token = "non-taint-token";
        Path database = serverRoot.resolve("state/control-plane.db");
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(serverRoot, 0, token, database).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"non-taint positive\"}", token));
            String projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            String scanId = text(scan, "scanId");
            List<Object> hypotheses = array(scan, "hypotheses");
            check(!hypotheses.isEmpty(), "live positive scan returns hypotheses");

            boolean guardInconsistency = hasProperty(hypotheses, GuardConsistencyDetector.PROPERTY);
            boolean idor = hasProperty(hypotheses, OwnershipIdorDetector.PROPERTY);
            boolean jwtAlg = hasProperty(hypotheses, DangerousConfigDetector.PROP_JWT_ALG_NONE);
            boolean sensitive = hasProperty(hypotheses, DangerousConfigDetector.PROP_SENSITIVE_CONFIG)
                    || hasProperty(hypotheses, DangerousConfigDetector.PROP_JWT_SECRET_CONFIG);
            check(guardInconsistency, "live positive: GUARD_INCONSISTENCY");
            check(idor, "live positive: IDOR_OWNERSHIP_GAP");
            check(jwtAlg || sensitive, "live positive: dangerous config family");

            for (Object value : hypotheses) {
                if (!(value instanceof Map<?, ?> item)) continue;
                check(!"sink-none".equals(String.valueOf(item.get("effect")))
                                && !"sink-none".equals(String.valueOf(item.get("source"))),
                        "live positive: no sink-none hypothesis fields");
            }

            ControlPlaneStore store = server.store();
            check(store.hypotheses(scanId).stream()
                            .anyMatch(h -> GuardConsistencyDetector.PROPERTY.equals(h.securityProperty())),
                    "store retains detector hypotheses");
            check(DetectorRegistry.defaults().detectors().size() >= 3,
                    "registry exposes first-batch detectors");
        }
    }

    private static void verifyLiveNegative(Path root) throws Exception {
        Path serverRoot = Files.createDirectories(root.resolve("neg"));
        Path jar = buildNegativeJar(serverRoot.resolve("negative"));
        String token = "non-taint-neg";
        Path database = serverRoot.resolve("state/control-plane.db");
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(serverRoot, 0, token, database).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"non-taint negative\"}", token));
            String projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            List<Object> hypotheses = array(scan, "hypotheses");
            check(!hasProperty(hypotheses, GuardConsistencyDetector.PROPERTY),
                    "live negative: no GUARD_INCONSISTENCY");
            check(!hasProperty(hypotheses, OwnershipIdorDetector.PROPERTY),
                    "live negative: no IDOR_OWNERSHIP_GAP");
            check(!hasProperty(hypotheses, DangerousConfigDetector.PROP_JWT_ALG_NONE),
                    "live negative: no JWT_ALG_NONE");
            check(!hasProperty(hypotheses, DangerousConfigDetector.PROP_SENSITIVE_CONFIG),
                    "live negative: no SENSITIVE_CONFIG_MATERIAL");
        }
    }

    private static Path buildPositiveJar(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeSpringAnnotations(sources);
        Path pkg = Files.createDirectories(sources.resolve("com/example/nt"));
        Files.writeString(pkg.resolve("MixedController.java"), """
                package com.example.nt;
                import org.springframework.web.bind.annotation.*;
                import org.springframework.security.access.prepost.PreAuthorize;
                @RestController
                public class MixedController {
                    @GetMapping("/admin")
                    @PreAuthorize("hasRole('ADMIN')")
                    public String admin() { return "admin"; }
                    @GetMapping("/open")
                    public String open() { return "open"; }
                    @GetMapping("/users/{userId}")
                    public String user(@PathVariable("userId") String userId) { return userId; }
                }
                """);
        Files.writeString(pkg.resolve("Loader.java"), """
                package com.example.nt;
                import java.io.ObjectInputStream;
                import java.io.ByteArrayInputStream;
                public class Loader {
                    public Object load(byte[] data) throws Exception {
                        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data))) {
                            return in.readObject();
                        }
                    }
                }
                """);
        compile(sources, classes);
        Path jar = root.resolve("positive-fixture.jar");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                output.putNextEntry(new ZipEntry(
                        "BOOT-INF/classes/" + classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, output);
                output.closeEntry();
            }
            output.putNextEntry(new ZipEntry("BOOT-INF/classes/application.properties"));
            output.write("""
                    server.port=8080
                    jwt.algorithm=none
                    spring.datasource.password=super-secret
                    blade.jwt.sign-key=demo-key
                    """.getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
            output.putNextEntry(new ZipEntry("BOOT-INF/lib/commons-collections-3.2.1.jar"));
            output.write(new byte[]{'P', 'K', 3, 4});
            output.closeEntry();
        }
        return jar;
    }

    private static Path buildNegativeJar(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeSpringAnnotations(sources);
        Path pkg = Files.createDirectories(sources.resolve("com/example/ntsafe"));
        Files.writeString(pkg.resolve("SafeController.java"), """
                package com.example.ntsafe;
                import org.springframework.web.bind.annotation.*;
                import org.springframework.security.access.prepost.PreAuthorize;
                @RestController
                public class SafeController {
                    @GetMapping("/a")
                    @PreAuthorize("hasRole('ADMIN')")
                    public String a() { return "a"; }
                    @GetMapping("/users/{userId}")
                    @PreAuthorize("#userId == authentication.name")
                    public String user(@PathVariable("userId") String userId) { return userId; }
                }
                """);
        compile(sources, classes);
        Path jar = root.resolve("negative-fixture.jar");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                output.putNextEntry(new ZipEntry(
                        "BOOT-INF/classes/" + classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, output);
                output.closeEntry();
            }
            output.putNextEntry(new ZipEntry("BOOT-INF/classes/application.properties"));
            output.write("server.port=8080\nspring.application.name=safe\n"
                    .getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }
        return jar;
    }

    private static void writeSpringAnnotations(Path sources) throws Exception {
        Path spring = Files.createDirectories(sources.resolve("org/springframework/web/bind/annotation"));
        Files.writeString(spring.resolve("RestController.java"), """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        Files.writeString(spring.resolve("GetMapping.java"), """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String value() default ""; String path() default ""; }
                """);
        Files.writeString(spring.resolve("PathVariable.java"), """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.PARAMETER)
                public @interface PathVariable { String value() default ""; String name() default ""; }
                """);
        Path sec = Files.createDirectories(sources.resolve("org/springframework/security/access/prepost"));
        Files.writeString(sec.resolve("PreAuthorize.java"), """
                package org.springframework.security.access.prepost;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.METHOD, ElementType.TYPE})
                public @interface PreAuthorize { String value(); }
                """);
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "JDK compiler available");
        List<Path> sourceFiles;
        try (Stream<Path> stream = Files.walk(sources)) {
            sourceFiles = stream.filter(path -> path.toString().endsWith(".java")).toList();
        }
        try (StandardJavaFileManager manager =
                     compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean success = compiler.getTask(null, manager, null,
                    List.of("--release", "17", "-parameters", "-d", classes.toString()), null,
                    manager.getJavaFileObjectsFromPaths(sourceFiles)).call();
            check(success, "fixture compilation");
        }
    }

    private static DetectorContext ctx(List<ApiDtos.EntryDto> entries,
                                       List<ApiDtos.SinkDto> sinks,
                                       List<ApiDtos.DependencyDto> dependencies,
                                       Map<String, ApiDtos.EvidenceDto> evidence,
                                       List<String> config) {
        return new DetectorContext(
                "scan-unit",
                ArtifactUniverse.empty(),
                new StaticFactSnapshot(StaticFactSnapshot.COMPLETE, List.of(), null),
                entries, sinks, dependencies, evidence, config);
    }

    private static ApiDtos.EntryDto entry(String id, String declaringClass, String method, String route,
                                          List<String> parameters, List<String> preconditions) {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p", "digest", "scan-unit", id, "HTTP", method, route,
                declaringClass, "module", parameters, preconditions, ApiDtos.STATIC_INFERRED,
                0.9, 0, List.of("ev-" + id));
    }

    private static boolean hasProperty(List<Object> hypotheses, String property) {
        return hypotheses.stream().anyMatch(value -> value instanceof Map<?, ?> item
                && property.equals(String.valueOf(item.get("securityProperty"))));
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method,
                                             String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("X-Sentinel-Authorization", token);
        HttpRequest request = "POST".equals(method)
                ? builder.POST(HttpRequest.BodyPublishers.ofString(body)).build()
                : builder.GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "request succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    @SuppressWarnings("unchecked")
    private static List<Object> array(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof List<?> list)) throw new AssertionError("missing array " + field);
        return (List<Object>) list;
    }

    private static String text(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof String text) || text.isBlank()) {
            throw new AssertionError("missing " + field);
        }
        return text;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

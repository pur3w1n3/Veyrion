package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.ClassMetadata;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.analysis.entry.NonHttpEntryProtocol;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.Entrypoint;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 通用 RuntimeCallback / Executor 入口探测验收：注册表、XXL-JOB fixture、
 * Actuator/ElasticJob 骨架、高价值信号、自定义适配器注入。
 */
public final class ExecutorCallbackEntryAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        ASSERTIONS.set(0);
        registryInstallsGenericAdapters();
        xxlJobAnnotationFixtureProducesHttpCallbacks();
        preAnalysisWritesExecutorEntries();
        actuatorConfigSkeleton();
        elasticJobObservationalOnlyByDefault();
        highValueSignalsReachProbeHelper();
        customAdapterInjectable();
        jobProtocolNotHttpProbeEligible();
        System.out.println("ExecutorCallbackEntryAcceptanceTest: PASS ("
                + ASSERTIONS.get() + " assertions)");
    }

    private static void registryInstallsGenericAdapters() {
        Set<String> ids = ExecutorEntryAdapterRegistry.registeredIds();
        check(ids.contains(XxlJobExecutorEntryAdapter.ID), "xxl-job adapter registered");
        check(ids.contains(SpringActuatorEntryAdapter.ID), "actuator adapter registered");
        check(ids.contains(ElasticJobHttpEntryAdapter.ID), "elastic-job adapter registered");
        check(ExecutorEntryAdapterRegistry.all().size() >= 3, "at least 3 adapters");
    }

    private static void xxlJobAnnotationFixtureProducesHttpCallbacks() {
        ExecutorEntryContext ctx = fixtureContext(
                List.of("com.demo.job.DemoJob"),
                List.of("xxl.job.executor.port=9999"),
                List.of(xxlJobClassMetadata("com.demo.job.DemoJob", "demoJobHandler")),
                List.of("BOOT-INF/lib/xxl-job-core-2.4.0.jar"));

        check(new XxlJobExecutorEntryAdapter().matches(ctx), "XXL adapter matches fixture");
        List<RuntimeCallbackEntry> entries = new XxlJobExecutorEntryAdapter().discover(ctx);
        check(entries.stream().anyMatch(e -> "/run".equals(e.address()) && "POST".equals(e.operation())),
                "XXL emits POST /run");
        check(entries.stream().anyMatch(e -> "/beat".equals(e.address())),
                "XXL emits /beat");
        check(entries.stream().anyMatch(e -> "/idleBeat".equals(e.address())),
                "XXL emits /idleBeat");
        check(entries.stream().anyMatch(e -> "/kill".equals(e.address())),
                "XXL emits /kill");
        check(entries.stream().anyMatch(e -> "/log".equals(e.address())),
                "XXL emits /log");
        check(entries.stream().anyMatch(e ->
                        e.declaringSymbol().contains("DemoJob")
                                && e.inputs().stream().anyMatch(i -> i.contains("demoJobHandler"))),
                "XXL emits @XxlJob handler bound to /run");
        check(entries.stream().allMatch(e -> "xxl-job".equals(e.frameworkId())),
                "XXL entries carry frameworkId");
        check(entries.stream().anyMatch(e -> "FACT".equals(e.provenanceKind())),
                "annotation-backed entries are FACT");
    }

    private static void preAnalysisWritesExecutorEntries() {
        ArtifactDescriptor artifact = new ArtifactDescriptor(
                "artifact-xxl-fixture",
                ArtifactType.CLASS,
                Path.of("E:/ai/Veyrion/target/executor-xxl-fixture.class").toAbsolutePath().normalize(),
                128,
                "a".repeat(64),
                true,
                Instant.parse("2026-07-30T00:00:00Z"),
                "executor-xxl-fixture.class");
        PreAnalysisInput input = new PreAnalysisInput(
                artifact,
                List.of("com.demo.job.DemoJob"),
                List.of("xxl.job.executor.port=9999"),
                List.of(xxlJobClassMetadata("com.demo.job.DemoJob", "demoJobHandler")));

        var result = new PreAnalysisService().analyze(input);
        List<Entrypoint> entries = result.entryCatalog().entries();
        check(entries.stream().anyMatch(e ->
                        "HTTP".equals(e.protocol()) && "/run".equals(e.route())),
                "PreAnalysis EntryCatalog contains XXL /run");
        check(entries.stream().anyMatch(e ->
                        e.preconditions().stream().anyMatch(p -> p.contains("framework:xxl-job"))),
                "entries tagged framework:xxl-job");
        check(entries.stream().anyMatch(e -> e.id().startsWith("entry-exec-")),
                "executor entry ids use entry-exec- prefix");
        check(!entries.isEmpty(), "non-zero entries prevents empty-catalog dynamic skip");
    }

    private static void actuatorConfigSkeleton() {
        ExecutorEntryContext ctx = fixtureContext(
                List.of("com.demo.App"),
                List.of("management.endpoints.web.exposure.include=health,info,env"),
                List.of(),
                List.of("BOOT-INF/lib/spring-boot-actuator-3.2.0.jar"));
        List<RuntimeCallbackEntry> entries = new SpringActuatorEntryAdapter().discover(ctx);
        check(entries.stream().anyMatch(e -> "/actuator/health".equals(e.address())),
                "Actuator emits /actuator/health");
        check(entries.stream().allMatch(e -> "HTTP".equals(e.protocol())),
                "Actuator entries are HTTP");
        check(entries.stream().allMatch(e -> "INFERENCE".equals(e.provenanceKind())),
                "Actuator skeleton remains INFERENCE");
    }

    private static void elasticJobObservationalOnlyByDefault() {
        ExecutorEntryContext ctx = fixtureContext(
                List.of("com.demo.job.MyElasticJob"),
                List.of("elasticjob.reg-center.server-lists=127.0.0.1:2181"),
                List.of(),
                List.of("BOOT-INF/lib/elastic-job-lite-core-3.0.0.jar"));
        List<RuntimeCallbackEntry> entries = new ElasticJobHttpEntryAdapter().discover(ctx);
        check(entries.stream().anyMatch(e -> "JOB".equals(e.protocol())),
                "ElasticJob emits observational JOB entry");
        check(entries.stream().noneMatch(e -> "HTTP".equals(e.protocol())),
                "ElasticJob does not fabricate HTTP without http-trigger config");

        ExecutorEntryContext httpCtx = fixtureContext(
                List.of("com.demo.job.MyElasticJob"),
                List.of("elasticjob.http.trigger=true"),
                List.of(),
                List.of("BOOT-INF/lib/elastic-job-lite-core-3.0.0.jar"));
        List<RuntimeCallbackEntry> httpEntries = new ElasticJobHttpEntryAdapter().discover(httpCtx);
        check(httpEntries.stream().anyMatch(e ->
                        "HTTP".equals(e.protocol()) && "/job/trigger".equals(e.address())),
                "ElasticJob emits HTTP only with explicit http-trigger evidence");
    }

    private static void highValueSignalsReachProbeHelper() {
        check(FrameworkAdapterRegistry.containsHighValueSignal("POST /run"),
                "XXL /run is high-value via executor registry");
        check(FrameworkAdapterRegistry.containsHighValueSignal("/actuator/env"),
                "Actuator /actuator/env is high-value");
        check(ExecutorEntryAdapterRegistry.containsHighValueSignal("/idleBeat"),
                "idleBeat high-value on executor registry");
    }

    private static void customAdapterInjectable() {
        ExecutorEntryAdapter custom = new ExecutorEntryAdapter() {
            @Override public String id() { return "test-custom-callback"; }
            @Override public String frameworkId() { return "test-rpc"; }
            @Override public boolean matches(ExecutorEntryContext context) {
                return context != null && context.configContains("test.rpc.callback");
            }
            @Override public List<RuntimeCallbackEntry> discover(ExecutorEntryContext context) {
                return List.of(new RuntimeCallbackEntry(
                        id(), frameworkId(), "HTTP", "POST", "/rpc/callback",
                        "test.rpc.CallbackServer", List.of("body:payload"),
                        List.of("framework:test-rpc"), "test:custom",
                        "custom adapter fixture", "INFERENCE", 0.66));
            }
            @Override public Set<String> highValueRouteSignals() {
                return Set.of("/rpc/callback");
            }
        };
        ExecutorEntryAdapterRegistry.registerForTests(custom);
        try {
            ExecutorEntryContext ctx = fixtureContext(
                    List.of(), List.of("test.rpc.callback=enabled"), List.of(), List.of());
            check(ExecutorEntryAdapterRegistry.matching(ctx).stream()
                            .anyMatch(a -> "test-custom-callback".equals(a.id())),
                    "custom adapter matches via registry");
            check(ExecutorEntryAdapterRegistry.discoverAll(ctx).stream()
                            .anyMatch(e -> "/rpc/callback".equals(e.address())),
                    "custom adapter discoverable");
            check(ExecutorEntryAdapterRegistry.containsHighValueSignal("/rpc/callback"),
                    "custom high-value signal visible");
        } finally {
            ExecutorEntryAdapterRegistry.unregisterForTests(custom);
        }
    }

    private static void jobProtocolNotHttpProbeEligible() {
        var job = NonHttpEntryProtocol.classify("JOB");
        check(!job.httpProbeEligible(), "JOB not HTTP-probe eligible");
        check("UNREACHED".equals(job.coverageStatus()), "JOB coverage UNREACHED");
        var scheduled = NonHttpEntryProtocol.classify("SCHEDULED");
        check(!scheduled.httpProbeEligible(), "SCHEDULED not HTTP-probe eligible");
    }

    private static ExecutorEntryContext fixtureContext(
            List<String> classNames,
            List<String> config,
            List<ClassMetadata> metadata,
            List<String> archiveNames) {
        ArtifactDescriptor artifact = new ArtifactDescriptor(
                "artifact-exec-ctx",
                ArtifactType.CLASS,
                Path.of("E:/ai/Veyrion/target/executor-ctx.class").toAbsolutePath().normalize(),
                64,
                "b".repeat(64),
                true,
                Instant.parse("2026-07-30T00:00:00Z"),
                "executor-ctx.class");
        return new ExecutorEntryContext(artifact, classNames, config, metadata, archiveNames);
    }

    private static ClassMetadata xxlJobClassMetadata(String className, String jobHandler) {
        ClassMetadata.AnnotationMetadata xxl = new ClassMetadata.AnnotationMetadata(
                "com.xxl.job.core.handler.annotation.XxlJob",
                Map.of("value", List.of(jobHandler)));
        ClassMetadata.MethodMetadata method = new ClassMetadata.MethodMetadata(
                "execute", "()V", 1, List.of(xxl), List.of());
        BytecodeFactIndex.ClassFact classFact = new BytecodeFactIndex.ClassFact(
                className, "java/lang/Object", List.of(), 1, "fixture");
        return new ClassMetadata(
                className, true, List.of(), List.of(method), classFact,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
    }
}

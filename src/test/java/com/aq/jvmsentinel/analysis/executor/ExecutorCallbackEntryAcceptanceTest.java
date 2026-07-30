package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.ClassMetadata;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.analysis.entry.NonHttpEntryProtocol;
import com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.service.probe.ProbeWireHelpers;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.Entrypoint;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.probe.ProbePlanCodec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 通用 RuntimeCallback / Executor 入口探测验收：注册表、XXL EmbedServer 字节码、
 * Actuator exposure/port、ElasticJob 证据驱动 HTTP、Netty/gRPC、端口/context 合成。
 */
public final class ExecutorCallbackEntryAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        ASSERTIONS.set(0);
        registryInstallsGenericAdapters();
        xxlJobAnnotationFixtureProducesHttpCallbacks();
        xxlEmbedServerBytecodeConfirmation();
        preAnalysisWritesExecutorEntries();
        actuatorExposureAndManagementPort();
        elasticJobObservationalOnlyByDefault();
        nettyGrpcEvidenceDriven();
        portAndContextPathSynthesis();
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
        check(ids.contains(NettyGrpcExecutorEntryAdapter.ID), "netty-grpc adapter registered");
        check(ExecutorEntryAdapterRegistry.all().size() >= 4, "at least 4 adapters");
    }

    private static void xxlJobAnnotationFixtureProducesHttpCallbacks() {
        ExecutorEntryContext ctx = fixtureContext(
                List.of("com.demo.job.DemoJob"),
                List.of("xxl.job.executor.port=9999", "server.port=8080"),
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
        check(entries.stream().anyMatch(e ->
                        e.preconditions().contains("listenPort=9999")
                                && e.preconditions().contains("portRole=executor-distinct")),
                "XXL carries distinct executor listenPort");
    }

    private static void xxlEmbedServerBytecodeConfirmation() {
        BytecodeFactIndex.ClassFact embedFact = new BytecodeFactIndex.ClassFact(
                "com.xxl.job.core.server.EmbedServer", "java/lang/Object", List.of(), 1,
                "nested-lib");
        BytecodeFactIndex.MethodFact start = new BytecodeFactIndex.MethodFact(
                "com/xxl/job/core/server/EmbedServer", "start", "()V", 1, "nested-lib");
        ClassMetadata embedMeta = new ClassMetadata(
                "com.xxl.job.core.server.EmbedServer", true, List.of(), List.of(),
                embedFact, List.of(), List.of(start), List.of(), List.of(), List.of(), List.of());

        BytecodeFactIndex.CallEdge edge = new BytecodeFactIndex.CallEdge(
                "com/demo/Boot", "main", "([Ljava/lang/String;)V",
                "com/xxl/job/core/server/EmbedServer", "start", "()V",
                BytecodeFactIndex.EdgeKind.DIRECT, "none",
                new BytecodeFactIndex.InstructionEvidence(
                        "com.demo.Boot", "main", "([Ljava/lang/String;)V", 12, 0));
        ClassMetadata caller = new ClassMetadata(
                "com.demo.Boot", true, List.of(), List.of(),
                new BytecodeFactIndex.ClassFact("com.demo.Boot", "java/lang/Object", List.of(), 1, "app"),
                List.of(), List.of(), List.of(), List.of(edge), List.of(), List.of());

        // 仅 jar 名 → 弱匹配；有 EmbedServer classfile → bytecode confirmed
        ExecutorEntryContext jarOnly = fixtureContext(
                List.of("com.demo.App"),
                List.of("xxl.job.executor.port=9999"),
                List.of(),
                List.of("BOOT-INF/lib/xxl-job-core-2.4.0.jar"));
        List<RuntimeCallbackEntry> weak = new XxlJobExecutorEntryAdapter().discover(jarOnly);
        check(weak.stream().noneMatch(e ->
                        e.preconditions().contains("embedServer:bytecode-confirmed")),
                "jar-name alone does not claim EmbedServer bytecode confirmation");

        ExecutorEntryContext withEmbed = fixtureContext(
                List.of("com.xxl.job.core.server.EmbedServer", "com.demo.Boot"),
                List.of("xxl.job.executor.port=9999"),
                List.of(embedMeta, caller),
                List.of("BOOT-INF/lib/xxl-job-core-2.4.0.jar"));
        check(XxlJobExecutorEntryAdapter.detectEmbedServer(withEmbed).confirmed(),
                "EmbedServer detected from nested lib classfile");
        List<RuntimeCallbackEntry> strong = new XxlJobExecutorEntryAdapter().discover(withEmbed);
        check(strong.stream().anyMatch(e ->
                        e.preconditions().contains("embedServer:bytecode-confirmed")
                                && "FACT".equals(e.provenanceKind())),
                "EmbedServer bytecode confirmation upgrades surface to FACT");
        check(!new NettyGrpcExecutorEntryAdapter().matches(withEmbed),
                "XXL EmbedServer must not be misclassified as custom Netty adapter");
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
        check(entries.stream().anyMatch(e ->
                        e.preconditions().contains("listenPort=9999")),
                "EntryCatalog carries listenPort precondition");
        check(!entries.isEmpty(), "non-zero entries prevents empty-catalog dynamic skip");
    }

    private static void actuatorExposureAndManagementPort() {
        ExecutorEntryContext ctx = fixtureContext(
                List.of("com.demo.App"),
                List.of(
                        "server.port=8080",
                        "server.servlet.context-path=/app",
                        "management.server.port=9090",
                        "management.endpoints.web.base-path=/manage",
                        "management.endpoints.web.exposure.include=health,env,shutdown"),
                List.of(),
                List.of("BOOT-INF/lib/spring-boot-actuator-3.2.0.jar"));
        List<RuntimeCallbackEntry> entries = new SpringActuatorEntryAdapter().discover(ctx);
        check(entries.stream().anyMatch(e -> "/manage/health".equals(e.address())),
                "Actuator uses configured base-path /manage");
        check(entries.stream().anyMatch(e -> "/manage/env".equals(e.address())),
                "Actuator exposure includes env");
        check(entries.stream().noneMatch(e -> e.address().contains("/info")),
                "Actuator omits endpoints not in exposure.include");
        check(entries.stream().anyMatch(e ->
                        e.preconditions().contains("listenPort=9090")
                                && e.preconditions().contains("portRole=management-distinct")),
                "Actuator distinct management port metadata");
        check(entries.stream().noneMatch(e ->
                        e.preconditions().stream().anyMatch(p -> p.equals("contextPath=/app"))),
                "distinct management port does not attach servlet context-path");

        ExecutorEntryContext samePort = fixtureContext(
                List.of("com.demo.App"),
                List.of(
                        "server.port=8080",
                        "server.servlet.context-path=/app",
                        "management.endpoints.web.exposure.include=health"),
                List.of(),
                List.of("BOOT-INF/lib/spring-boot-actuator-3.2.0.jar"));
        List<RuntimeCallbackEntry> same = new SpringActuatorEntryAdapter().discover(samePort);
        check(same.stream().anyMatch(e ->
                        e.preconditions().contains("contextPath=/app")
                                && e.preconditions().contains("listenPort=8080")),
                "same-port Actuator keeps servlet context-path");
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
                "ElasticJob does not fabricate HTTP without http-trigger evidence");

        ExecutorEntryContext flagOnly = fixtureContext(
                List.of("com.demo.job.MyElasticJob"),
                List.of("elasticjob.http.trigger=true"),
                List.of(),
                List.of("BOOT-INF/lib/elastic-job-lite-core-3.0.0.jar"));
        List<RuntimeCallbackEntry> flagEntries = new ElasticJobHttpEntryAdapter().discover(flagOnly);
        check(flagEntries.stream().noneMatch(e -> "HTTP".equals(e.protocol())),
                "boolean http.trigger alone does not invent /job/trigger");

        ExecutorEntryContext httpCtx = fixtureContext(
                List.of("com.demo.job.MyElasticJob"),
                List.of("elasticjob.http.trigger.path=/api/job/trigger"),
                List.of(),
                List.of("BOOT-INF/lib/elastic-job-lite-core-3.0.0.jar"));
        List<RuntimeCallbackEntry> httpEntries = new ElasticJobHttpEntryAdapter().discover(httpCtx);
        check(httpEntries.stream().anyMatch(e ->
                        "HTTP".equals(e.protocol()) && "/api/job/trigger".equals(e.address())),
                "ElasticJob emits HTTP only with explicit path evidence");

        ClassMetadata.AnnotationMetadata post = new ClassMetadata.AnnotationMetadata(
                "org.springframework.web.bind.annotation.PostMapping",
                Map.of("value", List.of("/internal/elastic/run")));
        ClassMetadata.MethodMetadata method = new ClassMetadata.MethodMetadata(
                "trigger", "()V", 1, List.of(post), List.of());
        ClassMetadata.AnnotationMetadata jobAnn = new ClassMetadata.AnnotationMetadata(
                "org.apache.shardingsphere.elasticjob.annotation.ElasticJobConfiguration",
                Map.of());
        ClassMetadata jobClass = new ClassMetadata(
                "com.demo.job.HttpElasticJob", true, List.of(jobAnn), List.of(method),
                new BytecodeFactIndex.ClassFact(
                        "com.demo.job.HttpElasticJob", "java/lang/Object", List.of(), 1, "fixture"),
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        ExecutorEntryContext annCtx = fixtureContext(
                List.of("com.demo.job.HttpElasticJob"),
                List.of(),
                List.of(jobClass),
                List.of("BOOT-INF/lib/elastic-job-lite-core-3.0.0.jar"));
        List<RuntimeCallbackEntry> annEntries = new ElasticJobHttpEntryAdapter().discover(annCtx);
        check(annEntries.stream().anyMatch(e ->
                        "HTTP".equals(e.protocol())
                                && "/internal/elastic/run".equals(e.address())
                                && "FACT".equals(e.provenanceKind())),
                "ElasticJob HTTP from RequestMapping on job class is FACT");
    }

    private static void nettyGrpcEvidenceDriven() {
        check(!new NettyGrpcExecutorEntryAdapter().matches(fixtureContext(
                        List.of("com.demo.App"), List.of(), List.of(), List.of())),
                "Netty/gRPC adapter does not match empty evidence");

        BytecodeFactIndex.CallEdge bindEdge = new BytecodeFactIndex.CallEdge(
                "com/demo/NettyBoot", "start", "()V",
                "io/netty/bootstrap/ServerBootstrap", "bind", "(I)Lio/netty/channel/ChannelFuture;",
                BytecodeFactIndex.EdgeKind.DIRECT, "none",
                new BytecodeFactIndex.InstructionEvidence(
                        "com.demo.NettyBoot", "start", "()V", 4, 0));
        ClassMetadata nettyBoot = new ClassMetadata(
                "com.demo.NettyBoot", true, List.of(), List.of(),
                new BytecodeFactIndex.ClassFact("com.demo.NettyBoot", "java/lang/Object", List.of(), 1, "app"),
                List.of(), List.of(), List.of(), List.of(bindEdge), List.of(), List.of());
        ExecutorEntryContext nettyCtx = fixtureContext(
                List.of("com.demo.NettyBoot", "io.netty.bootstrap.ServerBootstrap"),
                List.of("netty.server.port=7777", "netty.http.path=/rpc/ingest"),
                List.of(nettyBoot),
                List.of("BOOT-INF/lib/netty-all-4.1.100.Final.jar"));
        List<RuntimeCallbackEntry> nettyEntries = new NettyGrpcExecutorEntryAdapter().discover(nettyCtx);
        check(nettyEntries.stream().anyMatch(e ->
                        "HTTP".equals(e.protocol()) && "/rpc/ingest".equals(e.address())
                                && e.preconditions().contains("listenPort=7777")),
                "Netty emits HTTP callback with config path and port");

        BytecodeFactIndex.ClassFact svcFact = new BytecodeFactIndex.ClassFact(
                "com.demo.GreeterService",
                "io/grpc/BindableService",
                List.of("io/grpc/BindableService"),
                1,
                "app");
        ClassMetadata grpcSvc = new ClassMetadata(
                "com.demo.GreeterService", true, List.of(), List.of(), svcFact,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        BytecodeFactIndex.CallEdge reflectionEdge = new BytecodeFactIndex.CallEdge(
                "com/demo/GrpcBoot", "start", "()V",
                "io/grpc/protobuf/services/ProtoReflectionService", "newInstance",
                "()Lio/grpc/BindableService;",
                BytecodeFactIndex.EdgeKind.DIRECT, "none",
                new BytecodeFactIndex.InstructionEvidence(
                        "com.demo.GrpcBoot", "start", "()V", 8, 0));
        ClassMetadata grpcBoot = new ClassMetadata(
                "com.demo.GrpcBoot", true, List.of(), List.of(),
                new BytecodeFactIndex.ClassFact("com.demo.GrpcBoot", "java/lang/Object", List.of(), 1, "app"),
                List.of(), List.of(), List.of(), List.of(reflectionEdge), List.of(), List.of());
        ExecutorEntryContext grpcCtx = fixtureContext(
                List.of("com.demo.GreeterService", "io.grpc.ServerBuilder",
                        "io.grpc.protobuf.services.ProtoReflectionService"),
                List.of("grpc.server.port=50051"),
                List.of(grpcSvc, grpcBoot),
                List.of("BOOT-INF/lib/grpc-netty-1.58.0.jar"));
        List<RuntimeCallbackEntry> grpcEntries = new NettyGrpcExecutorEntryAdapter().discover(grpcCtx);
        check(grpcEntries.stream().anyMatch(e ->
                        "RPC".equals(e.protocol()) && e.address().contains("GreeterService")),
                "gRPC emits RPC protocol service entry");
        check(grpcEntries.stream().anyMatch(e ->
                        "RPC".equals(e.protocol())
                                && e.address().contains("ServerReflection")
                                && "FACT".equals(e.provenanceKind())),
                "gRPC reflection entry is FACT RPC");
        check(grpcEntries.stream().noneMatch(e ->
                        "HTTP".equals(e.protocol()) && e.address().contains("ServerReflection")),
                "gRPC reflection is not mislabeled as HTTP");
    }

    private static void portAndContextPathSynthesis() {
        ExecutorSurfaceConfig.Surface surface = ExecutorSurfaceConfig.parse(List.of(
                "server.port=8080",
                "server.servlet.context-path=/xxl-job-admin",
                "xxl.job.executor.port=9999",
                "management.server.port=9090",
                "management.endpoints.web.base-path=/actuator"));
        check(surface.serverPort() == 8080, "parse server.port");
        check(surface.xxlExecutorPort() == 9999, "parse xxl.job.executor.port");
        check(surface.managementPort() == 9090, "parse management.server.port");
        check("/xxl-job-admin".equals(surface.servletContextPath()), "parse context-path");
        check(surface.managementPortDistinct(), "management port distinct from server");
        check(surface.actuatorContextPath().isEmpty(),
                "distinct management port drops servlet context-path");
        check("/app/api".equals(ExecutorSurfaceConfig.composeProbeRoute("/app", "/api")),
                "compose context + route");
        check("/app/api".equals(ExecutorSurfaceConfig.composeProbeRoute("/app", "/app/api")),
                "compose is idempotent");

        ApiDtos.EntryDto xxlEntry = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p1", "a".repeat(64), "scan-1",
                "entry-exec-xxl-1", "HTTP", "POST", "/run",
                "com.xxl.job.core.server.EmbedServer", "executor",
                List.of(),
                List.of("framework:xxl-job", "listenPort=9999", "portRole=executor-distinct"),
                "STATIC_INFERRED", 0.9, 0, List.of("ev-1"));
        ExternalArtifactTaskExecutor.ProbeTarget xxlProbe = ProbeWireHelpers.probeTargetFor(xxlEntry);
        check(xxlProbe.listenPort() == 9999, "probeTargetFor carries executor listenPort");
        check("/run".equals(xxlProbe.route()), "XXL probe route has no servlet context-path");

        ApiDtos.EntryDto actuatorSame = new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p1", "a".repeat(64), "scan-1",
                "entry-exec-act-1", "HTTP", "GET", "/actuator/health",
                "actuator", "management",
                List.of(),
                List.of("framework:spring-actuator", "listenPort=8080", "contextPath=/app"),
                "STATIC_INFERRED", 0.7, 0, List.of("ev-2"));
        ExternalArtifactTaskExecutor.ProbeTarget actProbe = ProbeWireHelpers.probeTargetFor(actuatorSame);
        check("/app/actuator/health".equals(actProbe.route()),
                "same-port Actuator probe joins context-path");
        check(actProbe.listenPort() == 8080, "Actuator probe listenPort from precondition");

        String plan = new String(ProbePlanCodec.encodeProbePlan(List.of(xxlProbe, actProbe)),
                StandardCharsets.UTF_8);
        check(plan.contains("\t9999"), "probe plan TSV encodes executor listenPort");
        check(plan.contains("/app/actuator/health"), "probe plan includes context-prefixed route");
    }

    private static void highValueSignalsReachProbeHelper() {
        check(FrameworkAdapterRegistry.containsHighValueSignal("POST /run"),
                "XXL /run is high-value via executor registry");
        check(FrameworkAdapterRegistry.containsHighValueSignal("/actuator/env"),
                "Actuator /actuator/env is high-value");
        check(ExecutorEntryAdapterRegistry.containsHighValueSignal("/idleBeat"),
                "idleBeat high-value on executor registry");
        check(ExecutorEntryAdapterRegistry.containsHighValueSignal("ServerBootstrap"),
                "Netty ServerBootstrap high-value class signal");
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
        var rpc = NonHttpEntryProtocol.classify("RPC");
        check(!rpc.httpProbeEligible(), "RPC not HTTP-probe eligible");
        var grpc = NonHttpEntryProtocol.classify("GRPC");
        check(!grpc.httpProbeEligible(), "GRPC not HTTP-probe eligible");
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

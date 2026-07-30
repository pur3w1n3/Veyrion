package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.ClassMetadata;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 自定义 Netty {@code ServerBootstrap}/bind 与 gRPC {@code ServerBuilder} /
 * service 注册 / reflection 的证据驱动适配器。
 *
 * <p>未命中字节码/配置证据时不产出假入口；命中时标注 protocol 为 HTTP 或 RPC。
 */
public final class NettyGrpcExecutorEntryAdapter implements ExecutorEntryAdapter {
    public static final String ID = "netty-grpc-callback";
    public static final String FRAMEWORK = "netty-grpc";

    private static final Pattern BIND_PORT = Pattern.compile(
            "(?i)(?:grpc|netty|rpc)\\.(?:server\\.)?port\\s*[=:]\\s*(\\d{2,5})");
    private static final Pattern HTTP_PATH = Pattern.compile(
            "(?i)(?:netty|rpc)\\.(?:http\\.)?(?:path|uri|endpoint)\\s*[=:]\\s*(/\\S{1,128})");

    private static final Set<String> NETTY_BOOTSTRAP = Set.of(
            "io.netty.bootstrap.ServerBootstrap",
            "io/netty/bootstrap/ServerBootstrap");
    private static final Set<String> GRPC_BUILDERS = Set.of(
            "io.grpc.ServerBuilder",
            "io/grpc/ServerBuilder",
            "io.grpc.netty.NettyServerBuilder",
            "io/grpc/netty/NettyServerBuilder",
            "io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder",
            "net.devh.boot.grpc.server.serverfactory.GrpcServerFactory");
    private static final Set<String> GRPC_REFLECTION = Set.of(
            "io.grpc.protobuf.services.ProtoReflectionService",
            "io/grpc/protobuf/services/ProtoReflectionService",
            "grpc.reflection.v1alpha.ServerReflection");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String frameworkId() {
        return FRAMEWORK;
    }

    @Override
    public boolean matches(ExecutorEntryContext context) {
        if (context == null) {
            return false;
        }
        EvidenceBundle evidence = collect(context);
        return evidence.hasNettyBind() || evidence.hasGrpcServer() || evidence.hasGrpcReflection();
    }

    @Override
    public List<RuntimeCallbackEntry> discover(ExecutorEntryContext context) {
        if (!matches(context)) {
            return List.of();
        }
        EvidenceBundle evidence = collect(context);
        ExecutorSurfaceConfig.Surface surface = ExecutorSurfaceConfig.parse(context.configurationLines());
        int listenPort = evidence.bindPort() > 0 ? evidence.bindPort() : surface.serverPort();

        List<RuntimeCallbackEntry> out = new ArrayList<>();
        if (evidence.hasNettyBind()) {
            List<String> pre = basePreconditions("http-callback", listenPort, surface);
            pre.add("netty:ServerBootstrap");
            for (String signal : evidence.nettySignals()) {
                pre.add("evidence:" + signal);
            }
            String address = evidence.httpPath().isEmpty() ? "/netty-callback" : evidence.httpPath();
            double confidence = evidence.httpPath().isEmpty() ? 0.62 : 0.74;
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    "POST",
                    address,
                    evidence.nettyDeclaringSymbol(),
                    List.of("body:payload"),
                    List.copyOf(pre),
                    "executor-adapter:" + ID + ":netty",
                    "Netty ServerBootstrap/bind evidence=" + evidence.nettySignals()
                            + (listenPort > 0 ? "; listenPort=" + listenPort : "")
                            + (evidence.httpPath().isEmpty()
                            ? "; route is observational placeholder (no config path)"
                            : "; route from config")
                            + "; custom channel handlers not fully resolved",
                    "INFERENCE",
                    confidence));
        }

        if (evidence.hasGrpcServer()) {
            List<String> pre = basePreconditions("rpc-callback", listenPort, surface);
            pre.add("grpc:ServerBuilder");
            for (String signal : evidence.grpcSignals()) {
                pre.add("evidence:" + signal);
            }
            for (String service : evidence.grpcServices()) {
                List<String> servicePre = new ArrayList<>(pre);
                servicePre.add("grpcService:" + service);
                out.add(new RuntimeCallbackEntry(
                        ID,
                        FRAMEWORK,
                        "RPC",
                        "INVOKE",
                        "/grpc/" + sanitizeService(service),
                        service,
                        List.of("rpc:service"),
                        List.copyOf(servicePre),
                        "executor-adapter:" + ID + ":grpc:" + sanitizeService(service),
                        "gRPC service registration evidence; protocol=RPC; "
                                + "method descriptors not fully enumerated; not HTTP-probe eligible",
                        "FACT",
                        0.88));
            }
            if (evidence.grpcServices().isEmpty()) {
                out.add(new RuntimeCallbackEntry(
                        ID,
                        FRAMEWORK,
                        "RPC",
                        "INVOKE",
                        "/grpc/*",
                        evidence.grpcDeclaringSymbol(),
                        List.of("rpc:server"),
                        List.copyOf(pre),
                        "executor-adapter:" + ID + ":grpc-server",
                        "gRPC ServerBuilder/bind evidence=" + evidence.grpcSignals()
                                + "; services not enumerated from bytecode",
                        "INFERENCE",
                        0.74));
            }
        }

        if (evidence.hasGrpcReflection()) {
            List<String> pre = basePreconditions("rpc-reflection", listenPort, surface);
            pre.add("grpc:reflection");
            for (String signal : evidence.reflectionSignals()) {
                pre.add("evidence:" + signal);
            }
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "RPC",
                    "INVOKE",
                    "/grpc.reflection.v1alpha.ServerReflection",
                    "io.grpc.protobuf.services.ProtoReflectionService",
                    List.of("rpc:reflection"),
                    List.copyOf(pre),
                    "executor-adapter:" + ID + ":grpc-reflection",
                    "gRPC reflection service registered; protocol=RPC; "
                            + "enables service discovery over RPC — not HTTP-probe eligible",
                    "FACT",
                    0.91));
        }

        return List.copyOf(out);
    }

    @Override
    public Set<String> highValueRouteSignals() {
        return Set.of("/netty-callback", "/grpc", "serverreflection");
    }

    @Override
    public Set<String> highValueClassSignals() {
        return Set.of("serverbootstrap", "serverbuilder", "protoreflectionservice", "netty.bootstrap");
    }

    private static List<String> basePreconditions(
            String kind, int listenPort, ExecutorSurfaceConfig.Surface surface) {
        List<String> pre = new ArrayList<>();
        pre.add("framework:" + FRAMEWORK);
        pre.add("callbackKind:" + kind);
        if (listenPort > 0) {
            pre = new ArrayList<>(ExecutorSurfaceConfig.withListenPort(pre, listenPort));
        }
        if (surface.serverPort() > 0 && listenPort > 0 && surface.serverPort() != listenPort) {
            pre.add("portRole=rpc-distinct");
            pre.add("serverPort=" + surface.serverPort());
        }
        return pre;
    }

    private static EvidenceBundle collect(ExecutorEntryContext context) {
        LinkedHashSet<String> nettySignals = new LinkedHashSet<>();
        LinkedHashSet<String> grpcSignals = new LinkedHashSet<>();
        LinkedHashSet<String> reflectionSignals = new LinkedHashSet<>();
        LinkedHashSet<String> grpcServices = new LinkedHashSet<>();
        String nettySymbol = "io.netty.bootstrap.ServerBootstrap";
        String grpcSymbol = "io.grpc.ServerBuilder";
        int bindPort = 0;
        String httpPath = "";
        boolean explicitNettyServerClass = false;

        for (String line : context.configurationLines()) {
            if (line == null) {
                continue;
            }
            Matcher portMatcher = BIND_PORT.matcher(line);
            if (portMatcher.find()) {
                try {
                    int port = Integer.parseInt(portMatcher.group(1));
                    if (port >= 1 && port <= 65_535) {
                        bindPort = port;
                        grpcSignals.add("config:port=" + port);
                        nettySignals.add("config:port=" + port);
                    }
                } catch (NumberFormatException ignored) {
                    // skip
                }
            }
            Matcher pathMatcher = HTTP_PATH.matcher(line);
            if (pathMatcher.find()) {
                httpPath = ExecutorSurfaceConfig.normalizePath(pathMatcher.group(1));
                if (!httpPath.isEmpty()) {
                    nettySignals.add("config:path=" + httpPath);
                }
            }
        }

        if (context.archiveEntryContains("netty-all")
                || context.archiveEntryContains("netty-transport")
                || context.archiveEntryContains("/netty-")) {
            // archive alone is weak — only boost when paired with bytecode below
            nettySignals.add("archive:netty");
        }
        if (context.archiveEntryContains("grpc-netty")
                || context.archiveEntryContains("grpc-services")
                || context.archiveEntryContains("grpc-core")) {
            grpcSignals.add("archive:grpc");
        }

        // 类路径上存在 ServerBootstrap/ServerBuilder（嵌套 lib）本身不够——
        // 必须有应用侧调用边 / BindableService 实现 / 显式配置 path|port。
        for (ClassMetadata metadata : context.classMetadata()) {
            if (metadata == null) {
                continue;
            }
            String className = metadata.className() == null ? "" : metadata.className().replace('/', '.');
            if (isFrameworkInternal(className)) {
                continue;
            }
            if (metadata.classFact() != null) {
                String superName = metadata.classFact().superClassName();
                if (superName != null) {
                    String superDotted = superName.replace('/', '.');
                    if (superDotted.endsWith("BindableService")
                            || superDotted.endsWith("ServerServiceDefinition")) {
                        grpcServices.add(className);
                        grpcSignals.add("extends:" + superDotted);
                    }
                }
                for (String iface : metadata.classFact().interfaces()) {
                    if (iface == null) {
                        continue;
                    }
                    String i = iface.replace('/', '.');
                    if (i.endsWith("BindableService") || i.contains("BindableService")) {
                        grpcServices.add(className);
                        grpcSignals.add("implements:BindableService");
                    }
                }
            }
            scanCallEdges(metadata, nettySignals, grpcSignals, reflectionSignals, grpcServices);
        }

        // 应用侧强证据：call-edge / implements / config path；禁止仅靠 lib 类名命中
        boolean nettyBind = nettySignals.stream().anyMatch(s ->
                s.startsWith("call-edge:") || s.startsWith("member-access:")
                        || s.startsWith("config:path"));
        boolean grpcServer = grpcSignals.stream().anyMatch(s ->
                s.startsWith("call-edge:") || s.startsWith("implements")
                        || s.startsWith("extends") || s.startsWith("config:port"));
        boolean reflection = reflectionSignals.stream().anyMatch(s ->
                s.startsWith("call-edge:") || s.startsWith("classfile:"));
        // gRPC port 配置 + BindableService 实现即可；仅 archive+port 不够
        if (!grpcServer && bindPort > 0 && !grpcServices.isEmpty()) {
            grpcServer = true;
            grpcSignals.add("config:port=" + bindPort);
        }
        if (nettyBind) {
            explicitNettyServerClass = true;
            nettySymbol = nettySignals.stream()
                    .filter(s -> s.startsWith("call-edge:"))
                    .findFirst()
                    .map(s -> s.substring("call-edge:".length()))
                    .orElse(nettySymbol);
        }
        if (grpcServer && !grpcServices.isEmpty()) {
            grpcSymbol = grpcServices.iterator().next();
        }

        return new EvidenceBundle(
                nettyBind, grpcServer, reflection,
                List.copyOf(nettySignals), List.copyOf(grpcSignals), List.copyOf(reflectionSignals),
                List.copyOf(grpcServices), nettySymbol, grpcSymbol, bindPort, httpPath,
                explicitNettyServerClass);
    }

    private static void scanCallEdges(
            ClassMetadata metadata,
            Set<String> nettySignals,
            Set<String> grpcSignals,
            Set<String> reflectionSignals,
            Set<String> grpcServices) {
        if (metadata.callEdges() == null) {
            return;
        }
        String caller = metadata.className() == null ? "" : metadata.className().replace('/', '.');
        if (isFrameworkInternal(caller)) {
            return;
        }
        for (BytecodeFactIndex.CallEdge edge : metadata.callEdges()) {
            if (edge == null || edge.targetOwner() == null) {
                continue;
            }
            String owner = edge.targetOwner().replace('/', '.');
            String name = edge.targetName() == null ? "" : edge.targetName();
            if (containsToken(owner, NETTY_BOOTSTRAP) || owner.endsWith("ServerBootstrap")) {
                nettySignals.add("call-edge:" + owner + "#" + name);
            }
            if (containsToken(owner, GRPC_BUILDERS) || owner.contains("ServerBuilder")) {
                grpcSignals.add("call-edge:" + owner + "#" + name);
                if ("addService".equals(name)) {
                    grpcServices.add(caller);
                }
            }
            if (containsToken(owner, GRPC_REFLECTION)
                    || owner.contains("ProtoReflectionService")
                    || "newServerReflectionInstance".equals(name)
                    || ("newInstance".equals(name) && owner.contains("ProtoReflectionService"))) {
                reflectionSignals.add("call-edge:" + owner + "#" + name);
            }
            if (("bind".equals(name) || "start".equals(name))
                    && (owner.contains("ServerBootstrap") || owner.contains("ServerBuilder"))) {
                if (owner.contains("Bootstrap") || owner.contains("netty")) {
                    nettySignals.add("call-edge:" + owner + "#" + name);
                }
                if (owner.contains("grpc") || owner.contains("ServerBuilder")) {
                    grpcSignals.add("call-edge:" + owner + "#" + name);
                }
            }
        }
        if (metadata.memberAccessFacts() != null) {
            for (BytecodeFactIndex.MemberAccessFact access : metadata.memberAccessFacts()) {
                if (access == null || access.targetOwner() == null) {
                    continue;
                }
                String owner = access.targetOwner().replace('/', '.');
                if (containsToken(owner, NETTY_BOOTSTRAP)) {
                    nettySignals.add("member-access:" + owner + "#" + access.targetName());
                }
                if (containsToken(owner, GRPC_BUILDERS) || containsToken(owner, GRPC_REFLECTION)) {
                    grpcSignals.add("member-access:" + owner + "#" + access.targetName());
                }
            }
        }
    }

    /** XXL EmbedServer / 框架内部 Netty 使用不计入自定义适配器。 */
    private static boolean isFrameworkInternal(String className) {
        if (className == null || className.isBlank()) {
            return true;
        }
        String lower = className.replace('/', '.').toLowerCase(Locale.ROOT);
        return lower.startsWith("com.xxl.job.")
                || lower.startsWith("io.netty.")
                || lower.startsWith("io.grpc.")
                || lower.startsWith("org.apache.shardingsphere.elasticjob.")
                || lower.startsWith("com.dangdang.ddframe.job.")
                || lower.startsWith("org.springframework.")
                || lower.startsWith("java.")
                || lower.startsWith("javax.")
                || lower.startsWith("jakarta.");
    }

    private static boolean containsToken(String value, Set<String> tokens) {
        if (value == null) {
            return false;
        }
        for (String token : tokens) {
            if (value.equals(token) || value.replace('/', '.').equals(token.replace('/', '.'))) {
                return true;
            }
        }
        return false;
    }

    private static String sanitizeService(String service) {
        if (service == null || service.isBlank()) {
            return "service";
        }
        String value = service.replace('/', '.').replaceAll("[^A-Za-z0-9_.-]", "_");
        return value.length() <= 96 ? value : value.substring(value.length() - 96);
    }

    private record EvidenceBundle(
            boolean hasNettyBind,
            boolean hasGrpcServer,
            boolean hasGrpcReflection,
            List<String> nettySignals,
            List<String> grpcSignals,
            List<String> reflectionSignals,
            List<String> grpcServices,
            String nettyDeclaringSymbol,
            String grpcDeclaringSymbol,
            int bindPort,
            String httpPath,
            boolean hasExplicitNettyServerClass
    ) {
    }
}

package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.ClassMetadata;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * XXL-JOB Executor 回调入口适配器（通用 RuntimeCallback 面的第一个实现）。
 *
 * <p>证据：
 * <ul>
 *   <li>方法注解 {@code @XxlJob} / JobHandler 接口实现 → FACT handler + 框架回调口</li>
 *   <li>嵌套 lib 内 {@code EmbedServer} 类/方法/调用边字节码确认 → 强化 matches/discover</li>
 *   <li>配置 {@code xxl.job.*}、类名/嵌套 jar {@code xxl-job-core} → 框架回调口</li>
 * </ul>
 *
 * <p>已知 HTTP 回调（xxl-job-core EmbedServer）：{@code /run} {@code /kill}
 * {@code /log} {@code /beat} {@code /idleBeat}。探针走 HTTP，不假设 MVC
 * {@code @RequestMapping}。独立 {@code xxl.job.executor.port} 写入 listenPort 元数据。
 */
public final class XxlJobExecutorEntryAdapter implements ExecutorEntryAdapter {
    public static final String ID = "xxl-job-executor";
    public static final String FRAMEWORK = "xxl-job";

    private static final String XXL_JOB_ANN = "com.xxl.job.core.handler.annotation.XxlJob";
    private static final String JOB_HANDLER = "com.xxl.job.core.handler.IJobHandler";
    private static final String JOB_HANDLER_SLASH = "com/xxl/job/core/handler/IJobHandler";
    private static final String EMBED_SERVER = "com.xxl.job.core.server.EmbedServer";
    private static final String EMBED_SERVER_SLASH = "com/xxl/job/core/server/EmbedServer";

    private static final List<CallbackSurface> SURFACES = List.of(
            new CallbackSurface("POST", "/run", List.of("body:jobHandler", "body:executorParams"),
                    "XXL-JOB executor run callback"),
            new CallbackSurface("POST", "/kill", List.of("body:jobId"),
                    "XXL-JOB executor kill callback"),
            new CallbackSurface("POST", "/log", List.of("body:logId", "body:fromLineNum"),
                    "XXL-JOB executor log callback"),
            new CallbackSurface("GET", "/beat", List.of(),
                    "XXL-JOB executor beat callback"),
            new CallbackSurface("POST", "/idleBeat", List.of("body:jobId"),
                    "XXL-JOB executor idleBeat callback")
    );

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
        if (context.configContains("xxl.job") || context.configContains("xxl-job")) {
            return true;
        }
        if (context.archiveEntryContains("xxl-job-core")
                || context.archiveEntryContains("/xxl-job/")
                || context.archiveEntryContains("xxl.job")) {
            return true;
        }
        if (context.classNameContains("com.xxl.job")
                || context.classNameContains("XxlJob")
                || context.classNameContains("EmbedServer")) {
            return true;
        }
        EmbedServerEvidence embed = detectEmbedServer(context);
        if (embed.confirmed()) {
            return true;
        }
        return !annotatedHandlers(context).isEmpty() || !jobHandlerImpls(context).isEmpty();
    }

    @Override
    public List<RuntimeCallbackEntry> discover(ExecutorEntryContext context) {
        if (!matches(context)) {
            return List.of();
        }
        List<RuntimeCallbackEntry> out = new ArrayList<>();
        ExecutorSurfaceConfig.Surface surface = ExecutorSurfaceConfig.parse(context.configurationLines());
        EmbedServerEvidence embed = detectEmbedServer(context);
        Presence presence = detectPresence(context, embed);

        List<String> frameworkPre = new ArrayList<>();
        frameworkPre.add("framework:" + FRAMEWORK);
        frameworkPre.add("callbackKind:executor-http");
        if (embed.confirmed()) {
            frameworkPre.add("embedServer:bytecode-confirmed");
            frameworkPre.add("embedServerSignal:" + embed.signal());
        }
        int listenPort = surface.xxlExecutorPort();
        if (listenPort > 0) {
            frameworkPre = new ArrayList<>(ExecutorSurfaceConfig.withListenPort(frameworkPre, listenPort));
            frameworkPre.add("executorPort=" + listenPort);
            if (surface.serverPort() > 0 && surface.serverPort() != listenPort) {
                frameworkPre.add("portRole=executor-distinct");
                frameworkPre.add("serverPort=" + surface.serverPort());
            }
        }
        // EmbedServer 为独立 Netty HTTP，不挂 servlet context-path（故意不写 contextPath）

        String surfaceProvenance = presence.annotationOrImpl || embed.confirmed() ? "FACT" : "INFERENCE";
        double surfaceConfidence = presence.annotationOrImpl ? 0.92
                : embed.confirmed() ? 0.90 : 0.78;
        String surfaceSummary = "XXL-JOB executor HTTP callback surface; presence="
                + presence.signal
                + (embed.confirmed()
                ? "; EmbedServer bytecode-confirmed (" + embed.signal() + ")"
                : "; EmbedServer routes are adapter-known")
                + (listenPort > 0 ? "; listenPort=" + listenPort : "")
                + "; runtime reachability not proven";

        for (CallbackSurface callback : SURFACES) {
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    callback.method(),
                    callback.route(),
                    EMBED_SERVER,
                    callback.inputs(),
                    List.copyOf(frameworkPre),
                    "executor-adapter:" + ID + ":surface:" + callback.route(),
                    callback.summary() + "; " + surfaceSummary,
                    surfaceProvenance,
                    surfaceConfidence));
        }

        for (HandlerHit hit : annotatedHandlers(context)) {
            List<String> inputs = new ArrayList<>();
            inputs.add("body:jobHandler=" + hit.jobHandler());
            inputs.add("annotation:@XxlJob");
            List<String> pre = new ArrayList<>(frameworkPre);
            pre.add("callbackKind:job-handler");
            pre.add("jobHandler:" + hit.jobHandler());
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    "POST",
                    "/run",
                    hit.symbol(),
                    inputs,
                    List.copyOf(pre),
                    "classfile-annotation:" + hit.symbol(),
                    "@XxlJob handler bound to executor /run callback; jobHandler="
                            + hit.jobHandler()
                            + "; static annotation FACT; dynamic dispatch not proven",
                    "FACT",
                    0.95));
        }

        for (String symbol : jobHandlerImpls(context)) {
            List<String> pre = new ArrayList<>(frameworkPre);
            pre.add("callbackKind:job-handler");
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    "POST",
                    "/run",
                    symbol,
                    List.of("body:jobHandler", "implements:IJobHandler"),
                    List.copyOf(pre),
                    "classfile-type:" + symbol,
                    "IJobHandler implementation present; executor /run may dispatch; "
                            + "handler name registration not fully resolved",
                    "INFERENCE",
                    0.82));
        }

        return dedupe(out);
    }

    @Override
    public Set<String> highValueRouteSignals() {
        return Set.of("/run", "/kill", "/idlebeat", "/beat", "/log");
    }

    @Override
    public Set<String> highValueClassSignals() {
        return Set.of("xxl.job", "xxljob", "ijobhandler", "embedserver");
    }

    /**
     * 在已扫到的（含 BOOT-INF/lib 一层展开）类上确认 EmbedServer / 回调服务器实现。
     */
    static EmbedServerEvidence detectEmbedServer(ExecutorEntryContext context) {
        if (context == null) {
            return EmbedServerEvidence.none();
        }
        for (String name : context.classNames()) {
            if (name == null) {
                continue;
            }
            String dotted = name.replace('/', '.');
            if (EMBED_SERVER.equals(dotted)
                    || dotted.endsWith(".EmbedServer")
                    || name.equals(EMBED_SERVER_SLASH)) {
                return new EmbedServerEvidence(true, "class-name:" + dotted);
            }
        }
        for (ClassMetadata metadata : context.classMetadata()) {
            if (metadata == null) {
                continue;
            }
            String className = metadata.className() == null ? "" : metadata.className().replace('/', '.');
            if (EMBED_SERVER.equals(className) || className.endsWith(".EmbedServer")) {
                boolean hasStart = false;
                if (metadata.methodFacts() != null) {
                    for (BytecodeFactIndex.MethodFact method : metadata.methodFacts()) {
                        if (method != null && method.name() != null) {
                            String n = method.name().toLowerCase(Locale.ROOT);
                            if (n.equals("start") || n.equals("bind") || n.contains("start")) {
                                hasStart = true;
                                break;
                            }
                        }
                    }
                }
                if (!hasStart && metadata.methods() != null) {
                    for (ClassMetadata.MethodMetadata method : metadata.methods()) {
                        if (method != null && method.name() != null) {
                            String n = method.name().toLowerCase(Locale.ROOT);
                            if (n.equals("start") || n.equals("bind") || n.contains("start")) {
                                hasStart = true;
                                break;
                            }
                        }
                    }
                }
                return new EmbedServerEvidence(true,
                        hasStart ? "classfile:EmbedServer+start" : "classfile:EmbedServer");
            }
            // 调用边指向 EmbedServer
            if (metadata.callEdges() != null) {
                for (BytecodeFactIndex.CallEdge edge : metadata.callEdges()) {
                    if (edge == null || edge.targetOwner() == null) {
                        continue;
                    }
                    String owner = edge.targetOwner().replace('/', '.');
                    if (EMBED_SERVER.equals(owner) || owner.endsWith(".EmbedServer")) {
                        return new EmbedServerEvidence(true,
                                "call-edge:" + owner + "#" + edge.targetName());
                    }
                }
            }
            if (metadata.memberAccessFacts() != null) {
                for (BytecodeFactIndex.MemberAccessFact access : metadata.memberAccessFacts()) {
                    if (access == null || access.targetOwner() == null) {
                        continue;
                    }
                    String owner = access.targetOwner().replace('/', '.');
                    if (EMBED_SERVER.equals(owner) || owner.endsWith(".EmbedServer")) {
                        return new EmbedServerEvidence(true,
                                "member-access:" + owner + "#" + access.targetName());
                    }
                }
            }
        }
        return EmbedServerEvidence.none();
    }

    private static Presence detectPresence(ExecutorEntryContext context, EmbedServerEvidence embed) {
        if (!annotatedHandlers(context).isEmpty()) {
            return new Presence(true, "annotation:@XxlJob");
        }
        if (!jobHandlerImpls(context).isEmpty()) {
            return new Presence(true, "implements:IJobHandler");
        }
        if (embed.confirmed()) {
            return new Presence(false, "bytecode:" + embed.signal());
        }
        if (context.configContains("xxl.job") || context.configContains("xxl-job")) {
            return new Presence(false, "config:xxl.job");
        }
        if (context.archiveEntryContains("xxl-job-core")) {
            return new Presence(false, "archive:xxl-job-core");
        }
        if (context.classNameContains("com.xxl.job") || context.classNameContains("XxlJob")) {
            return new Presence(false, "class-name:xxl.job");
        }
        return new Presence(false, "unknown");
    }

    private static List<HandlerHit> annotatedHandlers(ExecutorEntryContext context) {
        List<HandlerHit> hits = new ArrayList<>();
        if (context == null) {
            return hits;
        }
        for (ClassMetadata metadata : context.classMetadata()) {
            if (metadata == null || !metadata.annotationMetadataValid()) {
                continue;
            }
            for (ClassMetadata.MethodMetadata method : metadata.methods()) {
                ClassMetadata.AnnotationMetadata ann = findXxlJob(method.annotations());
                if (ann == null) {
                    continue;
                }
                String handler = firstNonBlank(ann.values("value"));
                if (handler.isBlank()) {
                    handler = firstNonBlank(ann.values("jobHandler"));
                }
                if (handler.isBlank()) {
                    handler = method.name();
                }
                String symbol = metadata.className() + "#" + method.name();
                hits.add(new HandlerHit(symbol, handler));
            }
        }
        return hits;
    }

    private static List<String> jobHandlerImpls(ExecutorEntryContext context) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (context == null) {
            return List.of();
        }
        for (ClassMetadata metadata : context.classMetadata()) {
            if (metadata == null || metadata.classFact() == null) {
                continue;
            }
            var fact = metadata.classFact();
            String superName = normalizeBinary(fact.superClassName());
            if (JOB_HANDLER.equals(superName.replace('/', '.'))
                    || JOB_HANDLER_SLASH.equals(superName)) {
                out.add(metadata.className());
                continue;
            }
            for (String iface : fact.interfaces()) {
                String n = normalizeBinary(iface);
                if (JOB_HANDLER.equals(n.replace('/', '.')) || JOB_HANDLER_SLASH.equals(n)) {
                    out.add(metadata.className());
                    break;
                }
            }
        }
        return List.copyOf(out);
    }

    private static ClassMetadata.AnnotationMetadata findXxlJob(
            List<ClassMetadata.AnnotationMetadata> annotations) {
        if (annotations == null) {
            return null;
        }
        for (ClassMetadata.AnnotationMetadata annotation : annotations) {
            if (annotation == null || annotation.typeName() == null) {
                continue;
            }
            String type = annotation.typeName();
            if (XXL_JOB_ANN.equals(type)
                    || type.endsWith(".XxlJob")
                    || "XxlJob".equals(simpleName(type))) {
                return annotation;
            }
        }
        return null;
    }

    private static List<RuntimeCallbackEntry> dedupe(List<RuntimeCallbackEntry> entries) {
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<RuntimeCallbackEntry> out = new ArrayList<>();
        for (RuntimeCallbackEntry entry : entries) {
            String key = entry.operation() + " " + entry.address() + " " + entry.declaringSymbol()
                    + " " + entry.preconditions();
            if (seen.add(key)) {
                out.add(entry);
            }
        }
        return List.copyOf(out);
    }

    private static String firstNonBlank(List<String> values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private static String simpleName(String type) {
        if (type == null) {
            return "";
        }
        int slash = Math.max(type.lastIndexOf('.'), type.lastIndexOf('/'));
        return slash < 0 ? type : type.substring(slash + 1);
    }

    private static String normalizeBinary(String binary) {
        return binary == null ? "" : binary.replace('.', '/').trim();
    }

    private record CallbackSurface(String method, String route, List<String> inputs, String summary) {
        private CallbackSurface {
            inputs = List.copyOf(inputs == null ? List.of() : inputs);
        }
    }

    private record HandlerHit(String symbol, String jobHandler) {
    }

    private record Presence(boolean annotationOrImpl, String signal) {
    }

    record EmbedServerEvidence(boolean confirmed, String signal) {
        static EmbedServerEvidence none() {
            return new EmbedServerEvidence(false, "");
        }
    }
}

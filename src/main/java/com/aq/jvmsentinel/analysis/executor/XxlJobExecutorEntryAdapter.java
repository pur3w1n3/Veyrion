package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.ClassMetadata;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * XXL-JOB Executor 回调入口适配器（通用 RuntimeCallback 面的第一个实现）。
 *
 * <p>证据：
 * <ul>
 *   <li>方法注解 {@code @XxlJob} / JobHandler 接口实现 → FACT handler + 框架回调口</li>
 *   <li>配置 {@code xxl.job.*}、类名/嵌套 jar {@code xxl-job-core} → 框架 EmbedServer 回调口</li>
 * </ul>
 *
 * <p>已知 HTTP 回调（xxl-job-core EmbedServer）：{@code /run} {@code /kill}
 * {@code /log} {@code /beat} {@code /idleBeat}。探针走 HTTP，不假设 MVC
 * {@code @RequestMapping}。
 */
public final class XxlJobExecutorEntryAdapter implements ExecutorEntryAdapter {
    public static final String ID = "xxl-job-executor";
    public static final String FRAMEWORK = "xxl-job";

    private static final String XXL_JOB_ANN = "com.xxl.job.core.handler.annotation.XxlJob";
    private static final String JOB_HANDLER = "com.xxl.job.core.handler.IJobHandler";
    private static final String JOB_HANDLER_SLASH = "com/xxl/job/core/handler/IJobHandler";

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
                || context.classNameContains("XxlJob")) {
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
        List<String> frameworkPre = List.of("framework:" + FRAMEWORK, "callbackKind:executor-http");

        Presence presence = detectPresence(context);
        String surfaceProvenance = presence.annotationOrImpl ? "FACT" : "INFERENCE";
        double surfaceConfidence = presence.annotationOrImpl ? 0.92 : 0.78;
        String surfaceSummary = "XXL-JOB executor HTTP callback surface; presence="
                + presence.signal
                + "; EmbedServer routes are adapter-known; runtime reachability not proven";

        for (CallbackSurface surface : SURFACES) {
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    surface.method(),
                    surface.route(),
                    "com.xxl.job.core.server.EmbedServer",
                    surface.inputs(),
                    frameworkPre,
                    "executor-adapter:" + ID + ":surface:" + surface.route(),
                    surface.summary() + "; " + surfaceSummary,
                    surfaceProvenance,
                    surfaceConfidence));
        }

        for (HandlerHit hit : annotatedHandlers(context)) {
            List<String> inputs = new ArrayList<>();
            inputs.add("body:jobHandler=" + hit.jobHandler());
            inputs.add("annotation:@XxlJob");
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    "POST",
                    "/run",
                    hit.symbol(),
                    inputs,
                    List.of("framework:" + FRAMEWORK, "callbackKind:job-handler",
                            "jobHandler:" + hit.jobHandler()),
                    "classfile-annotation:" + hit.symbol(),
                    "@XxlJob handler bound to executor /run callback; jobHandler="
                            + hit.jobHandler()
                            + "; static annotation FACT; dynamic dispatch not proven",
                    "FACT",
                    0.95));
        }

        for (String symbol : jobHandlerImpls(context)) {
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    "POST",
                    "/run",
                    symbol,
                    List.of("body:jobHandler", "implements:IJobHandler"),
                    List.of("framework:" + FRAMEWORK, "callbackKind:job-handler"),
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
        return Set.of("xxl.job", "xxljob", "ijobhandler");
    }

    private static Presence detectPresence(ExecutorEntryContext context) {
        if (!annotatedHandlers(context).isEmpty()) {
            return new Presence(true, "annotation:@XxlJob");
        }
        if (!jobHandlerImpls(context).isEmpty()) {
            return new Presence(true, "implements:IJobHandler");
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
}
